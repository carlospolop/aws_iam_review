#!/usr/bin/env python3

import argparse
import json
import os
import shlex
import subprocess
import sys
import threading
import time
from typing import Optional
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
import concurrent.futures


DEFAULT_LOCATION = "global"
MAX_PERMS_TO_PRINT = 15

try:
    from termcolor import colored  # type: ignore
except Exception as exc:
    raise SystemExit(
        "Missing dependency `termcolor`. Install with `pip3 install -r requirements.txt`."
    ) from exc

try:
    from tqdm import tqdm  # type: ignore
except Exception:
    tqdm = None

try:
    import google.auth  # type: ignore
    import google.oauth2.service_account  # type: ignore
    import google.auth.transport.requests  # type: ignore
except Exception as exc:
    raise SystemExit(
        "Missing dependency `google-auth`. Install with `pip3 install -r requirements.txt`."
    ) from exc

from scripts.permission_risk_classifier import classify_permission
from bluepeass.report import Target, atomic_write_json, build_report
from bluepeass.progress import StageProgress
from bluepeass.normalize import normalize_gcp_scope
from bluepeass.progress_pool import SlotStageProgress


class ApiError(RuntimeError):
    pass


def _iter_with_progress(items: list, *, desc: str, unit: str):
    if tqdm is None:
        return items
    return tqdm(items, desc=desc, unit=unit)


def _new_progress(*, total: int, desc: str, unit: str, leave: bool = False):
    if tqdm is None:
        return None
    return tqdm(total=total, desc=desc, unit=unit, leave=leave)


def _ok(msg: str) -> str:
    return f"{colored('[+] ', 'green')}{msg}"


def _info(msg: str) -> str:
    return f"{colored('[*] ', 'yellow')}{msg}"


def _err(msg: str) -> str:
    return f"{colored('[-] ', 'red')}{msg}"


def run_json(cmd: list[str]) -> object:
    try:
        out = subprocess.check_output(cmd, text=True)
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"Command failed: {shlex.join(cmd)}\n{exc.output}") from exc
    out = out.strip()
    if not out:
        return None
    return json.loads(out)


def run_text(cmd: list[str]) -> str:
    try:
        out = subprocess.check_output(cmd, text=True)
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"Command failed: {shlex.join(cmd)}\n{exc.output}") from exc
    return out.strip()


def _get_access_token_from_gcloud() -> Optional[str]:
    for cmd in (["gcloud", "auth", "print-access-token"],):
        try:
            token = run_text(cmd)
        except Exception:
            continue
        if token:
            return token
    return None


def _get_access_token_from_google_auth_default() -> Optional[str]:
    try:
        creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        req = google.auth.transport.requests.Request()
        creds.refresh(req)
        return getattr(creds, "token", None)
    except Exception:
        return None


def _get_access_token_from_service_account_json(sa_json: str) -> str:
    try:
        if os.path.exists(sa_json):
            info = json.loads(open(sa_json, "r", encoding="utf-8").read())
        else:
            info = json.loads(sa_json)
    except Exception as exc:
        raise RuntimeError("Invalid --sa-json (must be a path to a JSON key file or a raw JSON string).") from exc

    creds = google.oauth2.service_account.Credentials.from_service_account_info(
        info, scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    req = google.auth.transport.requests.Request()
    creds.refresh(req)
    token = getattr(creds, "token", None)
    if not token:
        raise RuntimeError("Unable to obtain access token from service account credentials.")
    return token


def get_access_token_auto(*, sa_json: Optional[str]) -> str:
    if sa_json:
        return _get_access_token_from_service_account_json(sa_json)

    token = _get_access_token_from_gcloud()
    if token:
        return token

    token = _get_access_token_from_google_auth_default()
    if token:
        return token

    raise RuntimeError(
        "Unable to obtain credentials. Provide `--sa-json` (service account key), or login with `gcloud auth login`, "
        "or run in an environment with metadata/ADC available."
    )


def http_json(
    url: str,
    *,
    token: str,
    quota_project: Optional[str] = None,
    method: str = "GET",
    body: Optional[dict] = None,
    timeout: int = 60,
    retries: int = 4,
) -> dict:
    headers = {"Authorization": f"Bearer {token}"}
    if quota_project:
        headers["X-Goog-User-Project"] = quota_project

    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    for attempt in range(retries + 1):
        req = urllib.request.Request(url, headers=headers, method=method, data=data)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
            if not raw:
                return {}
            return json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            try:
                err_json = json.loads(raw) if raw else {}
            except Exception:
                err_json = {"raw": raw}

            status = err_json.get("error", {}).get("status")
            message = err_json.get("error", {}).get("message") or raw or str(exc)
            reason = None
            for detail in err_json.get("error", {}).get("details", []) or []:
                if isinstance(detail, dict) and detail.get("@type", "").endswith("ErrorInfo"):
                    reason = detail.get("reason")
                    break

            # Backoff on transient errors.
            if exc.code in (429, 500, 502, 503, 504) and attempt < retries:
                time.sleep(min(8, 0.5 * (2**attempt)))
                continue

            raise ApiError(f"{exc.code} {status or ''} {reason or ''}: {message}".strip()) from exc
        except (urllib.error.URLError, ConnectionResetError, TimeoutError) as exc:
            if attempt < retries:
                time.sleep(min(8, 0.5 * (2**attempt)))
                continue
            raise ApiError(f"Network error: {exc}") from exc


def rfc3339(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def list_projects_in_organization(*, organization_id: str, token: str, quota_project: str) -> list[str]:
    project_ids: list[str] = []
    page_token: Optional[str] = None
    while True:
        params = {"pageSize": "500", "parent": f"organizations/{organization_id}"}
        if page_token:
            params["pageToken"] = page_token
        url = f"https://cloudresourcemanager.googleapis.com/v3/projects?{urllib.parse.urlencode(params)}"
        data = http_json(url, token=token, quota_project=quota_project)
        for proj in data.get("projects", []) or []:
            if not isinstance(proj, dict):
                continue
            state = proj.get("state")
            pid = proj.get("projectId")
            if state == "ACTIVE" and isinstance(pid, str) and pid:
                project_ids.append(pid)
        page_token = data.get("nextPageToken")
        if not page_token:
            break
    return sorted(set(project_ids))


def list_all_accessible_projects(*, token: str, quota_project: str) -> list[str]:
    """
    List all ACTIVE projects the current identity can see.

    Uses Cloud Resource Manager v1 `projects.list`.
    """
    project_ids: list[str] = []
    page_token: Optional[str] = None
    while True:
        params = {"pageSize": "500", "filter": "lifecycleState:ACTIVE"}
        if page_token:
            params["pageToken"] = page_token
        url = f"https://cloudresourcemanager.googleapis.com/v1/projects?{urllib.parse.urlencode(params)}"
        data = http_json(url, token=token, quota_project=quota_project)
        for proj in data.get("projects", []) or []:
            if not isinstance(proj, dict):
                continue
            state = proj.get("lifecycleState")
            pid = proj.get("projectId")
            if state == "ACTIVE" and isinstance(pid, str) and pid:
                project_ids.append(pid)
        page_token = data.get("nextPageToken")
        if not page_token:
            break
    return sorted(set(project_ids))


def get_organization_display_name(*, organization_id: str, token: str, quota_project: str) -> Optional[str]:
    org_id = organization_id.strip()
    if not org_id:
        return None
    url = f"https://cloudresourcemanager.googleapis.com/v1/organizations/{org_id}"
    data = http_json(url, token=token, quota_project=quota_project)
    name = data.get("displayName")
    return name.strip() if isinstance(name, str) and name.strip() else None


def org_display_name_to_domain_hint(display_name: Optional[str]) -> Optional[str]:
    if not display_name:
        return None
    cand = display_name.strip().lower()
    # Heuristic: domain-like strings contain dots and no spaces.
    if "." in cand and " " not in cand and "/" not in cand:
        return cand
    return None


def get_project_iam_policy(*, project_id: str, token: str, quota_project: str) -> dict:
    url = f"https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}:getIamPolicy"
    return http_json(url, token=token, quota_project=quota_project, method="POST", body={})


def get_organization_iam_policy(*, organization_id: str, token: str, quota_project: str) -> dict:
    url = f"https://cloudresourcemanager.googleapis.com/v1/organizations/{organization_id}:getIamPolicy"
    return http_json(url, token=token, quota_project=quota_project, method="POST", body={})


def get_folder_iam_policy(*, folder_id: str, token: str, quota_project: str) -> dict:
    # v2 supports folders:getIamPolicy (POST).
    url = f"https://cloudresourcemanager.googleapis.com/v2/folders/{folder_id}:getIamPolicy"
    return http_json(url, token=token, quota_project=quota_project, method="POST", body={})


def list_folder_ids_for_project(*, project_id: str, token: str, quota_project: str) -> list[str]:
    """Return folder IDs in the project's ancestry (closest-first)."""
    url = f"https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}:getAncestry"
    data = http_json(url, token=token, quota_project=quota_project, method="POST", body={})
    folder_ids: list[str] = []
    for e in data.get("ancestor", []) or []:
        rid = e.get("resourceId", {}) or {}
        if rid.get("type") == "folder":
            fid = rid.get("id")
            if isinstance(fid, str) and fid:
                folder_ids.append(fid)
    return folder_ids


def print_permissions(flagged_perms: dict) -> None:
    if not flagged_perms:
        return
    risk_colors = {
        "critical": "red",
        "high": "yellow",
        "medium": "blue",
        "low": "cyan",
    }
    for risk_level in ["critical", "high", "medium", "low"]:
        perms = flagged_perms.get(risk_level) or []
        if not perms:
            continue
        more_than_str = " and more..." if len(perms) > MAX_PERMS_TO_PRINT else ""
        color = risk_colors.get(risk_level, "white")
        shown = ", ".join(f"`{p}`" for p in perms[:MAX_PERMS_TO_PRINT])
        print(f"    - {colored(risk_level.upper(), color)}: {shown}{more_than_str}")


def iam_bindings_to_principal_roles(policy: dict) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for b in policy.get("bindings", []) or []:
        if not isinstance(b, dict):
            continue
        role = b.get("role")
        if not isinstance(role, str) or not role:
            continue
        for m in b.get("members", []) or []:
            if not isinstance(m, str) or not m:
                continue
            out.setdefault(m, set()).add(role)
    return out


def merge_principal_roles(*maps: dict[str, set[str]]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for m in maps:
        for principal, roles in m.items():
            out.setdefault(principal, set()).update(roles)
    return out


def principal_roles_from_search_results(results: list[dict]) -> dict[str, set[str]]:
    """Build principal->roles from CAI searchAllIamPolicies results (resource-level IAM)."""
    out: dict[str, set[str]] = {}
    for item in results or []:
        policy = item.get("policy", {}) or {}
        for b in policy.get("bindings", []) or []:
            if not isinstance(b, dict):
                continue
            role = b.get("role")
            if not isinstance(role, str) or not role:
                continue
            for m in b.get("members", []) or []:
                if not isinstance(m, str) or not m or m.startswith("deleted:"):
                    continue
                out.setdefault(m, set()).add(role)
    return out


def get_last_audit_activity(
    *,
    project_id: str,
    principal_email: str,
    token: str,
    quota_project: str,
    since: datetime,
) -> Optional[str]:
    filter_expr = (
        f'logName:"cloudaudit.googleapis.com" '
        f'AND protoPayload.authenticationInfo.principalEmail="{principal_email}" '
        f'AND timestamp>="{rfc3339(since)}"'
    )
    body = {
        "resourceNames": [f"projects/{project_id}"],
        "filter": filter_expr,
        "orderBy": "timestamp desc",
        "pageSize": 1,
    }
    data = http_json(
        "https://logging.googleapis.com/v2/entries:list",
        token=token,
        quota_project=quota_project,
        method="POST",
        body=body,
        timeout=90,
        retries=5,
    )
    entries = data.get("entries", []) or []
    if not entries:
        return None
    first = entries[0]
    if isinstance(first, dict):
        ts = first.get("timestamp")
        return ts if isinstance(ts, str) else None
    return None


def get_last_key_activity(
    *,
    project_id: str,
    service_account_key_name: str,
    token: str,
    quota_project: str,
    since: datetime,
) -> Optional[str]:
    # Best-effort: not all audit log entries include this field for all auth flows.
    filter_expr = (
        f'logName:"cloudaudit.googleapis.com" '
        f'AND protoPayload.authenticationInfo.serviceAccountKeyName="{service_account_key_name}" '
        f'AND timestamp>="{rfc3339(since)}"'
    )
    body = {
        "resourceNames": [f"projects/{project_id}"],
        "filter": filter_expr,
        "orderBy": "timestamp desc",
        "pageSize": 1,
    }
    data = http_json(
        "https://logging.googleapis.com/v2/entries:list",
        token=token,
        quota_project=quota_project,
        method="POST",
        body=body,
        timeout=90,
        retries=5,
    )
    entries = data.get("entries", []) or []
    if not entries:
        return None
    first = entries[0]
    if isinstance(first, dict):
        ts = first.get("timestamp")
        return ts if isinstance(ts, str) else None
    return None


def get_default_project_from_gcloud() -> Optional[str]:
    try:
        value = run_text(["gcloud", "config", "get-value", "project"])
    except Exception:
        return None
    return value if value and value.lower() != "(unset)" else None


def enable_apis(project_id: str, apis: list[str]) -> None:
    subprocess.run(
        ["gcloud", "services", "enable", *apis, "--project", project_id, "-q"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )


def list_enabled_apis(project_id: str) -> set[str]:
    # Note: using gcloud here keeps the dependencies minimal and avoids implementing OAuth for Service Usage.
    # Output is one API name per line.
    try:
        out = subprocess.check_output(
            ["gcloud", "services", "list", "--enabled", "--project", project_id, "--format=value(config.name)"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return set()
    return {line.strip() for line in out.splitlines() if line.strip()}


def ensure_apis_enabled(project_id: str, apis: list[str]) -> list[str]:
    enabled = list_enabled_apis(project_id)
    missing = [a for a in apis if a not in enabled]
    if not missing:
        return []
    enable_apis(project_id, missing)
    return missing


_ROLE_PERMISSIONS_CACHE: dict[str, list[str]] = {}
_ROLE_PERMISSIONS_LOCK = threading.Lock()


def get_role_permissions(*, role: str, token: str, quota_project: Optional[str]) -> list[str]:
    if not role:
        return []
    with _ROLE_PERMISSIONS_LOCK:
        cached = _ROLE_PERMISSIONS_CACHE.get(role)
    if cached is not None:
        return cached

    # Supported formats:
    # - roles/viewer
    # - projects/<project>/roles/<customRole>
    # - organizations/<org>/roles/<customRole>
    if role.startswith("roles/") or role.startswith("projects/") or role.startswith("organizations/"):
        url = f"https://iam.googleapis.com/v1/{role}"
    else:
        # Thread-safe cache write for unsupported format
        with _ROLE_PERMISSIONS_LOCK:
            _ROLE_PERMISSIONS_CACHE[role] = []
        return []

    try:
        data = http_json(url, token=token, quota_project=quota_project)
    except Exception:
        with _ROLE_PERMISSIONS_LOCK:
            _ROLE_PERMISSIONS_CACHE[role] = []
        return []

    perms = data.get("includedPermissions", []) or []
    perms = [p for p in perms if isinstance(p, str)]
    with _ROLE_PERMISSIONS_LOCK:
        _ROLE_PERMISSIONS_CACHE[role] = perms
    return perms


def list_project_custom_roles(*, project_id: str, token: str, quota_project: str) -> list[dict]:
    roles: list[dict] = []
    page_token: Optional[str] = None
    while True:
        params = {"pageSize": "300"}
        if page_token:
            params["pageToken"] = page_token
        url = f"https://iam.googleapis.com/v1/projects/{project_id}/roles?{urllib.parse.urlencode(params)}"
        data = http_json(url, token=token, quota_project=quota_project)
        for r in data.get("roles", []) or []:
            if isinstance(r, dict):
                roles.append(r)
        page_token = data.get("nextPageToken")
        if not page_token:
            break
    return roles


def iter_recommendations(
    *,
    parent: str,
    recommender_id: str,
    token: str,
    quota_project: Optional[str],
    location: str,
    page_size: int,
) -> list[dict]:
    recs: list[dict] = []
    page_token: Optional[str] = None
    while True:
        params = {"pageSize": str(page_size)}
        if page_token:
            params["pageToken"] = page_token

        base = (
            f"https://recommender.googleapis.com/v1/{parent}"
            f"/locations/{location}/recommenders/{recommender_id}/recommendations"
        )
        url = f"{base}?{urllib.parse.urlencode(params)}"

        try:
            data = http_json(url, token=token, quota_project=quota_project)
        except ApiError as exc:
            message = str(exc).lower()
            if quota_project is None and "requires a quota project" in message:
                quota_guess = parent.split("/", 1)[1] if parent.startswith("projects/") else None
                data = http_json(url, token=token, quota_project=quota_guess)
            else:
                raise

        recs.extend(data.get("recommendations", []) or [])
        page_token = data.get("nextPageToken")
        if not page_token:
            break
    return recs


def list_recommender_locations(*, parent: str, token: str, quota_project: Optional[str]) -> list[str]:
    url = f"https://recommender.googleapis.com/v1/{parent}/locations?pageSize=200"
    try:
        data = http_json(url, token=token, quota_project=quota_project)
    except ApiError:
        return [DEFAULT_LOCATION]
    locs = []
    for loc in data.get("locations", []) or []:
        name = loc.get("name") if isinstance(loc, dict) else None
        if isinstance(name, str) and "/locations/" in name:
            locs.append(name.rsplit("/", 1)[-1])
    return sorted(set(locs)) or [DEFAULT_LOCATION]


def iter_search_all_iam_policies(
    *,
    scope: str,
    query: str,
    token: str,
    quota_project: Optional[str],
    page_size: int,
) -> list[dict]:
    results: list[dict] = []
    page_token: Optional[str] = None
    while True:
        params = {"query": query, "pageSize": str(page_size)}
        if page_token:
            params["pageToken"] = page_token
        base = f"https://cloudasset.googleapis.com/v1/{scope}:searchAllIamPolicies"
        url = f"{base}?{urllib.parse.urlencode(params)}"
        try:
            data = http_json(url, token=token, quota_project=quota_project)
        except ApiError as exc:
            message = str(exc).lower()
            # When a quota project is explicitly set, always honor it (X-Goog-User-Project),
            # and fail with a clear error if the service isn't enabled there.
            if quota_project is not None and "service_disabled" in message:
                raise ApiError(
                    f"Cloud Asset API appears disabled for quota project `{quota_project}`. "
                    f"Enable `cloudasset.googleapis.com` in that quota project (or change --quota-project)."
                ) from exc
            # If the API does require a quota project (common with user creds), retry using
            # the analyzed project as the quota project.
            elif quota_project is None and "requires a quota project" in message:
                # Use the scope's project as quota project if possible, otherwise omit.
                quota_guess = scope.split("/", 1)[1] if scope.startswith("projects/") else None
                data = http_json(url, token=token, quota_project=quota_guess)
            else:
                raise
        results.extend(data.get("results", []) or [])
        page_token = data.get("nextPageToken")
        if not page_token:
            break
    return results


def parse_public_iam(results: list[dict]) -> list[dict]:
    findings: list[dict] = []
    for item in results:
        resource = item.get("resource")
        policy = item.get("policy", {})
        bindings = policy.get("bindings", []) or []
        for b in bindings:
            role = b.get("role")
            members = b.get("members", []) or []
            public_members = [m for m in members if m in ("allUsers", "allAuthenticatedUsers")]
            if public_members:
                findings.append(
                    {"resource": resource, "role": role, "members": public_members}
                )
    return findings


def parse_workload_identity_trusts(results: list[dict]) -> list[dict]:
    findings: list[dict] = []
    for item in results:
        resource = item.get("resource")
        policy = item.get("policy", {})
        for b in policy.get("bindings", []) or []:
            role = b.get("role")
            members = b.get("members", []) or []
            external = [m for m in members if "principalSet://iam.googleapis.com/" in m or "principal://iam.googleapis.com/" in m]
            if external:
                findings.append({"resource": resource, "role": role, "members": external})
    return findings


def parse_external_domains(results: list[dict], allowed_domains: set[str]) -> list[dict]:
    findings: list[dict] = []
    for item in results:
        resource = item.get("resource")
        policy = item.get("policy", {})
        for b in policy.get("bindings", []) or []:
            role = b.get("role")
            members = b.get("members", []) or []
            domains = []
            for m in members:
                if not isinstance(m, str) or not m.startswith("domain:"):
                    continue
                domain = m.split(":", 1)[1].strip().lower()
                if domain and domain not in allowed_domains:
                    domains.append(m)
            if domains:
                findings.append({"resource": resource, "role": role, "members": domains})
    return findings


def classify_permissions_yaml(perms: list[str], risk_levels: list[str] = None) -> dict:
    """Classify permissions by risk level using `risk_rules/gcp.yaml`.
    
    Args:
        perms: List of permission strings to classify
        risk_levels: List of risk levels to check (low, medium, high, critical). 
                    Default: ['high', 'critical']
    
    Returns:
        dict with:
            - flagged_perms: dict mapping risk_level -> list of matched permissions
            - is_admin: bool, True if administrator (* permission)
    """
    perms = [p for p in perms if isinstance(p, str) and p.strip()]
    if not perms:
        return {
            "flagged_perms": {},
            "is_admin": False,
        }
    
    # Default to high and critical if not specified
    if risk_levels is None:
        risk_levels = ['high', 'critical']
    
    # Check for administrator access
    if "*" in perms:
        return {
            "flagged_perms": {"critical": ["*"]},
            "is_admin": True,
        }
    
    flagged_perms: dict[str, list[str]] = {}
    for perm in perms:
        lvl = classify_permission("gcp", perm, unknown_default="high")
        if lvl not in risk_levels:
            continue
        flagged_perms.setdefault(lvl, []).append(perm)
    
    # Deduplicate permissions within each risk level
    for risk_level in flagged_perms:
        flagged_perms[risk_level] = sorted(set(flagged_perms[risk_level]))
    
    return {
        "flagged_perms": flagged_perms,
        "is_admin": False,
    }


def subset_permissions_matching_yaml(perms: list[str], risk_levels: list[str] = None) -> dict:
    """Return flagged permissions matching YAML patterns."""
    return classify_permissions_yaml(perms, risk_levels)


def parse_member(member: str) -> dict:
    member = member.strip()
    kind = member.split(":", 1)[0] if ":" in member else "unknown"
    payload = member.split(":", 1)[1] if ":" in member else member
    email_domain = None
    if kind in ("user", "group", "serviceAccount") and "@" in payload:
        email_domain = payload.split("@", 1)[1].lower()
    return {"member": member, "kind": kind, "payload": payload, "email_domain": email_domain}


def extract_sa_project_from_email(payload: str) -> Optional[str]:
    # Common patterns:
    # - name@PROJECT_ID.iam.gserviceaccount.com
    # - PROJECT_NUMBER-compute@developer.gserviceaccount.com
    # - service-PROJECT_NUMBER@gcp-sa-<service>.iam.gserviceaccount.com
    if "@" not in payload:
        return None
    local, domain = payload.split("@", 1)
    domain = domain.lower()
    if domain.endswith(".iam.gserviceaccount.com"):
        parts = domain.split(".")
        if len(parts) >= 4:
            return parts[0]  # PROJECT_ID or PROJECT_NUMBER
    if domain == "developer.gserviceaccount.com":
        if "-" in local:
            maybe_number = local.split("-", 1)[0]
            if maybe_number.isdigit():
                return maybe_number
    return None


def binding_condition(binding: dict) -> Optional[dict]:
    cond = binding.get("condition")
    if not isinstance(cond, dict):
        return None
    out = {
        "title": cond.get("title"),
        "description": cond.get("description"),
        "expression": cond.get("expression"),
    }
    if not any(out.values()):
        return None
    return out


def parse_external_trusts(
    *,
    results: list[dict],
    project_id: Optional[str],
    allowed_domains: set[str],
    allowed_projects: set[str],
    include_cross_project_same_org: bool,
    project_org_id: Optional[str],
    resolve_org_for_project,
    source_scope: str,
) -> list[dict]:
    trusts: list[dict] = []
    for item in results:
        resource = item.get("resource")
        policy = item.get("policy", {})
        for b in policy.get("bindings", []) or []:
            role = b.get("role")
            cond = binding_condition(b)
            for m in b.get("members", []) or []:
                if not isinstance(m, str):
                    continue
                if m.startswith("deleted:"):
                    continue

                parsed = parse_member(m)
                kind = parsed["kind"]
                payload = parsed["payload"]
                email_domain = parsed["email_domain"]

                reasons: list[str] = []
                cross_project = False
                cross_org = False
                other_project = None
                other_org_id = None

                if m in ("allUsers", "allAuthenticatedUsers"):
                    reasons.append("public")

                if "principalSet://iam.googleapis.com/" in m or "principal://iam.googleapis.com/" in m:
                    reasons.append("workload_identity_federation")

                if kind in ("user", "group") and email_domain in ("gmail.com", "googlemail.com"):
                    reasons.append("gmail_identity")

                if kind in ("user", "group") and email_domain and allowed_domains:
                    if email_domain not in allowed_domains:
                        reasons.append("external_email_domain")

                if kind == "domain":
                    dom = payload.strip().lower()
                    if dom and allowed_domains and dom not in allowed_domains:
                        reasons.append("external_domain_principal")

                if kind == "serviceAccount":
                    other_project = extract_sa_project_from_email(payload)
                    if other_project and project_id and other_project != project_id and other_project not in allowed_projects:
                        cross_project = True
                        reasons.append("cross_project_service_account")
                        if project_org_id and resolve_org_for_project:
                            other_org_id = resolve_org_for_project(other_project)
                            if other_org_id and other_org_id != project_org_id:
                                cross_org = True
                                reasons.append("cross_org_service_account")
                    elif other_project and (not project_id) and other_project not in allowed_projects:
                        cross_project = True
                        reasons.append("cross_project_service_account")

                if reasons:
                    if (
                        cross_project
                        and (not include_cross_project_same_org)
                        and (project_org_id is not None)
                        and (other_org_id is not None)
                        and (other_org_id == project_org_id)
                    ):
                        continue
                    trusts.append(
                        {
                            "resource": resource,
                            "role": role,
                            "member": m,
                            "memberKind": kind,
                            "reasons": sorted(set(reasons)),
                            "condition": cond,
                            "crossProject": cross_project,
                            "crossOrg": cross_org,
                            "otherProject": other_project,
                            "otherOrgId": other_org_id,
                            "sourceScope": source_scope,
                        }
                    )
    return trusts


def list_service_account_user_managed_keys(
    *, service_account_email: str, token: str, quota_project: str
) -> list[dict]:
    sa = urllib.parse.quote(service_account_email, safe="@")
    url = f"https://iam.googleapis.com/v1/projects/-/serviceAccounts/{sa}/keys?keyTypes=USER_MANAGED"
    data = http_json(url, token=token, quota_project=quota_project)
    keys = data.get("keys", []) or []
    out = []
    for k in keys:
        if not isinstance(k, dict):
            continue
        out.append(
            {
                "name": k.get("name"),
                "keyType": k.get("keyType"),
                "validAfterTime": k.get("validAfterTime"),
                "validBeforeTime": k.get("validBeforeTime"),
            }
        )
    return out


def role_has_flagged_permissions(role: Optional[str], *, token: str, quota_project: Optional[str], risk_levels: list[str] = None) -> bool:
    """Check if a role has flagged permissions at specified risk levels."""
    if not role:
        return False
    perms = get_role_permissions(role=role, token=token, quota_project=quota_project)
    known = classify_permissions_yaml(perms, risk_levels)
    return bool(known["flagged_perms"])


def summarize_iam_policy_recommendation(rec: dict) -> dict:
    content = rec.get("content", {}) or {}
    overview = content.get("overview", {}) or {}

    operations: list[dict] = []
    for group in content.get("operationGroups", []) or []:
        for op in group.get("operations", []) or []:
            operations.append(
                {
                    "action": op.get("action"),
                    "path": op.get("path"),
                    "value": op.get("value"),
                    "valueMatcher": op.get("valueMatcher"),
                }
            )

    role = (
        overview.get("bindingRole")
        or overview.get("role")
        or overview.get("removedRole")
        or overview.get("targetRole")
    )
    principal = (
        overview.get("principalEmail")
        or overview.get("member")
        or overview.get("principal")
        or overview.get("removedMember")
    )
    resource = overview.get("resource") or rec.get("primaryResourceId") or rec.get("primaryResource")

    # If overview is missing key fields, infer from operations (common in IAM policy recommender).
    if (not principal or not role or not resource) and operations:
        for op in operations:
            if not isinstance(op, dict):
                continue
            op_value = op.get("value")
            op_path = op.get("path") or ""
            op_resource = op.get("resource") or op.get("resourceName") or op.get("resource_id")
            path_filters = op.get("pathFilters") or {}
            op_role = None
            if isinstance(path_filters, dict):
                op_role = path_filters.get("/iamPolicy/bindings/*/role") or path_filters.get("role")
            if not role and isinstance(op_role, str) and op_role:
                role = op_role
            if not principal and isinstance(op_value, str) and "members" in op_path:
                principal = op_value
            if not resource and isinstance(op_resource, str) and op_resource:
                resource = op_resource

    return {
        "name": rec.get("name"),
        "description": rec.get("description"),
        "priority": rec.get("priority"),
        "state": rec.get("stateInfo", {}).get("state"),
        "etag": rec.get("etag"),
        "lastRefreshTime": rec.get("lastRefreshTime"),
        "overview": overview,
        "principal": principal,
        "role": role,
        "resource": resource,
        "privilegedRole": False,
        "operations": operations,
    }


def print_human(results: list[dict], *, max_items: int) -> None:
    for proj in results:
        scope_type = proj.get("scope_type")
        scope = proj.get("scope")
        label = scope if scope_type != "project" else scope.split("/", 1)[1] if isinstance(scope, str) else scope
        print(f"\nInteresting permissions in {colored(str(label), 'yellow')}:")
        allowed = proj.get("allowed_domains") or []
        if allowed:
            print(f"{colored('Allowed domains', 'cyan')}: {', '.join(allowed)}")

        errors = proj.get("errors", []) or []
        if errors:
            print(f"{colored('Errors', 'red', attrs=['bold'])}: {len(errors)} (use --out-json for details)")

        recs = proj.get("recommendations", [])
        public = proj.get("public_iam", [])
        wit = proj.get("workload_identity_trusts", [])
        external_domains = proj.get("external_domains", [])
        external_trusts_raw = proj.get("external_trusts", [])
        external_trusts = external_trusts_raw
        if external_trusts_raw:
            seen = set()
            deduped: list[dict] = []
            for item in external_trusts_raw:
                if not isinstance(item, dict):
                    continue
                reasons = tuple(item.get("reasons") or [])
                cond = item.get("condition", {}) or {}
                cond_expr = cond.get("expression")
                key = (
                    item.get("member"),
                    item.get("role"),
                    reasons,
                    cond_expr,
                )
                if key in seen:
                    continue
                seen.add(key)
                deduped.append(item)
            external_trusts = deduped
        principal_risks = proj.get("principal_risks", [])
        inactive_principals = proj.get("inactive_principals", []) or []
        inactive_keys = proj.get("inactive_service_account_keys", []) or []

        has_findings = bool(
            errors
            or recs
            or public
            or wit
            or (external_domains is not None and external_domains)
            or (external_trusts is not None and external_trusts)
            or principal_risks
            or inactive_principals
            or inactive_keys
        )
        if not has_findings:
            print("  (No findings)")
            continue

        if recs:
            print(f"{colored('IAM recommendations', 'yellow', attrs=['bold'])}: {len(recs)}")
            shown = 0
            for r in recs:
                if shown >= max_items:
                    break
                shown += 1
                priv = " (PRIVILEGED ROLE)" if r.get("privilegedRole") else ""
                principal = r.get("principal") or "<unknown principal>"
                role = r.get("role") or "<unknown role>"
                resource = r.get("resource") or "<unknown resource>"
                desc = r.get("description") or ""
                print(f"  - `{principal}` -> `{role}`{priv}")
                print(f"    resource: `{resource}`")
                if desc:
                    print(f"    {desc}")

        if external_domains is not None:
            if external_domains:
                print(f"{colored('External domain principals', 'yellow', attrs=['bold'])}: {len(external_domains)}")
                for item in external_domains[:max_items]:
                    members = ", ".join(item.get("members") or [])
                    print(f"  - `{item.get('resource')}` : `{item.get('role')}` -> {members}")

        if public:
            print(f"{colored('Public IAM bindings', 'yellow', attrs=['bold'])}: {len(public)}")
            for item in public[:max_items]:
                members = ", ".join(item.get("members") or [])
                print(f"  - `{item.get('resource')}` : `{item.get('role')}` -> {members}")

        if wit:
            print(f"{colored('Workload Identity trusts', 'yellow', attrs=['bold'])}: {len(wit)}")
            for item in wit[:max_items]:
                print(f"  - `{item.get('resource')}` : `{item.get('role')}`")

        if external_trusts is not None:
            if external_trusts:
                grouped: dict[str, dict] = {}
                for item in external_trusts:
                    if not isinstance(item, dict):
                        continue
                    role = item.get("role") or "<unknown role>"
                    member = item.get("member") or "<unknown member>"
                    resource = item.get("resource")
                    reasons = item.get("reasons") or []
                    cond = item.get("condition", {}) or {}
                    cond_expr = cond.get("expression")

                    role_entry = grouped.setdefault(role, {"resources": set(), "members": {}})
                    if isinstance(resource, str) and resource:
                        role_entry["resources"].add(resource)
                    m_entry = role_entry["members"].setdefault(
                        member, {"resources": set(), "reasons": set(), "conditions": set()}
                    )
                    if isinstance(resource, str) and resource:
                        m_entry["resources"].add(resource)
                    for r in reasons:
                        if isinstance(r, str) and r:
                            m_entry["reasons"].add(r)
                    if isinstance(cond_expr, str) and cond_expr:
                        m_entry["conditions"].add(cond_expr)

                print(f"{colored('External trusts', 'yellow', attrs=['bold'])}: {len(external_trusts)}")
                shown_roles = 0
                for role in sorted(grouped.keys()):
                    if shown_roles >= max_items:
                        break
                    shown_roles += 1
                    role_entry = grouped[role]
                    role_resources = role_entry["resources"]
                    show_resource = len(role_resources) > 1
                    members = role_entry["members"]
                    print(f"  - `{role}` ({len(members)} principals)")
                    shown_members = 0
                    for member in sorted(members.keys()):
                        if shown_members >= max_items:
                            break
                        shown_members += 1
                        m_entry = members[member]
                        reasons_str = ",".join(sorted(m_entry["reasons"]))
                        reasons_str = f" ({reasons_str})" if reasons_str else ""
                        conds = sorted(m_entry["conditions"])
                        cond_str = f" condition={conds[0]}" if conds else ""
                        res_str = ""
                        if show_resource:
                            res_list = sorted(m_entry["resources"])
                            if len(res_list) == 1:
                                res_str = f" resource=`{res_list[0]}`"
                            elif len(res_list) > 1:
                                res_str = f" resource=`{res_list[0]}` (+{len(res_list) - 1} more)"
                        print(f"    - `{member}`{reasons_str}{cond_str}{res_str}")

        if principal_risks:
            print(f"{colored('Principals with flagged permissions', 'yellow', attrs=['bold'])}: {len(principal_risks)}")
            for item in principal_risks[:max_items]:
                principal = item.get("principal")
                flagged_perms = item.get("flagged_perms", {})
                if not flagged_perms:
                    continue
                roles = item.get("roles", []) or []
                print(f"  - `{principal}` ({len(roles)} roles)")
                print_permissions(flagged_perms)
                print()

        sa_keys = proj.get("service_account_keys", []) or []
        if sa_keys:
            print(f"{colored('Service account keys (user-managed)', 'yellow', attrs=['bold'])}: {len(sa_keys)}")
            for item in sa_keys[:max_items]:
                sa = item.get("service_account")
                key_name = item.get("key_name") or (item.get("key") or {}).get("name")
                inactive = item.get("inactive")
                reason = item.get("reason") or ""
                inactive_str = colored("INACTIVE", "red") if inactive else colored("ACTIVE/UNKNOWN", "green")
                extra = f" ({reason})" if reason else ""
                print(f"  - `{sa}` key={key_name}: {inactive_str}{extra}")

        unused_custom_roles = proj.get("unused_custom_roles", []) or []
        if unused_custom_roles:
            print(f"{colored('Unused custom roles', 'yellow', attrs=['bold'])}: {len(unused_custom_roles)}")
            for item in unused_custom_roles[:max_items]:
                role_name = item.get("role")
                flagged = item.get("flagged_perms", {}) or {}
                no_flagged = not any((flagged or {}).values())
                extra = " (No flagged permissions)" if no_flagged else ""
                print(f"  - `{role_name}`{extra}")
                if not no_flagged:
                    print_permissions(flagged)
                print()

        if inactive_principals:
            print(f"{colored('Inactive principals', 'yellow', attrs=['bold'])}: {len(inactive_principals)}")
            for item in inactive_principals[:max_items]:
                print(f"  - `{item.get('principal')}`: {item.get('reason')}")

        # Inactive SA keys are already labeled in "Service account keys (user-managed)" above.


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Find GCP IAM least-privilege opportunities using Recommender + Cloud Asset Inventory (uses your current gcloud login)."
    )
    scope_group = ap.add_mutually_exclusive_group()
    scope_group.add_argument("--project", action="append", help="Project ID to analyze (repeatable).")
    scope_group.add_argument("--organization", help="Organization ID to analyze (e.g., 1234567890).")
    scope_group.add_argument("--all-projects", action="store_true", help="Enumerate and analyze all accessible projects.")
    ap.add_argument(
        "--sa-json",
        help="Service Account JSON credentials (path to key file or raw JSON string). If omitted, uses gcloud creds or ADC/metadata.",
    )
    ap.add_argument(
        "--quota-project",
        help="Project ID used for API quota/billing (X-Goog-User-Project). Defaults to the first analyzed project.",
    )
    ap.add_argument("--page-size", type=int, default=200, help="Page size for API list calls (default: 200).")
    ap.add_argument("--max-items", type=int, default=20, help="Max findings to print per section (default: 20).")
    ap.add_argument("--out-json", help="Write full JSON results to this path (stdout stays human-readable).")
    ap.add_argument("--max-parallel-scopes", type=int, default=10, help="Max projects/scopes to analyze in parallel (default: 10).")
    ap.add_argument("--min-unused-days", type=int, default=90, help="Days without observed audit-log activity to consider inactive (default: 90).")
    ap.add_argument("--risk-levels", default="high,critical", help="Comma-separated list of risk levels to flag (low,medium,high,critical). Default: high,critical")
    ap.set_defaults(scan_resource_iam=True)
    ap.add_argument(
        "--include-folder-inheritance",
        action="store_true",
        default=True,
        help="Include IAM bindings inherited from ancestor folders (default: enabled).",
    )
    ap.add_argument(
        "--no-include-folder-inheritance",
        dest="include_folder_inheritance",
        action="store_false",
        help="Disable folder inheritance scan.",
    )
    ap.add_argument(
        "--no-scan-resource-iam",
        dest="scan_resource_iam",
        action="store_false",
        help="Disable scanning IAM bindings on resources inside the project (Cloud Asset Inventory).",
    )
    ap.add_argument(
        "--skip-workload-identity-scan",
        action="store_true",
        help="Skip Cloud Asset scan for Workload Identity Pool/Federation trust principals.",
    )
    ap.add_argument(
        "--allowed-domain",
        action="append",
        default=[],
        help="Allowed identity domain(s) (repeatable). Used to flag email/domain principals outside this allowlist.",
    )
    ap.add_argument(
        "--skip-external-domain-scan",
        action="store_true",
        help="Skip Cloud Asset scan for `domain:<domain>` principals (only runs when --allowed-domain is set).",
    )
    ap.add_argument(
        "--allowed-project",
        action="append",
        default=[],
        help="Allowed project ID(s) for cross-project serviceAccount members (repeatable).",
    )
    ap.add_argument(
        "--skip-external-trust-scan",
        action="store_true",
        help="Skip external trust scan (public, cross-project service accounts, workload identity federation, external domains).",
    )
    args = ap.parse_args()
    
    # Parse and validate risk levels
    valid_risk_levels = ['low', 'medium', 'high', 'critical']
    risk_levels = [r.strip().lower() for r in args.risk_levels.split(',')]
    for risk in risk_levels:
        if risk not in valid_risk_levels:
            print(f"[-] Error: Invalid risk level '{risk}'. Valid values: {', '.join(valid_risk_levels)}", file=sys.stderr)
            return 2

    try:
        token = get_access_token_auto(sa_json=args.sa_json)
    except Exception as exc:
        print(_err(f"Authentication error: {exc}"), file=sys.stderr)
        return 2

    projects: list[str] = []
    scope_items: list[tuple[str, str]] = []
    if args.organization:
        org_id = args.organization.strip()
        if not org_id:
            print(_err("Empty --organization provided."), file=sys.stderr)
            return 2
        scope_items = [("organization", f"organizations/{org_id}")]
    elif args.all_projects:
        # We need a quota project to list projects with user creds.
        scope_items = [("all_projects", "all_projects")]
    else:
        if args.project:
            for item in args.project:
                projects.extend([p.strip() for p in item.split(",") if p.strip()])
        else:
            default_project = get_default_project_from_gcloud()
            if default_project:
                projects = [default_project]
        projects = list(dict.fromkeys(projects))  # stable de-dup
        if not projects:
            print(_err("No project selected. Use --project (or set `gcloud config set project ...`)."), file=sys.stderr)
            return 2
        scope_items = [("project", f"projects/{pid}") for pid in projects]

    quota_project = args.quota_project or (
        scope_items[0][1].split("/", 1)[1] if scope_items[0][1].startswith("projects/") else None
    )
    if not quota_project:
        # For org scope, a quota project is required for some auth modes/APIs.
        default_project = get_default_project_from_gcloud()
        if default_project:
            quota_project = default_project
        else:
            print(
                _err("Missing --quota-project (required for --organization/--all-projects when no default gcloud project is set)."),
                file=sys.stderr,
            )
            return 2
    required_apis = [
        "recommender.googleapis.com",
        "cloudasset.googleapis.com",
        "iam.googleapis.com",
        "cloudresourcemanager.googleapis.com",
    ]
    try:
        newly_enabled = ensure_apis_enabled(quota_project, required_apis)
        if newly_enabled:
            print(
                _info(
                    f"Enabled missing APIs in quota project `{quota_project}`: {', '.join(newly_enabled)} (best-effort)."
                ),
                file=sys.stderr,
            )
    except Exception as exc:
        print(
            f"{colored('[!] ', 'yellow')}Warning: failed ensuring required APIs in quota project `{quota_project}`: {exc}",
            file=sys.stderr,
        )

    recommenders_project = [
        "google.iam.policy.Recommender",
        "google.iam.policy.ChangeRiskRecommender",
        "google.iam.serviceAccount.ChangeRiskRecommender",
    ]
    recommenders_org = [
        "google.iam.policy.Recommender",
    ]

    results: list[dict] = []
    allowed_domains = {d.strip().lower() for d in args.allowed_domain if d and d.strip()}
    allowed_projects = {p.strip() for p in args.allowed_project if p and p.strip()}
    # If org was provided, iterate projects in org (this is what we want for org-wide coverage).
    if scope_items and scope_items[0][0] == "organization":
        org_id = scope_items[0][1].split("/", 1)[1]
        try:
            print(_info(f"Enumerating projects in organization {org_id}..."), file=sys.stderr)
            org_projects = list_projects_in_organization(organization_id=org_id, token=token, quota_project=quota_project)
        except ApiError as exc:
            print(_err(f"Unable to list projects in organization {org_id}: {exc}"), file=sys.stderr)
            return 2
        if not org_projects:
            print(_err(f"No ACTIVE projects found under organization {org_id} (or no permissions)."), file=sys.stderr)
            return 2
        scope_items = [("project", f"projects/{pid}") for pid in org_projects]
    elif scope_items and scope_items[0][0] == "all_projects":
        try:
            print(_info("Enumerating all accessible projects..."), file=sys.stderr)
            all_projects = list_all_accessible_projects(token=token, quota_project=quota_project)
        except ApiError as exc:
            print(_err(f"Unable to list accessible projects: {exc}"), file=sys.stderr)
            return 2
        if not all_projects:
            print(_err("No ACTIVE projects found (or no permissions)."), file=sys.stderr)
            return 2
        scope_items = [("project", f"projects/{pid}") for pid in all_projects]

    since = datetime.now(timezone.utc) - timedelta(days=max(1, args.min_unused_days))

    org_display_cache: dict[str, Optional[str]] = {}
    org_domain_cache: dict[str, Optional[str]] = {}

    org_cache_lock = threading.Lock()

    def analyze_scope(scope_type: str, scope: str, *, show_progress: bool, progress_cb=None) -> dict:
        org_cache: dict[str, Optional[str]] = {}
        # Cache for IAM policies within this scope run to avoid duplicate fetches
        iam_policy_cache: dict[str, dict] = {}

        def resolve_org_for_project(other_project: str) -> Optional[str]:
            if other_project in org_cache:
                return org_cache[other_project]
            try:
                url = f"https://cloudresourcemanager.googleapis.com/v1/projects/{other_project}:getAncestry"
                data = http_json(url, token=token, quota_project=quota_project, method="POST", body={})
                org = None
                for e in data.get("ancestor", []) or []:
                    rid = e.get("resourceId", {}) or {}
                    if rid.get("type") == "organization":
                        org = rid.get("id")
                        break
                org_cache[other_project] = org
                return org
            except Exception:
                org_cache[other_project] = None
                return None

        project_id = scope.split("/", 1)[1] if scope_type == "project" else None
        scope_label = project_id or scope
        step_bar = _new_progress(total=6, desc=f"Analyzing {scope_label}", unit="step", leave=False) if show_progress else None

        project_org_id = resolve_org_for_project(project_id) if project_id else None

        project_allowed_domains = set(allowed_domains)
        if not project_allowed_domains and project_org_id:
            with org_cache_lock:
                if project_org_id not in org_display_cache:
                    try:
                        org_display_cache[project_org_id] = get_organization_display_name(
                            organization_id=project_org_id, token=token, quota_project=quota_project
                        )
                    except Exception:
                        org_display_cache[project_org_id] = None
                if project_org_id not in org_domain_cache:
                    org_domain_cache[project_org_id] = org_display_name_to_domain_hint(
                        org_display_cache.get(project_org_id)
                    )
                inferred = org_domain_cache.get(project_org_id)
            if inferred:
                project_allowed_domains.add(inferred)

        if step_bar is not None:
            step_bar.update(1)

        if progress_cb:
            progress_cb("init")

        project_out: dict = {
            "scope_type": scope_type,
            "scope": scope,
            "quota_project": quota_project,
            "recommenders": recommenders_org if scope_type == "organization" else recommenders_project,
            "recommendations": [],
            "public_iam": [],
            "workload_identity_trusts": [],
            "external_domains": [],
            "external_trusts": [],
            "principal_risks": [],
            "inactive_principals": [],
            "inactive_service_account_keys": [],
            "errors": [],
            "allowed_domains": sorted(project_allowed_domains),
        }

        if progress_cb:
            progress_cb("recommender")
        active_recommenders = recommenders_org if scope_type == "organization" else recommenders_project
        for recommender_id in active_recommenders:
            locations = list_recommender_locations(parent=scope, token=token, quota_project=quota_project)
            try:
                for location in locations:
                    recs_raw = iter_recommendations(
                        parent=scope,
                        recommender_id=recommender_id,
                        token=token,
                        quota_project=quota_project,
                        location=location,
                        page_size=args.page_size,
                    )
                    for rec in recs_raw:
                        summary = summarize_iam_policy_recommendation(rec)
                        summary["recommender"] = recommender_id
                        summary["location"] = location
                        summary["privilegedRole"] = role_has_flagged_permissions(
                            summary.get("role"),
                            token=token,
                            quota_project=quota_project,
                            risk_levels=risk_levels,
                        )
                        project_out["recommendations"].append(summary)
            except ApiError as exc:
                project_out["errors"].append(
                    {"kind": "recommender", "recommender": recommender_id, "error": str(exc)}
                )

        if step_bar is not None:
            step_bar.update(1)

        if progress_cb:
            progress_cb("public_iam")
        try:
            public_results = iter_search_all_iam_policies(
                scope=scope,
                query="policy:allUsers OR policy:allAuthenticatedUsers",
                token=token,
                quota_project=quota_project,
                page_size=min(args.page_size, 500),
            )
            project_out["public_iam"] = parse_public_iam(public_results)
        except ApiError as exc:
            project_out["errors"].append({"kind": "cloudasset", "scan": "public_iam", "error": str(exc)})

        if step_bar is not None:
            step_bar.update(1)

        # Inactive principals + keys (project scope only).
        if progress_cb:
            progress_cb("audit_logs")
        if scope_type == "project" and project_id:
            try:
                # Use cache for project policy
                cache_key_project = f"project:{project_id}"
                if cache_key_project not in iam_policy_cache:
                    iam_policy_cache[cache_key_project] = get_project_iam_policy(project_id=project_id, token=token, quota_project=quota_project)
                project_policy = iam_policy_cache[cache_key_project]
                principal_to_roles_project = iam_bindings_to_principal_roles(project_policy)

                principal_to_roles_org: dict[str, set[str]] = {}
                if project_org_id:
                    try:
                        # Use cache for org policy
                        cache_key_org = f"org:{project_org_id}"
                        if cache_key_org not in iam_policy_cache:
                            iam_policy_cache[cache_key_org] = get_organization_iam_policy(
                                organization_id=project_org_id, token=token, quota_project=quota_project
                            )
                        org_policy = iam_policy_cache[cache_key_org]
                        principal_to_roles_org = iam_bindings_to_principal_roles(org_policy) if org_policy else {}
                    except Exception:
                        principal_to_roles_org = {}

                principal_to_roles_folders: dict[str, set[str]] = {}
                if project_id and args.include_folder_inheritance:
                    try:
                        for fid in list_folder_ids_for_project(project_id=project_id, token=token, quota_project=quota_project):
                            try:
                                # Use cache for folder policies
                                cache_key_folder = f"folder:{fid}"
                                if cache_key_folder not in iam_policy_cache:
                                    iam_policy_cache[cache_key_folder] = get_folder_iam_policy(folder_id=fid, token=token, quota_project=quota_project)
                                fpol = iam_policy_cache[cache_key_folder]
                                if fpol:
                                    principal_to_roles_folders = merge_principal_roles(
                                        principal_to_roles_folders, iam_bindings_to_principal_roles(fpol)
                                    )
                            except Exception:
                                continue
                    except Exception:
                        pass

                principal_to_roles_full = merge_principal_roles(
                    principal_to_roles_project, principal_to_roles_folders, principal_to_roles_org
                )

                inactive_principals: list[dict] = []
                inactive_keys: list[dict] = []
                service_account_keys: list[dict] = []

                principal_items = [
                    (p, r)
                    for p, r in sorted(principal_to_roles_full.items())
                    if isinstance(p, str)
                    and not p.startswith("deleted:")
                    and (p.startswith("user:") or p.startswith("serviceAccount:"))
                ]
                principal_bar = (
                    _new_progress(
                        total=len(principal_items),
                        desc=f"Audit-log activity ({project_id})",
                        unit="principal",
                        leave=False,
                    )
                    if show_progress
                    else None
                )

                # Parallelize log lookups (3 threads max).
                principal_last_seen: dict[str, Optional[str]] = {}
                with concurrent.futures.ThreadPoolExecutor(max_workers=3) as log_executor:
                    future_to_principal = {}
                    for principal, _roles in principal_items:
                        principal_email = principal.split(":", 1)[1]
                        future_to_principal[
                            log_executor.submit(
                                get_last_audit_activity,
                                project_id=project_id,
                                principal_email=principal_email,
                                token=token,
                                quota_project=quota_project,
                                since=since,
                            )
                        ] = principal

                    for fut in concurrent.futures.as_completed(future_to_principal):
                        principal = future_to_principal[fut]
                        try:
                            principal_last_seen[principal] = fut.result()
                        except Exception:
                            principal_last_seen[principal] = None
                        if principal_bar is not None:
                            principal_bar.update(1)

                    # Service account keys: list keys (IAM API) sequentially, but check key usage logs in parallel (3 threads).
                    key_futures = {}
                    for principal, _roles in principal_items:
                        if not principal.startswith("serviceAccount:"):
                            continue
                        principal_email = principal.split(":", 1)[1]
                        try:
                            keys = list_service_account_user_managed_keys(
                                service_account_email=principal_email,
                                token=token,
                                quota_project=quota_project,
                            )
                        except Exception:
                            keys = []
                        for k in keys:
                            key_name = k.get("name")
                            if not isinstance(key_name, str) or not key_name:
                                continue
                            key_futures[
                                log_executor.submit(
                                    get_last_key_activity,
                                    project_id=project_id,
                                    service_account_key_name=key_name,
                                    token=token,
                                    quota_project=quota_project,
                                    since=since,
                                )
                            ] = (principal, k, key_name)

                    for fut in concurrent.futures.as_completed(key_futures):
                        principal, k, key_name = key_futures[fut]
                        try:
                            key_last_seen = fut.result()
                        except Exception:
                            key_last_seen = None
                        inactive = not bool(key_last_seen)
                        reason = (
                            f"No audit-log key usage observed in the last {args.min_unused_days} days (best-effort)."
                            if inactive
                            else None
                        )
                        service_account_keys.append(
                            {
                                "service_account": principal,
                                "key": k,
                                "key_name": key_name,
                                "inactive": inactive,
                                "reason": reason,
                                "last_seen": key_last_seen,
                            }
                        )
                        if inactive:
                            inactive_keys.append(
                                {
                                    "service_account": principal,
                                    "key": k,
                                    "key_name": key_name,
                                    "reason": reason,
                                }
                            )

                # Build inactive principals list (deterministic order).
                for principal, roles in principal_items:
                    if not principal_last_seen.get(principal):
                        inactive_principals.append(
                            {
                                "principal": principal,
                                "roles": sorted(roles),
                                "reason": f"No audit-log activity observed in the last {args.min_unused_days} days.",
                            }
                        )

                project_out["inactive_principals"] = inactive_principals
                project_out["inactive_service_account_keys"] = inactive_keys
                project_out["service_account_keys"] = service_account_keys
                if principal_bar is not None:
                    principal_bar.close()
            except ApiError as exc:
                project_out["errors"].append({"kind": "inactivity", "error": str(exc)})

        if step_bar is not None:
            step_bar.update(1)

        if progress_cb:
            progress_cb("trust_scans")
        
        # Cache for Cloud Asset queries to avoid duplicate searches
        cai_results_cache: dict[str, list[dict]] = {}
        
        # Query 1: public IAM (allUsers/allAuthenticatedUsers)
        public_query = "policy:allUsers OR policy:allAuthenticatedUsers"
        try:
            public_results = iter_search_all_iam_policies(
                scope=scope,
                query=public_query,
                token=token,
                quota_project=quota_project,
                page_size=min(args.page_size, 500),
            )
            cai_results_cache[public_query] = public_results
            project_out["public_iam"] = parse_public_iam(public_results)
        except ApiError as exc:
            project_out["errors"].append({"kind": "cloudasset", "scan": "public_iam", "error": str(exc)})
            cai_results_cache[public_query] = []
        
        # Query 2: workload identity trusts
        wit_query = 'policy:"principalSet://iam.googleapis.com/" OR policy:"principal://iam.googleapis.com/"'
        if not args.skip_workload_identity_scan:
            try:
                wit_results = iter_search_all_iam_policies(
                    scope=scope,
                    query=wit_query,
                    token=token,
                    quota_project=quota_project,
                    page_size=min(args.page_size, 500),
                )
                cai_results_cache[wit_query] = wit_results
                project_out["workload_identity_trusts"] = parse_workload_identity_trusts(wit_results)
            except ApiError as exc:
                project_out["errors"].append(
                    {"kind": "cloudasset", "scan": "workload_identity_trusts", "error": str(exc)}
                )
                cai_results_cache[wit_query] = []
        else:
            cai_results_cache[wit_query] = []

        # Query 3: domain principals
        domain_query = 'policy:"domain:"'
        if project_allowed_domains and not args.skip_external_domain_scan:
            try:
                domain_results = iter_search_all_iam_policies(
                    scope=scope,
                    query=domain_query,
                    token=token,
                    quota_project=quota_project,
                    page_size=min(args.page_size, 500),
                )
                cai_results_cache[domain_query] = domain_results
                project_out["external_domains"] = parse_external_domains(domain_results, project_allowed_domains)
            except ApiError as exc:
                project_out["errors"].append(
                    {"kind": "cloudasset", "scan": "external_domains", "error": str(exc)}
                )
                cai_results_cache[domain_query] = []
        else:
            cai_results_cache[domain_query] = []

        # External trust scan - reuse cached results where possible
        if not args.skip_external_trust_scan:
            try:
                # Reuse already-fetched results, only query new ones
                combined: list[dict] = []
                combined.extend(cai_results_cache.get(public_query, []))
                combined.extend(cai_results_cache.get(wit_query, []))
                combined.extend(cai_results_cache.get(domain_query, []))
                
                # Query the remaining types that weren't cached
                for q in ['policy:"serviceAccount:"', 'policy:"user:"', 'policy:"group:"']:
                    combined.extend(
                        iter_search_all_iam_policies(
                            scope=scope,
                            query=q,
                            token=token,
                            quota_project=quota_project,
                            page_size=min(args.page_size, 500),
                        )
                    )

                project_out["external_trusts"] = parse_external_trusts(
                    results=combined,
                    project_id=project_id,
                    allowed_domains=project_allowed_domains,
                    allowed_projects=(allowed_projects | ({project_id} if project_id else set())),
                    include_cross_project_same_org=True,
                    project_org_id=project_org_id,
                    resolve_org_for_project=resolve_org_for_project,
                    source_scope=scope,
                )
            except ApiError as exc:
                project_out["errors"].append({"kind": "cloudasset", "scan": "external_trusts", "error": str(exc)})

        if (
            scope_type == "project"
            and project_org_id
            and project_allowed_domains
            and not args.skip_external_trust_scan
        ):
            try:
                org_scope = f"organizations/{project_org_id}"
                org_queries = [
                    "policy:allUsers OR policy:allAuthenticatedUsers",
                    'policy:"principalSet://iam.googleapis.com/" OR policy:"principal://iam.googleapis.com/"',
                    'policy:"domain:"',
                    'policy:"user:"',
                    'policy:"group:"',
                ]
                org_combined: list[dict] = []
                for q in org_queries:
                    org_combined.extend(
                        iter_search_all_iam_policies(
                            scope=org_scope,
                            query=q,
                            token=token,
                            quota_project=quota_project,
                            page_size=min(args.page_size, 500),
                        )
                    )
                org_trusts = parse_external_trusts(
                    results=org_combined,
                    project_id=None,
                    allowed_domains=project_allowed_domains,
                    allowed_projects=allowed_projects,
                    include_cross_project_same_org=True,
                    project_org_id=project_org_id,
                    resolve_org_for_project=resolve_org_for_project,
                    source_scope=org_scope,
                )
                if org_trusts:
                    project_out.setdefault("external_trusts", [])
                    project_out["external_trusts"].extend(org_trusts)
            except ApiError as exc:
                project_out["errors"].append({"kind": "cloudasset", "scan": "external_trusts_org", "error": str(exc)})

        if step_bar is not None:
            step_bar.update(1)

        # Principal risks + unused custom roles.
        if progress_cb:
            progress_cb("expand_roles")
        try:
            # Reuse cached project policy
            cache_key_project = f"project:{project_id}"
            if project_id:
                if cache_key_project not in iam_policy_cache:
                    iam_policy_cache[cache_key_project] = get_project_iam_policy(project_id=project_id, token=token, quota_project=quota_project)
                project_policy = iam_policy_cache[cache_key_project]
            else:
                project_policy = {}
            principal_to_roles_project = iam_bindings_to_principal_roles(project_policy) if project_policy else {}

            principal_to_roles_org: dict[str, set[str]] = {}
            if project_org_id:
                try:
                    # Reuse cached org policy
                    cache_key_org = f"org:{project_org_id}"
                    if cache_key_org not in iam_policy_cache:
                        iam_policy_cache[cache_key_org] = get_organization_iam_policy(
                            organization_id=project_org_id, token=token, quota_project=quota_project
                        )
                    org_policy = iam_policy_cache[cache_key_org]
                    principal_to_roles_org = iam_bindings_to_principal_roles(org_policy) if org_policy else {}
                except Exception:
                    principal_to_roles_org = {}

            principal_to_roles_folders: dict[str, set[str]] = {}
            if project_id and project_org_id and args.include_folder_inheritance:
                try:
                    folder_ids = list_folder_ids_for_project(project_id=project_id, token=token, quota_project=quota_project)
                except Exception:
                    folder_ids = []
                for fid in folder_ids:
                    try:
                        # Reuse cached folder policy
                        cache_key_folder = f"folder:{fid}"
                        if cache_key_folder not in iam_policy_cache:
                            iam_policy_cache[cache_key_folder] = get_folder_iam_policy(folder_id=fid, token=token, quota_project=quota_project)
                        fpol = iam_policy_cache[cache_key_folder]
                        principal_to_roles_folders = merge_principal_roles(
                            principal_to_roles_folders, iam_bindings_to_principal_roles(fpol) if fpol else {}
                        )
                    except Exception:
                        continue

            principal_to_roles_resource: dict[str, set[str]] = {}
            if project_id and args.scan_resource_iam:
                try:
                    resource_queries = [
                        'policy:"user:"',
                        'policy:"group:"',
                        'policy:"serviceAccount:"',
                        "policy:allUsers OR policy:allAuthenticatedUsers",
                        'policy:"domain:"',
                    ]
                    res_combined: list[dict] = []
                    for q in resource_queries:
                        res_combined.extend(
                            iter_search_all_iam_policies(
                                scope=f"projects/{project_id}",
                                query=q,
                                token=token,
                                quota_project=quota_project,
                                page_size=min(args.page_size, 500),
                            )
                        )
                    principal_to_roles_resource = principal_roles_from_search_results(res_combined)
                except Exception:
                    principal_to_roles_resource = {}

            principal_to_roles_all = merge_principal_roles(
                principal_to_roles_project,
                principal_to_roles_folders,
                principal_to_roles_org,
                principal_to_roles_resource,
            )
            project_out["principal_sources"] = {
                "project": len(principal_to_roles_project),
                "folders": len(principal_to_roles_folders),
                "organization": len(principal_to_roles_org),
                "resources": len(principal_to_roles_resource),
                "merged": len(principal_to_roles_all),
            }
        except Exception:
            principal_to_roles_all = {}
            project_out["principal_sources"] = {"project": 0, "folders": 0, "organization": 0, "resources": 0, "merged": 0}

        # Prefetch IAM role permission expansions in parallel (3 threads max).
        # This speeds up the later per-principal expansion phase.
        roles_to_fetch: set[str] = set()
        for rs in (principal_to_roles_all or {}).values():
            if not rs:
                continue
            for r in rs:
                if isinstance(r, str) and r:
                    roles_to_fetch.add(r)
        if roles_to_fetch:
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as role_exec:
                future_roles = [
                    role_exec.submit(get_role_permissions, role=role, token=token, quota_project=quota_project)
                    for role in sorted(roles_to_fetch)
                ]
                for fut in concurrent.futures.as_completed(future_roles):
                    try:
                        fut.result()
                    except Exception:
                        pass

        principal_items_all = list(sorted(principal_to_roles_all.items()))
        principal_eval_bar = (
            _new_progress(
                total=len(principal_items_all),
                desc=f"Expanding roles ({scope_label})",
                unit="principal",
                leave=False,
            )
            if show_progress
            else None
        )
        for principal, roles in principal_items_all:
            if principal_eval_bar is not None:
                principal_eval_bar.update(1)
            if principal in ("allUsers", "allAuthenticatedUsers"):
                continue
            if principal.startswith("deleted:"):
                continue
            if principal.startswith("domain:"):
                continue
            # Accumulate permissions from all roles, then deduplicate before classification
            perms_set: set[str] = set()
            for role in sorted(roles):
                perms_set.update(get_role_permissions(role=role, token=token, quota_project=quota_project))
            
            # Convert to list for classification (already deduplicated)
            perms = list(perms_set)
            
            known = classify_permissions_yaml(perms, risk_levels)
            if not known["flagged_perms"]:
                continue
            project_out["principal_risks"].append(
                {"principal": principal, "roles": sorted(roles), "flagged_perms": known["flagged_perms"]}
            )
        if principal_eval_bar is not None:
            principal_eval_bar.close()

        # Unused custom roles (project-only).
        if progress_cb:
            progress_cb("custom_roles")
        if project_id:
            try:
                used_roles = set()
                for roles in principal_to_roles_all.values():
                    used_roles.update(roles)
                custom_roles = list_project_custom_roles(project_id=project_id, token=token, quota_project=quota_project)
                unused_custom_roles: list[dict] = []
                for r in custom_roles:
                    role_name = r.get("name")
                    if not isinstance(role_name, str) or not role_name:
                        continue
                    if role_name in used_roles:
                        continue
                    perms = get_role_permissions(role=role_name, token=token, quota_project=quota_project)
                    known = classify_permissions_yaml(perms, risk_levels)
                    flagged = known.get("flagged_perms") or {}
                    unused_custom_roles.append({"role": role_name, "flagged_perms": flagged})
                project_out["unused_custom_roles"] = unused_custom_roles
            except Exception as exc:
                project_out["errors"].append({"kind": "custom_roles", "error": str(exc)})

        if step_bar is not None:
            step_bar.update(1)
            step_bar.close()

        if progress_cb:
            progress_cb("finalize")
        return project_out

    def _analyze_with_slot(idx: int, scope_type: str, scope: str, overall: StageProgress, slot_progress: SlotStageProgress) -> dict:
        label = scope.split("/", 1)[1] if isinstance(scope, str) and "/" in scope else str(scope)
        slot = slot_progress.acquire(label)
        try:
            return analyze_scope(
                scope_type,
                scope,
                show_progress=False,
                progress_cb=slot_progress.make_callback(slot, forward=overall.make_callback(idx)),
            )
        finally:
            slot_progress.finish(slot)
            slot_progress.release(slot)

    if len(scope_items) > 1:
        out_by_index: dict[int, dict] = {}
        overall = StageProgress(
            total=len(scope_items),
            desc="Analyzing projects",
            unit="project",
            tqdm_factory=(lambda **kw: tqdm(**kw)) if tqdm is not None else None,
            stages=[
                "init",
                "recommender",
                "public_iam",
                "audit_logs",
                "trust_scans",
                "expand_roles",
                "custom_roles",
                "finalize",
            ],
        )
        stages = [
            "init",
            "recommender",
            "public_iam",
            "audit_logs",
            "trust_scans",
            "expand_roles",
            "custom_roles",
            "finalize",
        ]
        slot_progress = SlotStageProgress(
            max_slots=min(args.max_parallel_scopes, len(scope_items)),
            stages=stages,
            unit="project",
            enabled=True,
            position_offset=1,
        )
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.max_parallel_scopes, len(scope_items))) as executor:
            future_map = {}
            for idx, (scope_type, scope) in enumerate(scope_items):
                future_map[
                    executor.submit(
                        (lambda _idx=idx, _scope_type=scope_type, _scope=scope: _analyze_with_slot(_idx, _scope_type, _scope, overall, slot_progress))
                    )
                ] = idx
            for fut in concurrent.futures.as_completed(future_map):
                idx = future_map[fut]
                try:
                    out_by_index[idx] = fut.result()
                except Exception as exc:
                    scope_type, scope = scope_items[idx]
                    out_by_index[idx] = {
                        "scope_type": scope_type,
                        "scope": scope,
                        "quota_project": quota_project,
                        "errors": [{"kind": "worker", "error": str(exc)}],
                    }
                overall.finish(idx)
        overall.close()
        slot_progress.close()
        results = [out_by_index[i] for i in range(len(scope_items)) if i in out_by_index]
    else:
        scope_type, scope = scope_items[0]
        results = [analyze_scope(scope_type, scope, show_progress=True)]

    if args.out_json:
        targets: list[dict] = []
        for r in results:
            if not isinstance(r, dict):
                continue
            scope = r.get("scope") or ""
            scope_type = r.get("scope_type") or ""
            if isinstance(scope, str) and scope.startswith("projects/"):
                target_type = "project"
                label = scope.split("/", 1)[1]
            elif isinstance(scope, str) and scope.startswith("organizations/"):
                target_type = "organization"
                label = scope.split("/", 1)[1]
            else:
                target_type = scope_type or "scope"
                label = None
            targets.append(
                Target(
                    target_type=target_type,
                    target_id=str(scope) if scope else "<unknown>",
                    label=str(label) if label else None,
                    data=normalize_gcp_scope(r),
                ).to_dict()
            )

        report = build_report(
            provider="gcp",
            targets=targets,
            errors=[],
            extra_summary={
                "total_scopes": len(results),
                "total_projects": sum(1 for r in results if (r.get("scope") or "").startswith("projects/")),
            },
        )
        atomic_write_json(args.out_json, report)

    print_human(results, max_items=args.max_items)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
