#!/usr/bin/env python3

import argparse
import json
import os
import shlex
import subprocess
import sys
import time
from typing import Optional
import fnmatch
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone


DEFAULT_LOCATION = "global"

try:
    import yaml  # type: ignore
except Exception as exc:
    raise SystemExit(
        "Missing dependency `pyyaml`. Install with `pip3 install -r requirements.txt`."
    ) from exc

try:
    import google.auth  # type: ignore
    import google.oauth2.service_account  # type: ignore
    import google.auth.transport.requests  # type: ignore
except Exception as exc:
    raise SystemExit(
        "Missing dependency `google-auth`. Install with `pip3 install -r requirements.txt`."
    ) from exc


def load_gcp_permissions_yaml(path: str = "gcp_permissions_cat.yaml") -> dict:
    if not os.path.exists(path):
        raise SystemExit(f"Missing `{path}`. Create it or place it next to this script.")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as exc:
        raise SystemExit(f"Failed to parse `{path}`: {exc}") from exc
    if not data or not isinstance(data, dict):
        raise SystemExit(f"`{path}` is empty or invalid (expected a YAML mapping).")
    return data


_GCP_PERMISSIONS_DATA: Optional[dict] = None


def get_gcp_permissions_data() -> dict:
    global _GCP_PERMISSIONS_DATA
    if _GCP_PERMISSIONS_DATA is None:
        _GCP_PERMISSIONS_DATA = load_gcp_permissions_yaml()
    return _GCP_PERMISSIONS_DATA


class ApiError(RuntimeError):
    pass


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


def get_project_iam_policy(*, project_id: str, token: str, quota_project: str) -> dict:
    url = f"https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}:getIamPolicy"
    return http_json(url, token=token, quota_project=quota_project, method="POST", body={})


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
    value = run_text(["gcloud", "config", "get-value", "project"])
    return value if value and value.lower() != "(unset)" else None


def enable_apis(project_id: str, apis: list[str]) -> None:
    subprocess.run(
        ["gcloud", "services", "enable", *apis, "--project", project_id, "-q"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )


_ROLE_PERMISSIONS_CACHE: dict[str, list[str]] = {}


def get_role_permissions(*, role: str, token: str, quota_project: Optional[str]) -> list[str]:
    if not role:
        return []
    if role in _ROLE_PERMISSIONS_CACHE:
        return _ROLE_PERMISSIONS_CACHE[role]

    # Supported formats:
    # - roles/viewer
    # - projects/<project>/roles/<customRole>
    # - organizations/<org>/roles/<customRole>
    if role.startswith("roles/") or role.startswith("projects/") or role.startswith("organizations/"):
        url = f"https://iam.googleapis.com/v1/{role}"
    else:
        _ROLE_PERMISSIONS_CACHE[role] = []
        return []

    try:
        data = http_json(url, token=token, quota_project=quota_project)
    except Exception:
        _ROLE_PERMISSIONS_CACHE[role] = []
        return []

    perms = data.get("includedPermissions", []) or []
    perms = [p for p in perms if isinstance(p, str)]
    _ROLE_PERMISSIONS_CACHE[role] = perms
    return perms


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
            # Common case with user credentials if quota project header is missing.
            if (
                quota_project is None
                and "requires a quota project" in str(exc).lower()
            ):
                return iter_recommendations(
                    project_id=project_id,
                    recommender_id=recommender_id,
                    token=token,
                    quota_project=project_id,
                    location=location,
                    state_filter=state_filter,
                    page_size=page_size,
                )
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
            # Some APIs don't require a quota project, and using one can fail if the service
            # isn't enabled there. Retry without the quota project header.
            if quota_project is not None and "service_disabled" in message:
                data = http_json(url, token=token, quota_project=None)
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
    """Classify permissions by risk level based on YAML patterns.
    
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
    
    yaml_data = get_gcp_permissions_data()
    
    # Check permissions by risk level
    for risk_level in ['low', 'medium', 'high', 'critical']:
        if risk_level not in risk_levels:
            continue  # Skip risk levels not requested
            
        if risk_level not in yaml_data:
            continue
            
        patterns = yaml_data[risk_level]
        if not isinstance(patterns, list):
            continue
            
        for entry in patterns:
            if not isinstance(entry, str) or not entry.strip():
                continue
                
            # Handle comma-separated permissions (all must be present)
            if "," in entry:
                required = [p.strip() for p in entry.split(",") if p.strip()]
            else:
                required = [entry.strip()]
            
            # Check if all required permissions match
            if all(any(fnmatch.fnmatch(p, pat) for p in perms) for pat in required):
                if risk_level not in flagged_perms:
                    flagged_perms[risk_level] = []
                flagged_perms[risk_level].extend(required)
    
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
        print(f"\nScope: {label}")

        errors = proj.get("errors", []) or []
        if errors:
            print(f"  Errors: {len(errors)} (use --json for details)")

        recs = proj.get("recommendations", [])
        print(f"  IAM recommendations: {len(recs)}")
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
            print(f"    - {principal} -> {role}{priv}")
            print(f"      resource: {resource}")
            if desc:
                print(f"      {desc}")

        public = proj.get("public_iam", [])
        print(f"  Public IAM bindings: {len(public)}")
        for item in public[:max_items]:
            print(f"    - {item.get('resource')} : {item.get('role')} -> {', '.join(item.get('members') or [])}")

        wit = proj.get("workload_identity_trusts", [])
        print(f"  Workload Identity trusts: {len(wit)}")
        for item in wit[:max_items]:
            print(f"    - {item.get('resource')} : {item.get('role')}")

        external_domains = proj.get("external_domains", [])
        if external_domains is not None:
            print(f"  External domain principals: {len(external_domains)}")
            for item in external_domains[:max_items]:
                print(f"    - {item.get('resource')} : {item.get('role')} -> {', '.join(item.get('members') or [])}")

        external_trusts = proj.get("external_trusts", [])
        if external_trusts is not None:
            print(f"  External trusts: {len(external_trusts)}")
            for item in external_trusts[:max_items]:
                reasons = ",".join(item.get("reasons") or [])
                cond = item.get("condition", {}) or {}
                cond_expr = cond.get("expression")
                cond_str = f" condition={cond_expr}" if cond_expr else ""
                print(f"    - {item.get('member')} -> {item.get('role')} ({reasons}){cond_str}")

        principal_risks = proj.get("principal_risks", [])
        if principal_risks:
            print(f"  Principal risks: {len(principal_risks)}")
            for item in principal_risks[:max_items]:
                principal = item.get("principal")
                flagged_perms = item.get("flagged_perms", {})
                if not flagged_perms:
                    continue
                
                # Build summary string showing count per risk level
                risk_summary = []
                for risk_level in ['critical', 'high', 'medium', 'low']:
                    if risk_level in flagged_perms:
                        count = len(flagged_perms[risk_level])
                        risk_summary.append(f"{risk_level}={count}")
                
                print(f"    - {principal}: {' '.join(risk_summary)}")


        inactive_principals = proj.get("inactive_principals", []) or []
        if inactive_principals:
            print(f"  Inactive principals: {len(inactive_principals)}")
            for item in inactive_principals[:max_items]:
                print(f"    - {item.get('principal')}: {item.get('reason')}")

        inactive_keys = proj.get("inactive_service_account_keys", []) or []
        if inactive_keys:
            print(f"  Inactive SA keys: {len(inactive_keys)}")
            for item in inactive_keys[:max_items]:
                sa = item.get("service_account")
                key = (item.get("key") or {}).get("name") if isinstance(item.get("key"), dict) else None
                print(f"    - {sa} key={key}: {item.get('reason')}")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Find GCP IAM least-privilege opportunities using Recommender + Cloud Asset Inventory (uses your current gcloud login)."
    )
    scope_group = ap.add_mutually_exclusive_group()
    scope_group.add_argument("--project", action="append", help="Project ID to analyze (repeatable).")
    scope_group.add_argument("--organization", help="Organization ID to analyze (e.g., 1234567890).")
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
    ap.add_argument("--json", action="store_true", help="Output full JSON results.")
    ap.add_argument("--min-unused-days", type=int, default=90, help="Days without observed audit-log activity to consider inactive (default: 90).")
    ap.add_argument("--risk-levels", default="high,critical", help="Comma-separated list of risk levels to flag (low,medium,high,critical). Default: high,critical")
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
        print(f"[-] Authentication error: {exc}", file=sys.stderr)
        return 2

    projects: list[str] = []
    scope_items: list[tuple[str, str]] = []
    if args.organization:
        org_id = args.organization.strip()
        if not org_id:
            print("Empty --organization provided.", file=sys.stderr)
            return 2
        scope_items = [("organization", f"organizations/{org_id}")]
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
            print("No project selected. Use --project (or set `gcloud config set project ...`).", file=sys.stderr)
            return 2
        scope_items = [("project", f"projects/{pid}") for pid in projects]

    quota_project = args.quota_project or (scope_items[0][1].split("/", 1)[1] if scope_items[0][1].startswith("projects/") else None)
    if not quota_project:
        # For org scope, a quota project is required for some auth modes/APIs.
        default_project = get_default_project_from_gcloud()
        if default_project:
            quota_project = default_project
        else:
            print("Missing --quota-project (required for --organization when no default gcloud project is set).", file=sys.stderr)
            return 2
    try:
        enable_apis(
            quota_project,
            [
                "recommender.googleapis.com",
                "cloudasset.googleapis.com",
                "iam.googleapis.com",
                "cloudresourcemanager.googleapis.com",
            ],
        )
    except Exception as exc:
        print(
            f"[!] Warning: failed enabling required APIs in quota project `{quota_project}`: {exc}",
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
    default_account = run_text(["gcloud", "config", "get-value", "account"])
    default_domain = default_account.split("@", 1)[1].lower() if "@" in default_account else None
    allowed_domains = {d.strip().lower() for d in args.allowed_domain if d and d.strip()}
    if default_domain:
        allowed_domains.add(default_domain)
    allowed_projects = {p.strip() for p in args.allowed_project if p and p.strip()}
    needs_external_domain_scan = bool(allowed_domains) and not args.skip_external_domain_scan
    # If org was provided, iterate projects in org (this is what we want for org-wide coverage).
    if scope_items and scope_items[0][0] == "organization":
        org_id = scope_items[0][1].split("/", 1)[1]
        try:
            org_projects = list_projects_in_organization(organization_id=org_id, token=token, quota_project=quota_project)
        except ApiError as exc:
            print(f"[-] Unable to list projects in organization {org_id}: {exc}", file=sys.stderr)
            return 2
        if not org_projects:
            print(f"[-] No ACTIVE projects found under organization {org_id} (or no permissions).", file=sys.stderr)
            return 2
        scope_items = [("project", f"projects/{pid}") for pid in org_projects]

    since = datetime.now(timezone.utc) - timedelta(days=max(1, args.min_unused_days))

    for scope_type, scope in scope_items:
        org_cache: dict[str, Optional[str]] = {}

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
        project_org_id = resolve_org_for_project(project_id) if project_id else None

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
        }

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
                    {
                        "kind": "recommender",
                        "recommender": recommender_id,
                        "error": str(exc),
                    }
                )

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

        # Inactive principals + keys (project scope only, relies on whatever audit logs exist already).
        if scope_type == "project" and project_id:
            try:
                policy = get_project_iam_policy(project_id=project_id, token=token, quota_project=quota_project)
                principal_to_roles_full = iam_bindings_to_principal_roles(policy)

                inactive_principals: list[dict] = []
                inactive_keys: list[dict] = []

                for principal, roles in sorted(principal_to_roles_full.items()):
                    if principal.startswith("deleted:"):
                        continue
                    if not (principal.startswith("user:") or principal.startswith("serviceAccount:")):
                        continue
                    principal_email = principal.split(":", 1)[1]
                    last_seen = get_last_audit_activity(
                        project_id=project_id,
                        principal_email=principal_email,
                        token=token,
                        quota_project=quota_project,
                        since=since,
                    )
                    if not last_seen:
                        inactive_principals.append(
                            {
                                "principal": principal,
                                "roles": sorted(roles),
                                "reason": f"No audit-log activity observed in the last {args.min_unused_days} days.",
                            }
                        )

                    if principal.startswith("serviceAccount:"):
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
                            key_last_seen = None
                            try:
                                key_last_seen = get_last_key_activity(
                                    project_id=project_id,
                                    service_account_key_name=key_name,
                                    token=token,
                                    quota_project=quota_project,
                                    since=since,
                                )
                            except Exception:
                                key_last_seen = None
                            if not key_last_seen:
                                inactive_keys.append(
                                    {
                                        "service_account": principal,
                                        "key": k,
                                        "reason": f"No audit-log key usage observed in the last {args.min_unused_days} days (best-effort).",
                                    }
                                )

                project_out["inactive_principals"] = inactive_principals
                project_out["inactive_service_account_keys"] = inactive_keys
            except ApiError as exc:
                project_out["errors"].append({"kind": "inactivity", "error": str(exc)})

        if not args.skip_workload_identity_scan:
            try:
                wit_query = 'policy:"principalSet://iam.googleapis.com/" OR policy:"principal://iam.googleapis.com/"'
                wit_results = iter_search_all_iam_policies(
                    scope=scope,
                    query=wit_query,
                    token=token,
                    quota_project=quota_project,
                    page_size=min(args.page_size, 500),
                )
                project_out["workload_identity_trusts"] = parse_workload_identity_trusts(wit_results)
            except ApiError as exc:
                project_out["errors"].append(
                    {"kind": "cloudasset", "scan": "workload_identity_trusts", "error": str(exc)}
                )

        if needs_external_domain_scan:
            try:
                domain_results = iter_search_all_iam_policies(
                    scope=scope,
                    query='policy:"domain:"',
                    token=token,
                    quota_project=quota_project,
                    page_size=min(args.page_size, 500),
                )
                project_out["external_domains"] = parse_external_domains(domain_results, allowed_domains)
            except ApiError as exc:
                project_out["errors"].append(
                    {"kind": "cloudasset", "scan": "external_domains", "error": str(exc)}
                )

        if not args.skip_external_trust_scan:
            try:
                queries = [
                    "policy:allUsers OR policy:allAuthenticatedUsers",
                    'policy:"principalSet://iam.googleapis.com/" OR policy:"principal://iam.googleapis.com/"',
                    'policy:"domain:"',
                    'policy:"serviceAccount:"',
                ]

                combined: list[dict] = []
                for q in queries:
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
                    allowed_domains=allowed_domains,
                    allowed_projects=(allowed_projects | ({project_id} if project_id else set())),
                    include_cross_project_same_org=True,
                    project_org_id=project_org_id,
                    resolve_org_for_project=resolve_org_for_project,
                )
            except ApiError as exc:
                project_out["errors"].append({"kind": "cloudasset", "scan": "external_trusts", "error": str(exc)})

        # Privileged permissions per principal (expand roles -> permissions; match YAML; optionally ask AI).
        # This does not require any logs; it's purely based on granted permissions.
        try:
            policy = get_project_iam_policy(project_id=project_id, token=token, quota_project=quota_project) if project_id else {}
            principal_to_roles_all = iam_bindings_to_principal_roles(policy) if policy else {}
        except Exception:
            principal_to_roles_all = {}

        for principal, roles in sorted(principal_to_roles_all.items()):
            if principal in ("allUsers", "allAuthenticatedUsers"):
                continue
            if principal.startswith("deleted:"):
                continue
            if principal.startswith("domain:"):
                continue
            perms: list[str] = []
            for role in sorted(roles):
                perms.extend(get_role_permissions(role=role, token=token, quota_project=quota_project))

            known = classify_permissions_yaml(perms, risk_levels)
            if not known["flagged_perms"]:
                continue

            # Build output structure with flagged permissions by risk level
            principal_risk = {
                "principal": principal,
                "roles": sorted(roles),
                "flagged_perms": known["flagged_perms"],
            }
            
            project_out["principal_risks"].append(principal_risk)

        results.append(project_out)

    if args.json:
        print(json.dumps({"results": results}, indent=2, sort_keys=False))
        return 0

    print_human(results, max_items=args.max_items)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
