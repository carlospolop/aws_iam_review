#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

import requests
from termcolor import colored
from tqdm import tqdm

import msal
try:
    from azure.core.credentials import AccessToken
    from azure.core.exceptions import HttpResponseError
    from azure.identity import ClientSecretCredential, DeviceCodeCredential
    from azure.mgmt.authorization import AuthorizationManagementClient
    from azure.mgmt.monitor import MonitorManagementClient
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.resource import SubscriptionClient
except Exception as e:  # pragma: no cover
    raise SystemExit(
        "Missing/invalid Azure dependencies. Install with:\n"
        "  python3 -m pip install -r requirements.txt\n\n"
        f"Import error: {e}"
    )

from bluepeass.progress import StageProgress
from bluepeass.report import Target, atomic_write_json, build_report
from bluepeass.normalize import normalize_azure_management_groups, normalize_azure_subscription
from scripts.permission_risk_classifier import RISK_LEVELS, RISK_ORDER, classify_permission


AZURE_PUBLIC_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Common public client (Azure CLI app id)
MGMT_API_VERSION = "2020-05-01"
AUTHZ_API_VERSION = "2022-04-01"


class AzureMsalTokenCacheCredential:
    """
    Use the Azure CLI MSAL token cache (~/.azure/msal_token_cache.json) WITHOUT invoking `az`.
    This keeps the script SDK/HTTP-only while letting users reuse `az login` sessions.
    """

    def __init__(
        self,
        *,
        cache_path: Optional[str] = None,
        client_id: str = AZURE_PUBLIC_CLIENT_ID,
        authority: str = "https://login.microsoftonline.com/organizations",
    ) -> None:
        self._cache_path = cache_path or os.path.expanduser("~/.azure/msal_token_cache.json")
        self._client_id = client_id
        self._authority = authority
        self._cache = msal.SerializableTokenCache()
        self._app: Optional[msal.PublicClientApplication] = None
        self._loaded = False

    def _load(self) -> None:
        if self._loaded:
            return
        if not os.path.exists(self._cache_path):
            raise RuntimeError(f"Azure CLI token cache not found at {self._cache_path}")
        with open(self._cache_path, "r", encoding="utf-8") as f:
            self._cache.deserialize(f.read())
        self._app = msal.PublicClientApplication(
            client_id=self._client_id,
            authority=self._authority,
            token_cache=self._cache,
        )
        self._loaded = True

    def get_token(self, *scopes: str, **kwargs: Any) -> AccessToken:
        self._load()
        assert self._app is not None
        accounts = self._app.get_accounts()
        if not accounts:
            raise RuntimeError("No accounts found in Azure CLI token cache. Run `az login` or use device-code/client-secret auth.")
        result = self._app.acquire_token_silent(list(scopes), account=accounts[0])
        if not result or "access_token" not in result:
            raise RuntimeError(f"Failed to acquire token silently from Azure CLI cache: {result}")
        return AccessToken(result["access_token"], int(result.get("expires_on") or 0))


def _jwt_exp(token: str) -> Optional[int]:
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        payload = parts[1]
        payload += "=" * (-len(payload) % 4)
        data = base64.urlsafe_b64decode(payload.encode("utf-8"))
        obj = json.loads(data.decode("utf-8"))
        exp = obj.get("exp")
        return int(exp) if exp is not None else None
    except Exception:
        return None


class StaticTokenCredential:
    def __init__(self, *, arm_token: str, graph_token: Optional[str] = None) -> None:
        self._arm_token = (arm_token or "").strip()
        self._graph_token = (graph_token or "").strip() or None

    def get_token(self, *scopes: str, **kwargs: Any) -> AccessToken:
        if any("graph.microsoft.com" in s for s in scopes):
            if not self._graph_token:
                raise ValueError("Graph token is required for Microsoft Graph scopes. Provide --graph-token or use --no-resolve-principals.")
            token = self._graph_token
        else:
            token = self._arm_token
        exp = _jwt_exp(token) or int(time.time()) + 300
        return AccessToken(token, exp)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _jwt_claims(token: str) -> dict[str, Any]:
    """
    Decode JWT claims WITHOUT verifying signature (best-effort).
    Useful to extract oid/upn/tid from access tokens.
    """
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1]
        pad = "=" * (-len(payload) % 4)
        data = base64.urlsafe_b64decode(payload + pad)
        obj = json.loads(data.decode("utf-8", errors="ignore"))
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _fmt_utc_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _dt_iso(dt: Optional[datetime]) -> Optional[str]:
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

def _parse_iso_dt(s: Any) -> Optional[datetime]:
    if not isinstance(s, str) or not s.strip():
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def _risk_levels_from_arg(s: str) -> list[str]:
    levels = [x.strip().lower() for x in (s or "").split(",") if x.strip()]
    if not levels:
        return ["high", "critical"]
    for x in levels:
        if x not in RISK_LEVELS:
            raise ValueError(f"Invalid risk level '{x}'. Valid values: {', '.join(RISK_LEVELS)}")
    return levels


def _max_risk_level(levels: dict[str, list[str]]) -> Optional[str]:
    best: Optional[str] = None
    best_order = -1
    for lvl, perms in levels.items():
        if not perms:
            continue
        o = RISK_ORDER.get(lvl, -1)
        if o > best_order:
            best_order = o
            best = lvl
    return best


def _as_dict(obj: Any) -> Any:
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "as_dict"):
        try:
            return obj.as_dict()
        except Exception:
            pass
    # Last resort: best-effort public attrs.
    if hasattr(obj, "__dict__"):
        return dict(obj.__dict__)
    return obj


def _extract_role_permission_patterns(role_def_dict: dict[str, Any]) -> dict[str, Any]:
    perms = role_def_dict.get("permissions") or []
    actions: list[str] = []
    data_actions: list[str] = []
    not_actions: list[str] = []
    not_data_actions: list[str] = []

    for p in perms:
        p = _as_dict(p)
        if not isinstance(p, dict):
            continue
        actions += [x for x in (p.get("actions") or []) if isinstance(x, str)]
        data_actions += [x for x in (p.get("data_actions") or p.get("dataActions") or []) if isinstance(x, str)]
        not_actions += [x for x in (p.get("not_actions") or p.get("notActions") or []) if isinstance(x, str)]
        not_data_actions += [x for x in (p.get("not_data_actions") or p.get("notDataActions") or []) if isinstance(x, str)]

    patterns = sorted({x.strip() for x in actions + data_actions if isinstance(x, str) and x.strip()})
    return {
        "patterns": patterns,
        "not_actions": sorted({x.strip() for x in not_actions if isinstance(x, str) and x.strip()}),
        "not_data_actions": sorted({x.strip() for x in not_data_actions if isinstance(x, str) and x.strip()}),
    }


def _classify_patterns(patterns: list[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {k: [] for k in RISK_LEVELS}
    for p in patterns:
        if not isinstance(p, str):
            continue
        p = p.strip()
        if not p:
            continue
        lvl = classify_permission("azure", p, unknown_default="high")
        out[lvl].append(p)
    for k in out:
        out[k] = sorted(set(out[k]))
    return out


def _flagged_only(perms_by_level: dict[str, list[str]], flagged_levels: set[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for lvl in RISK_LEVELS:
        if lvl in flagged_levels and perms_by_level.get(lvl):
            out[lvl] = perms_by_level[lvl]
    return out


def _build_credential(args) -> Any:
    # Avoid `AzureCliCredential` to ensure we don't shell out to the `az` CLI.
    auth_method = (getattr(args, "auth_method", None) or "auto").strip().lower()
    if auth_method not in ("auto", "client-secret", "device-code", "az-cache"):
        raise ValueError("Invalid --auth-method. Use one of: auto, client-secret, device-code, az-cache")

    if getattr(args, "arm_token", None):
        return StaticTokenCredential(arm_token=args.arm_token, graph_token=getattr(args, "graph_token", None))

    if args.client_id and args.tenant_id and args.client_secret:
        return ClientSecretCredential(tenant_id=args.tenant_id, client_id=args.client_id, client_secret=args.client_secret)

    env_tid = os.getenv("AZURE_TENANT_ID")
    env_cid = os.getenv("AZURE_CLIENT_ID")
    env_sec = os.getenv("AZURE_CLIENT_SECRET")
    if auth_method in ("auto", "client-secret") and env_tid and env_cid and env_sec:
        return ClientSecretCredential(tenant_id=env_tid, client_id=env_cid, client_secret=env_sec)

    if auth_method in ("auto", "az-cache") and not args.no_az_token_cache:
        try:
            return AzureMsalTokenCacheCredential()
        except Exception:
            if auth_method == "az-cache":
                raise

    if auth_method == "client-secret":
        raise ValueError("client-secret auth selected but missing --tenant-id/--client-id/--client-secret (or env vars).")

    if auth_method == "az-cache":
        raise ValueError("az-cache auth selected but no Azure CLI token cache was usable. Run `az login` or use another auth method.")

    tenant_id = args.tenant_id or os.getenv("AZURE_TENANT_ID") or "organizations"
    client_id = args.device_client_id or AZURE_PUBLIC_CLIENT_ID

    def prompt_callback(dc):
        msg = dc.get("message") if isinstance(dc, dict) else None
        if msg:
            print(msg)

    return DeviceCodeCredential(tenant_id=tenant_id, client_id=client_id, prompt_callback=prompt_callback)


def _graph_lookup(
    *,
    credential: Any,
    object_id: str,
    cache: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    if object_id in cache:
        return cache[object_id]

    token = credential.get_token("https://graph.microsoft.com/.default").token

    def get_json(url: str, select: str) -> dict[str, Any]:
        r = requests.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            params={"$select": select},
            timeout=30,
        )
        if r.status_code == 404:
            return {}
        if r.status_code >= 400:
            raise RuntimeError(f"Graph lookup failed ({r.status_code}): {r.text[:200]}")
        data = r.json()
        return data if isinstance(data, dict) else {}

    # Prefer typed endpoints to get UPN/mail/appId fields reliably.
    # `signInActivity` is not always available in v1.0 (tenant/SKU/permissions dependent). Try v1.0 first, then beta.
    data = get_json(
        f"https://graph.microsoft.com/v1.0/users/{object_id}",
        "id,displayName,userPrincipalName,mail,userType,creationType,externalUserState,signInActivity",
    )
    if data and "signInActivity" not in data:
        try:
            data_beta = get_json(
                f"https://graph.microsoft.com/beta/users/{object_id}",
                "id,displayName,userPrincipalName,mail,userType,creationType,externalUserState,signInActivity",
            )
            if data_beta:
                data = data_beta
        except Exception:
            pass
    if not data:
        data = get_json(
            f"https://graph.microsoft.com/v1.0/servicePrincipals/{object_id}",
            "id,displayName,appId,servicePrincipalType,servicePrincipalNames",
        )
    if not data:
        data = get_json(f"https://graph.microsoft.com/v1.0/groups/{object_id}", "id,displayName,mail")
    if not data:
        data = get_json(
            f"https://graph.microsoft.com/v1.0/directoryObjects/{object_id}",
            "id,displayName,@odata.type",
        )
    out = {
        "id": data.get("id"),
        "display_name": data.get("displayName"),
        "user_principal_name": data.get("userPrincipalName"),
        "mail": data.get("mail"),
        "app_id": data.get("appId"),
        "service_principal_type": data.get("servicePrincipalType"),
        "user_type": data.get("userType"),
        "creation_type": data.get("creationType"),
        "external_user_state": data.get("externalUserState"),
        "odata_type": data.get("@odata.type"),
    }
    sign_in = data.get("signInActivity")
    if isinstance(sign_in, dict):
        last_sign_in = _parse_iso_dt(sign_in.get("lastSignInDateTime"))
        last_non_interactive = _parse_iso_dt(sign_in.get("lastNonInteractiveSignInDateTime"))
        out["last_sign_in_at"] = _dt_iso(last_sign_in)
        out["last_non_interactive_sign_in_at"] = _dt_iso(last_non_interactive)
        best = None
        for dt in (last_sign_in, last_non_interactive):
            if dt and (best is None or dt > best):
                best = dt
        out["last_any_sign_in_at"] = _dt_iso(best)
    cache[object_id] = out
    return out


def _graph_list_guest_users(
    *,
    credential: Any,
    max_items: int,
) -> tuple[list[dict[str, Any]], Optional[str]]:
    """
    Best-effort listing of guest users in Entra ID (tenant-wide).
    Requires Graph permissions (often `User.Read.All` or broader).
    """
    token = credential.get_token("https://graph.microsoft.com/.default").token
    url = "https://graph.microsoft.com/v1.0/users"
    params = {
        "$filter": "userType eq 'Guest'",
        "$select": "id,displayName,userPrincipalName,mail,userType,creationType,externalUserState",
        "$top": "999",
    }

    out: list[dict[str, Any]] = []
    while url and len(out) < max_items:
        r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, params=params, timeout=30)
        params = None  # nextLink includes query
        if r.status_code >= 400:
            return [], f"Graph guest users list failed ({r.status_code}): {r.text[:200]}"
        data = r.json() or {}
        values = data.get("value") or []
        if isinstance(values, list):
            for u in values:
                if not isinstance(u, dict):
                    continue
                out.append(
                    {
                        "id": u.get("id"),
                        "display_name": u.get("displayName"),
                        "user_principal_name": u.get("userPrincipalName"),
                        "mail": u.get("mail"),
                        "user_type": u.get("userType"),
                        "creation_type": u.get("creationType"),
                        "external_user_state": u.get("externalUserState"),
                    }
                )
                if len(out) >= max_items:
                    break
        url = data.get("@odata.nextLink")

    return out, None


def _mi_federated_identity_credentials(
    *,
    credential: Any,
    subscription_id: str,
    max_items: int,
) -> tuple[list[dict[str, Any]], Optional[str]]:
    """
    Best-effort listing of federated identity credentials for user-assigned managed identities.
    Uses ARM resource list filtered by resource type.
    """
    rm = ResourceManagementClient(credential, subscription_id)
    out: list[dict[str, Any]] = []
    try:
        it = rm.resources.list(filter="resourceType eq 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials'")
        for r in it:
            if len(out) >= max_items:
                break
            d = _as_dict(r)
            if not isinstance(d, dict):
                continue
            props = d.get("properties") or {}
            if not isinstance(props, dict):
                props = {}
            out.append(
                {
                    "id": d.get("id"),
                    "name": d.get("name"),
                    "type": d.get("type"),
                    "location": d.get("location"),
                    "issuer": props.get("issuer"),
                    "subject": props.get("subject"),
                    "audiences": props.get("audiences"),
                }
            )
        return out, None
    except Exception as e:
        return [], str(e)


def _arm_get(
    *,
    credential: Any,
    url: str,
    params: Optional[dict[str, str]] = None,
) -> dict[str, Any]:
    token = credential.get_token("https://management.azure.com/.default").token
    r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, params=params or {}, timeout=60)
    if r.status_code >= 400:
        raise RuntimeError(f"ARM GET failed ({r.status_code}) {url}: {r.text[:200]}")
    data = r.json()
    if not isinstance(data, dict):
        raise RuntimeError("Unexpected ARM response (not JSON object)")
    return data


def _list_management_groups(credential: Any, *, max_items: int) -> list[dict[str, Any]]:
    url = "https://management.azure.com/providers/Microsoft.Management/managementGroups"
    params = {"api-version": MGMT_API_VERSION}
    out: list[dict[str, Any]] = []
    while url and len(out) < max_items:
        data = _arm_get(credential=credential, url=url, params=params)
        params = None
        vals = data.get("value") or []
        if isinstance(vals, list):
            for mg in vals:
                if isinstance(mg, dict):
                    out.append(mg)
                    if len(out) >= max_items:
                        break
        url = data.get("nextLink")
    return out


def _list_mg_custom_role_definitions(
    credential: Any,
    *,
    management_group_id: str,
    max_items: int,
) -> list[dict[str, Any]]:
    mg_id = management_group_id.strip()
    if not mg_id:
        return []
    url = f"https://management.azure.com/providers/Microsoft.Management/managementGroups/{mg_id}/providers/Microsoft.Authorization/roleDefinitions"
    params = {"api-version": AUTHZ_API_VERSION, "$filter": "type eq 'CustomRole'"}
    out: list[dict[str, Any]] = []
    while url and len(out) < max_items:
        data = _arm_get(credential=credential, url=url, params=params)
        params = None
        vals = data.get("value") or []
        if isinstance(vals, list):
            for rd in vals:
                if isinstance(rd, dict):
                    out.append(rd)
                    if len(out) >= max_items:
                        break
        url = data.get("nextLink")
    return out

def _activity_event_oid(ev: dict[str, Any]) -> Optional[str]:
    # Activity Log event schema: `claims` contains oid in most cases.
    claims = ev.get("claims")
    if isinstance(claims, dict):
        return (
            claims.get("http://schemas.microsoft.com/identity/claims/objectidentifier")
            or claims.get("oid")
            or claims.get("objectidentifier")
        )
    return None


def _activity_event_op(ev: dict[str, Any]) -> Optional[str]:
    op = ev.get("operation_name") or ev.get("operationName")
    op = _as_dict(op)
    if isinstance(op, dict):
        return op.get("value") or op.get("localized_value") or op.get("localizedValue")
    if isinstance(op, str):
        return op
    return None


def _activity_event_ts(ev: dict[str, Any]) -> Optional[datetime]:
    ts = ev.get("event_timestamp") or ev.get("eventTimestamp")
    if isinstance(ts, datetime):
        return ts
    if isinstance(ts, str) and ts.strip():
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            return None
    return None


def _is_guid(s: str) -> bool:
    if not s or not isinstance(s, str):
        return False
    s = s.strip()
    if len(s) != 36:
        return False
    # 8-4-4-4-12
    parts = s.split("-")
    if len(parts) != 5:
        return False
    lens = [8, 4, 4, 4, 12]
    for p, l in zip(parts, lens):
        if len(p) != l:
            return False
    hexchars = set("0123456789abcdefABCDEF")
    return all(c in hexchars for c in s.replace("-", ""))


def _principal_best_label(principal_type: Optional[str], principal_id: str, principal_info: Optional[dict[str, Any]]) -> str:
    ptype = (principal_type or "unknown").strip()
    info = principal_info or {}
    ident = (
        info.get("user_principal_name")
        or info.get("mail")
        or info.get("app_id")
        or info.get("display_name")
        or principal_id
    )
    disp = info.get("display_name")
    if disp and ident and disp != ident:
        return f"{ptype}:{ident} ({disp})"
    return f"{ptype}:{ident}"


@dataclass
class SubscriptionScanResult:
    subscription_id: str
    subscription_name: Optional[str]
    principals: list[dict]
    inactive_principals: list[dict]
    unused_custom_roles: list[dict]
    external_rbac_principals: list[dict]
    managed_identity_federated_credentials: list[dict]
    guest_users: list[dict]
    errors: list[dict]
    stats: dict


@dataclass
class ManagementGroupScanResult:
    management_groups_scanned: int
    unused_custom_roles: list[dict]
    errors: list[dict]


def scan_subscription(
    *,
    credential: Any,
    subscription_id: str,
    subscription_name: Optional[str],
    flagged_levels: set[str],
    min_unused_days: int,
    max_items: int,
    resolve_principals: bool,
    activity_max_events: int,
    skip_activity_logs: bool,
    scan_entra: bool,
    scan_mi_federation: bool,
    max_entra_items: int,
    current_identity: Optional[dict[str, Any]] = None,
    stage_cb: Optional[Callable[[str], None]] = None,
) -> SubscriptionScanResult:
    errors: list[dict] = []
    stage_cb = stage_cb or (lambda _: None)

    def fail(where: str, e: Exception) -> None:
        errors.append({"where": where, "error": str(e)})

    scope = f"/subscriptions/{subscription_id}"
    authz = AuthorizationManagementClient(credential, subscription_id)
    rm = ResourceManagementClient(credential, subscription_id)

    stage_cb("role_assignments")
    assignments: list[dict[str, Any]] = []
    try:
        # List all role assignments in the subscription (includes nested scopes).
        # Some tenants reject `atScopeAndBelow()` filters, so prefer subscription-wide listing.
        it = authz.role_assignments.list()
        for a in it:
            assignments.append(_as_dict(a))
    except Exception as e:
        # Fallback: subscription scope only.
        try:
            it = authz.role_assignments.list_for_scope(scope, filter="atScope()")
            for a in it:
                assignments.append(_as_dict(a))
        except Exception as e2:
            fail("role_assignments_list", e)
            fail("role_assignments_list_for_scope", e2)

    by_principal: dict[str, list[dict[str, Any]]] = defaultdict(list)
    role_def_ids: set[str] = set()
    external_rbac_principals: list[dict[str, Any]] = []
    for a in assignments:
        if not isinstance(a, dict):
            continue
        pid = a.get("principal_id") or a.get("principalId")
        if not isinstance(pid, str) or not pid.strip():
            continue
        pid = pid.strip()
        by_principal[pid].append(a)

        ptype = (a.get("principal_type") or a.get("principalType") or "").strip()
        if ptype and ptype.lower().startswith("foreign"):
            external_rbac_principals.append(
                {
                    "principal_id": pid,
                    "principal_type": ptype,
                    "scope": a.get("scope"),
                    "role_definition_id": a.get("role_definition_id") or a.get("roleDefinitionId"),
                    "role_definition_name": a.get("role_definition_name") or a.get("roleDefinitionName"),
                    "assignment_id": a.get("id"),
                    "reason": "foreign_principal_type",
                }
            )

        rdid = a.get("role_definition_id") or a.get("roleDefinitionId")
        if isinstance(rdid, str) and rdid.strip():
            role_def_ids.add(rdid.strip())

    stage_cb("role_definitions")
    role_defs_by_full_id: dict[str, dict[str, Any]] = {}

    def fetch_role_def(full_id: str) -> tuple[str, Optional[dict[str, Any]], Optional[str]]:
        try:
            role_guid = full_id.rsplit("/", 1)[-1]
            rd = authz.role_definitions.get(scope, role_guid)
            return full_id, _as_dict(rd), None
        except Exception as e:
            return full_id, None, str(e)

    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = {ex.submit(fetch_role_def, rid): rid for rid in sorted(role_def_ids)}
        for fut in as_completed(futs):
            rid, rd, err = fut.result()
            if err:
                fail("role_definitions_get", RuntimeError(f"{rid}: {err}"))
                continue
            if rd:
                role_defs_by_full_id[rid] = rd

    principal_cache: dict[str, dict[str, Any]] = {}
    if resolve_principals:
        stage_cb("resolve_principals")
        for pid in tqdm(list(by_principal.keys()), desc="Resolving principals (Graph)", unit="principal", leave=False):
            try:
                _graph_lookup(credential=credential, object_id=pid, cache=principal_cache)
            except Exception as e:
                principal_cache[pid] = {"id": pid, "lookup_error": str(e)}

    # Build principal permission sets (patterns only).
    principal_entries: list[dict] = []
    flagged_exact_ops_union: set[str] = set()
    principal_flagged_exact_ops: dict[str, set[str]] = defaultdict(set)

    for pid, plist in by_principal.items():
        principal_type = (plist[0].get("principal_type") or plist[0].get("principalType") or None) if plist else None

        roles: list[dict] = []
        patterns: list[str] = []
        not_actions_union: set[str] = set()
        not_data_actions_union: set[str] = set()
        role_pattern_map: dict[str, list[str]] = {}
        role_label_map: dict[str, str] = {}

        for a in plist:
            rdid = a.get("role_definition_id") or a.get("roleDefinitionId")
            role_name = a.get("role_definition_name") or a.get("roleDefinitionName")
            a_scope = a.get("scope")
            roles.append(
                {
                    "role_definition_id": rdid,
                    "role_definition_name": role_name,
                    "scope": a_scope,
                    "assignment_id": a.get("id"),
                }
            )
            if isinstance(rdid, str) and rdid in role_defs_by_full_id:
                rp = _extract_role_permission_patterns(role_defs_by_full_id[rdid])
                patterns += rp["patterns"]
                not_actions_union.update(rp["not_actions"])
                not_data_actions_union.update(rp["not_data_actions"])
                role_pattern_map[rdid] = rp["patterns"]
                role_label = role_name or rdid
                if a_scope:
                    role_label = f"{role_label} @ {a_scope}"
                role_label_map[rdid] = role_label

        patterns = sorted(set(x for x in patterns if isinstance(x, str) and x.strip()))
        perms_by_level = _classify_patterns(patterns)
        flagged = _flagged_only(perms_by_level, flagged_levels)
        perm_sources: dict[str, dict[str, list[str]]] = {}
        if flagged:
            perm_to_level = {}
            for lvl, plist2 in flagged.items():
                for perm in plist2:
                    perm_to_level[perm] = lvl
            for rdid, rpatterns in role_pattern_map.items():
                rpattern_set = set(rpatterns)
                for perm, lvl in perm_to_level.items():
                    if perm in rpattern_set:
                        role_label = role_label_map.get(rdid) or rdid
                        perm_sources.setdefault(lvl, {}).setdefault(perm, []).append(role_label)
            for lvl in list(perm_sources.keys()):
                for perm in list(perm_sources[lvl].keys()):
                    perm_sources[lvl][perm] = sorted(set(perm_sources[lvl][perm]))

        # Only exact operations can be correlated to activity logs.
        for lvl, ops in flagged.items():
            for op in ops:
                if "*" in op:
                    continue
                principal_flagged_exact_ops[pid].add(op)
                flagged_exact_ops_union.add(op)

        entry: dict[str, Any] = {
            "principal_id": pid,
            "principal_type": principal_type,
            "roles": roles,
            "permission_patterns_by_risk": perms_by_level,
            "flagged_permission_patterns_by_risk": flagged,
            "flagged_perm_sources": perm_sources,
            "not_actions": sorted(not_actions_union),
            "not_data_actions": sorted(not_data_actions_union),
        }
        if resolve_principals:
            entry["principal"] = principal_cache.get(pid)
            entry["principal_label"] = _principal_best_label(principal_type, pid, principal_cache.get(pid))
        else:
            entry["principal_label"] = f"{principal_type or 'unknown'}:{pid}"
        principal_entries.append(entry)

    # Activity logs: best-effort "inactive principals" + best-effort last-used for exact ops.
    last_seen_by_oid: dict[str, datetime] = {}
    last_used_op_by_oid: dict[str, dict[str, datetime]] = defaultdict(dict)
    last_seen_by_caller: dict[str, datetime] = {}
    last_used_op_by_caller: dict[str, dict[str, datetime]] = defaultdict(dict)

    stage_cb("activity_logs")
    if not skip_activity_logs:
        mon = MonitorManagementClient(credential, subscription_id)
        start = datetime.now(timezone.utc) - timedelta(days=min_unused_days)
        end = datetime.now(timezone.utc)
        # OData filter string for Activity Logs. Use `...Z` form; some tenants are picky about offsets.
        filter_str = f"eventTimestamp ge '{_fmt_utc_z(start)}' and eventTimestamp le '{_fmt_utc_z(end)}'"
        try:
            count = 0
            for ev in mon.activity_logs.list(filter=filter_str):
                count += 1
                if count > activity_max_events:
                    break
                d = _as_dict(ev)
                if not isinstance(d, dict):
                    continue
                ts = _activity_event_ts(d)
                if not ts:
                    continue

                oid = _activity_event_oid(d)
                caller = d.get("caller")
                if isinstance(caller, str) and caller.strip():
                    c = caller.strip()
                    prevc = last_seen_by_caller.get(c.lower())
                    if prevc is None or ts > prevc:
                        last_seen_by_caller[c.lower()] = ts
                    if not oid and _is_guid(c):
                        oid = c

                if oid:
                    prev = last_seen_by_oid.get(oid)
                    if prev is None or ts > prev:
                        last_seen_by_oid[oid] = ts

                op = _activity_event_op(d)
                if not op or "*" in op or op not in flagged_exact_ops_union:
                    continue
                if oid:
                    prev2 = last_used_op_by_oid[oid].get(op)
                    if prev2 is None or ts > prev2:
                        last_used_op_by_oid[oid][op] = ts
                if isinstance(caller, str) and caller.strip():
                    c = caller.strip().lower()
                    prev3 = last_used_op_by_caller[c].get(op)
                    if prev3 is None or ts > prev3:
                        last_used_op_by_caller[c][op] = ts
        except HttpResponseError as e:
            fail("activity_logs_list", e)
        except Exception as e:
            fail("activity_logs_list", e)
        activity_events_seen = count
    else:
        activity_events_seen = 0

    inactive_principals: list[dict] = []
    if not skip_activity_logs:
        # If the subscription has zero events in the queried window, do NOT label everything as inactive.
        # This happens with insufficient permissions or subscriptions with no activity.
        if activity_events_seen == 0:
            fail(
                "activity_logs_inactive_suppressed",
                RuntimeError("Activity Logs returned 0 events for the time window; inactive principal detection suppressed."),
            )
        else:
            for p in principal_entries:
                pid = p["principal_id"]
                ptype = (p.get("principal_type") or "").strip().lower()
                if ptype not in ("user", "serviceprincipal"):
                    continue
                # Never mark the currently authenticated identity as inactive (it is actively running this tool).
                if current_identity and isinstance(current_identity.get("oid"), str) and pid == current_identity.get("oid"):
                    p["last_seen_at"] = _dt_iso(datetime.now(timezone.utc))
                    continue
                last_seen = last_seen_by_oid.get(pid)
                principal_info = p.get("principal") if resolve_principals else None

                # Entra sign-in activity (users only): if sign-in is within the window, treat as active.
                # This is tenant-wide and does not guarantee the user used this subscription, but it is a more reliable
                # "is this identity active at all" signal than Activity Logs.
                if ptype == "user" and isinstance(principal_info, dict):
                    any_signin = _parse_iso_dt(principal_info.get("last_any_sign_in_at"))
                    if any_signin:
                        # If within window, consider active and update last_seen.
                        if any_signin >= (datetime.now(timezone.utc) - timedelta(days=min_unused_days)):
                            if last_seen is None or any_signin > last_seen:
                                last_seen = any_signin
                            p["entra_last_any_sign_in_at"] = _dt_iso(any_signin)
                        else:
                            p["entra_last_any_sign_in_at"] = _dt_iso(any_signin)
                if not last_seen and resolve_principals:
                    info = p.get("principal") or {}
                    candidates = []
                    for k in ("user_principal_name", "mail", "app_id"):
                        v = info.get(k)
                        if isinstance(v, str) and v.strip():
                            candidates.append(v.strip().lower())
                    for c in candidates:
                        ts = last_seen_by_caller.get(c)
                        if ts and (last_seen is None or ts > last_seen):
                            last_seen = ts

                if not last_seen:
                    inactive_principals.append(
                        {
                            "principal_id": pid,
                            "principal_type": p.get("principal_type"),
                            "principal_label": _principal_best_label(p.get("principal_type"), pid, principal_info),
                            "reason": f"No Activity Log events in the last {min_unused_days} days (best-effort).",
                            "entra_last_any_sign_in_at": (principal_info or {}).get("last_any_sign_in_at") if isinstance(principal_info, dict) else None,
                        }
                    )
                p["last_seen_at"] = _dt_iso(last_seen)

                ops_used = dict(last_used_op_by_oid.get(pid) or {})
                if resolve_principals:
                    info = p.get("principal") or {}
                    candidates = []
                    for k in ("user_principal_name", "mail", "app_id"):
                        v = info.get(k)
                        if isinstance(v, str) and v.strip():
                            candidates.append(v.strip().lower())
                    for c in candidates:
                        for op, ts in (last_used_op_by_caller.get(c) or {}).items():
                            prev = ops_used.get(op)
                            if prev is None or ts > prev:
                                ops_used[op] = ts
                if ops_used:
                    p["flagged_permissions_last_used_at"] = {k: _dt_iso(v) for k, v in sorted(ops_used.items())}

    stage_cb("custom_roles")
    unused_custom_roles: list[dict] = []
    try:
        assigned_role_def_full_ids = {x.lower() for x in role_def_ids}
        # Custom roles can be defined at subscription scope or at resource group scopes.
        custom_role_defs: dict[str, dict[str, Any]] = {}

        def add_role_defs(role_defs_iter) -> None:
            for rd in role_defs_iter:
                rdd = _as_dict(rd)
                if not isinstance(rdd, dict):
                    continue
                rid = (rdd.get("id") or "").strip()
                if not rid:
                    continue
                custom_role_defs[rid.lower()] = rdd

        add_role_defs(authz.role_definitions.list(scope, filter="type eq 'CustomRole'"))

        # Resource groups in this subscription: list custom roles at each RG scope as well.
        rg_scopes: list[str] = []
        try:
            for rg in rm.resource_groups.list():
                rgd = _as_dict(rg)
                rg_name = (rgd.get("name") or "").strip()
                if rg_name:
                    rg_scopes.append(f"{scope}/resourceGroups/{rg_name}")
        except Exception as e:
            fail("resource_groups_list", e)

        def fetch_rg_custom_roles(rg_scope: str) -> tuple[str, Optional[list[Any]], Optional[str]]:
            try:
                items = list(authz.role_definitions.list(rg_scope, filter="type eq 'CustomRole'"))
                return rg_scope, items, None
            except Exception as e:
                return rg_scope, None, str(e)

        if rg_scopes:
            with ThreadPoolExecutor(max_workers=8) as ex:
                futs = {ex.submit(fetch_rg_custom_roles, s): s for s in rg_scopes}
                for fut in as_completed(futs):
                    rg_scope, items, err = fut.result()
                    if err:
                        fail("role_definitions_list_custom_rg", RuntimeError(f"{rg_scope}: {err}"))
                        continue
                    if items:
                        add_role_defs(items)

        for rdd in custom_role_defs.values():
            rid = (rdd.get("id") or "").strip()
            if not rid:
                continue
            if rid.lower() in assigned_role_def_full_ids:
                continue
            rp = _extract_role_permission_patterns(rdd)
            perms_by_level = _classify_patterns(rp["patterns"])
            unused_custom_roles.append(
                {
                    "role_definition_id": rid,
                    "role_name": rdd.get("role_name") or rdd.get("roleName"),
                    "description": rdd.get("description"),
                    "assignable_scopes": rdd.get("assignable_scopes") or rdd.get("assignableScopes"),
                    "permission_patterns_by_risk": perms_by_level,
                    "flagged_permission_patterns_by_risk": _flagged_only(perms_by_level, flagged_levels),
                }
            )
    except Exception as e:
        fail("role_definitions_list_custom", e)

    principal_entries = sorted(
        principal_entries,
        key=lambda x: (
            -RISK_ORDER.get(_max_risk_level(x.get("flagged_permission_patterns_by_risk") or {}) or "low", 0),
            x.get("principal_type") or "",
            x.get("principal_id") or "",
        ),
    )
    unused_custom_roles = sorted(unused_custom_roles, key=lambda r: r.get("role_name") or r.get("role_definition_id") or "")

    stats = {
        "subscription_id": subscription_id,
        "subscription_name": subscription_name,
        "total_role_assignments": len(assignments),
        "total_principals": len(principal_entries),
        "principals_with_flagged_permissions": sum(1 for p in principal_entries if p.get("flagged_permission_patterns_by_risk")),
        "inactive_principals": len(inactive_principals),
        "unused_custom_roles": len(unused_custom_roles),
        "scanned_at": _utc_now_iso(),
        "activity_log_max_events": activity_max_events,
        "activity_log_best_effort": not skip_activity_logs,
        "activity_log_events_seen": activity_events_seen,
        "min_unused_days": min_unused_days,
        "max_items_stdout": max_items,
    }

    # Sanity check: is the currently authenticated identity "active" in this subscription?
    if current_identity and not skip_activity_logs and activity_events_seen:
        oid = current_identity.get("oid")
        upn = (current_identity.get("upn") or "").strip().lower()
        active = False
        if isinstance(oid, str) and oid and oid in last_seen_by_oid:
            active = True
        if upn and upn in last_seen_by_caller:
            active = True
        stats["current_identity"] = {k: current_identity.get(k) for k in ("oid", "upn", "tid")}
        stats["current_identity_active_best_effort"] = active
        stats["current_identity_always_considered_active"] = True

    guest_users: list[dict] = []
    mi_fics: list[dict] = []

    stage_cb("entra_external")
    if scan_entra:
        try:
            guest_users, err = _graph_list_guest_users(credential=credential, max_items=max_entra_items)
            if err:
                fail("graph_guest_users_list", RuntimeError(err))
        except Exception as e:
            fail("graph_guest_users_list", e)

        # Annotate guests with RBAC access in this subscription (by object id).
        principals_with_access = set(by_principal.keys())
        for u in guest_users:
            oid = u.get("id")
            if isinstance(oid, str) and oid in principals_with_access:
                u["has_rbac_access_in_subscription"] = True
            else:
                u["has_rbac_access_in_subscription"] = False

    stage_cb("mi_federation")
    if scan_mi_federation:
        try:
            mi_fics, err = _mi_federated_identity_credentials(
                credential=credential, subscription_id=subscription_id, max_items=max_entra_items
            )
            if err:
                fail("mi_federated_identity_credentials_list", RuntimeError(err))
        except Exception as e:
            fail("mi_federated_identity_credentials_list", e)

    stage_cb("render")
    return SubscriptionScanResult(
        subscription_id=subscription_id,
        subscription_name=subscription_name,
        principals=principal_entries,
        inactive_principals=inactive_principals,
        unused_custom_roles=unused_custom_roles,
        external_rbac_principals=sorted(
            external_rbac_principals, key=lambda x: (x.get("principal_type") or "", x.get("principal_id") or "")
        ),
        managed_identity_federated_credentials=mi_fics,
        guest_users=guest_users,
        errors=errors,
        stats=stats,
    )


def _print_section(title: str) -> None:
    print(colored(title, "yellow", attrs=["bold"]) + ":")


def _print_permissions(flagged_perms_by_risk: dict[str, list[str]], *, max_items: int) -> None:
    """Match Blue-AWSPEAS permission styling."""
    risk_colors = {
        "critical": "red",
        "high": "yellow",
        "medium": "blue",
        "low": "cyan",
    }
    for risk_level in ["critical", "high", "medium", "low"]:
        perms = (flagged_perms_by_risk or {}).get(risk_level) or []
        if not perms:
            continue
        more_than_str = " and more..." if len(perms) > max_items else ""
        color = risk_colors.get(risk_level, "white")
        print(
            f"    - {colored(risk_level.upper(), color)}: {', '.join(f'`{p}`' for p in perms[:max_items])}{more_than_str}"
        )


def _print_kv(key: str, value: str) -> None:
    print(f"{colored(key + ':', 'white')} {value}")


def _print_subscription_stdout(res: SubscriptionScanResult, *, flagged_levels: set[str], max_items: int) -> None:
    sub_id = colored(res.subscription_id, "yellow")
    sub_name = colored(res.subscription_name or "unknown", "blue")
    print(f"Interesting permissions in {sub_id} ({sub_name}): ")

    if res.errors:
        print(colored("Errors (best-effort):", "red", attrs=["bold"]))
        for e in res.errors[:max_items]:
            print(f"  - {e.get('where')}: {e.get('error')}")
        if len(res.errors) > max_items:
            print(f"  ... ({len(res.errors) - max_items} more)")
        print()

    _print_kv("Total principals", str(res.stats.get("total_principals", 0)))
    _print_kv("Principals w/ flagged permissions", str(res.stats.get("principals_with_flagged_permissions", 0)))
    _print_kv("Inactive principals (best-effort)", str(res.stats.get("inactive_principals", 0)))
    _print_kv("Unused custom roles", str(res.stats.get("unused_custom_roles", 0)))
    print()

    flagged = [p for p in res.principals if p.get("flagged_permission_patterns_by_risk")]
    if flagged:
        _print_section("Principals with flagged permissions")
        for p in flagged[:max_items]:
            label = p.get("principal_label") or f"{p.get('principal_type') or 'unknown'}:{p.get('principal_id')}"
            print(f"  - `{label}`")
            last_seen = p.get("last_seen_at")
            if last_seen:
                print(f"    - last_seen: {last_seen}")
            _print_permissions(p.get("flagged_permission_patterns_by_risk") or {}, max_items=max_items)
            print()
        if len(flagged) > max_items:
            print(f"  - and {len(flagged) - max_items} more...")
            print()

    if res.inactive_principals:
        _print_section("Inactive principals (best-effort)")
        for p in res.inactive_principals[:max_items]:
            label = p.get("principal_label") or f"{p.get('principal_type')}:{p.get('principal_id')}"
            print(f"  - `{label}`: {p.get('reason')}")
        if len(res.inactive_principals) > max_items:
            print(f"  - and {len(res.inactive_principals) - max_items} more...")
        print()

    if res.unused_custom_roles:
        _print_section("Unused custom roles")
        for r in res.unused_custom_roles[:max_items]:
            name = r.get("role_name") or r.get("role_definition_id")
            print(f"  - `{name}`")
            flagged_r = r.get("flagged_permission_patterns_by_risk") or {}
            if flagged_r:
                _print_permissions(flagged_r, max_items=max_items)
            else:
                print("    - (No flagged permissions)")
            print()
        if len(res.unused_custom_roles) > max_items:
            print(f"  - and {len(res.unused_custom_roles) - max_items} more...")
            print()

    if res.external_rbac_principals:
        _print_section("External trusts (RBAC foreign principals)")
        for t in res.external_rbac_principals[:max_items]:
            role = t.get("role_definition_name") or t.get("role_definition_id") or "unknown_role"
            scope = t.get("scope") or "unknown_scope"
            print(f"  - `{t.get('principal_type')}:{t.get('principal_id')}` -> `{role}` scope=`{scope}`")
        if len(res.external_rbac_principals) > max_items:
            print(f"  - and {len(res.external_rbac_principals) - max_items} more...")
        print()

    if res.managed_identity_federated_credentials:
        _print_section("Managed identities trusting external identity providers (OIDC)")
        for fic in res.managed_identity_federated_credentials[:max_items]:
            name = fic.get("name") or fic.get("id") or "unknown"
            issuer = fic.get("issuer") or "unknown_issuer"
            subject = fic.get("subject") or "unknown_subject"
            print(f"  - `{name}` issuer=`{issuer}` subject=`{subject}`")
        if len(res.managed_identity_federated_credentials) > max_items:
            print(f"  - and {len(res.managed_identity_federated_credentials) - max_items} more...")
        print()

    if res.guest_users:
        _print_section("Guest users (Entra ID)")
        for u in res.guest_users[:max_items]:
            upn = u.get("user_principal_name") or u.get("mail") or u.get("id") or "unknown"
            access = " RBAC_ACCESS" if u.get("has_rbac_access_in_subscription") else ""
            print(f"  - `{upn}`{access}")
        if len(res.guest_users) > max_items:
            print(f"  - and {len(res.guest_users) - max_items} more...")
        print()


def _print_mg_stdout(res: ManagementGroupScanResult, *, max_items: int) -> None:
    if not res.unused_custom_roles and not res.errors:
        return
    _print_section("Unused custom roles in management groups")
    if res.errors:
        for e in res.errors[:max_items]:
            print(f"  - ERROR: {e.get('where')}: {e.get('error')}")
        if len(res.errors) > max_items:
            print(f"  - and {len(res.errors) - max_items} more errors...")
        print()

    if not res.unused_custom_roles:
        print("  - (none)")
        print()
        return

    for r in res.unused_custom_roles[:max_items]:
        name = r.get("role_name") or r.get("role_definition_id") or "unknown"
        print(f"  - `{name}` scope=`{r.get('scope') or 'unknown'}`")
        flagged = r.get("flagged_permission_patterns_by_risk") or {}
        if flagged:
            _print_permissions(flagged, max_items=max_items)
        else:
            print("    - (No flagged permissions)")
        print()
    if len(res.unused_custom_roles) > max_items:
        print(f"  - and {len(res.unused_custom_roles) - max_items} more...")
        print()


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Find Azure RBAC risky permissions and inactive principals (best-effort). Uses Azure SDKs, not the `az` CLI."
    )
    scope = ap.add_mutually_exclusive_group(required=True)
    scope.add_argument("--subscription", action="append", help="Subscription ID or name to analyze (repeatable).")
    scope.add_argument("--all-subscriptions", action="store_true", help="Enumerate and analyze all accessible subscriptions.")

    ap.add_argument("--risk-levels", default="high,critical", help="Comma-separated list of risk levels to flag (low,medium,high,critical). Default: high,critical")
    ap.add_argument("--min-unused-days", type=int, default=90, help="Days without observed Activity Log events to consider inactive (default: 90).")
    ap.add_argument("--max-items", type=int, default=20, help="Max findings to print per section (default: 20).")
    ap.add_argument("--activity-max-events", type=int, default=20000, help="Max Activity Log events to fetch per subscription (default: 20000).")
    ap.add_argument("--skip-activity-logs", action="store_true", help="Skip Activity Log scan (disables inactive and last-used heuristics).")
    ap.set_defaults(resolve_principals=True)
    ap.add_argument(
        "--no-resolve-principals",
        dest="resolve_principals",
        action="store_false",
        help="Disable Microsoft Graph principal resolution.",
    )
    ap.add_argument("--scan-entra", action="store_true", default=True, help="Scan Entra ID for guest users (best-effort; default: enabled).")
    ap.add_argument("--no-scan-entra", dest="scan_entra", action="store_false", help="Disable Entra ID guest user scan.")
    ap.add_argument(
        "--scan-mi-federation",
        action="store_true",
        default=True,
        help="Scan subscription for managed identity federated credentials (best-effort; default: enabled).",
    )
    ap.add_argument("--no-scan-mi-federation", dest="scan_mi_federation", action="store_false", help="Disable MI federated-credential scan.")
    ap.add_argument("--max-entra-items", type=int, default=2000, help="Cap results for Entra/MI scans (default: 2000).")
    ap.add_argument(
        "--scan-management-groups",
        action="store_true",
        default=True,
        help="When using --all-subscriptions, also scan management groups for unused custom roles (best-effort; default: enabled).",
    )
    ap.add_argument("--no-scan-management-groups", dest="scan_management_groups", action="store_false", help="Disable management group scan.")
    ap.add_argument("--max-parallel-subscriptions", type=int, default=10, help="Max subscriptions to analyze in parallel (default: 10).")

    # Auth (no az CLI).
    ap.add_argument(
        "--auth-method",
        default="auto",
        help="Authentication method: auto, client-secret, device-code, az-cache (default: auto).",
    )
    ap.add_argument("--tenant-id", help="Tenant ID (required for client-secret auth; optional for device-code).")
    ap.add_argument("--client-id", help="Service principal (app) client ID for client-secret auth.")
    ap.add_argument("--client-secret", help="Service principal client secret for client-secret auth.")
    ap.add_argument("--arm-token", help="Azure Resource Manager access token (Bearer). If provided, bypasses other auth methods.")
    ap.add_argument("--graph-token", help="Microsoft Graph access token (Bearer). Used for principal resolution when --arm-token is provided.")
    ap.add_argument("--device-client-id", help="Public client ID for device-code auth (default: Azure CLI public app id).")
    ap.add_argument(
        "--no-az-token-cache",
        action="store_true",
        help="Do not read tokens from ~/.azure/msal_token_cache.json; force device-code/client-secret auth.",
    )

    ap.add_argument("--out-json", help="Write full JSON results to this path (stdout stays human-readable).")
    args = ap.parse_args()

    try:
        flagged_levels = set(_risk_levels_from_arg(args.risk_levels))
    except Exception as e:
        print(f"{colored('[-] ', 'red')}Error: {e}")
        sys.exit(2)

    try:
        credential = _build_credential(args)
        # Force an early token acquisition to fail fast.
        mgmt_token = credential.get_token("https://management.azure.com/.default").token
        mgmt_claims = _jwt_claims(mgmt_token)
        current_identity = {
            "oid": mgmt_claims.get("oid") or mgmt_claims.get("http://schemas.microsoft.com/identity/claims/objectidentifier"),
            "upn": mgmt_claims.get("upn") or mgmt_claims.get("preferred_username"),
            "tid": mgmt_claims.get("tid"),
        }
    except Exception as e:
        print(f"{colored('[-] ', 'red')}Azure authentication failed: {e}")
        sys.exit(1)

    sub_client = SubscriptionClient(credential)
    try:
        subs = list(sub_client.subscriptions.list())
    except Exception as e:
        print(f"{colored('[-] ', 'red')}Failed to list subscriptions: {e}")
        sys.exit(1)

    # Resolve subscriptions.
    resolved: list[tuple[str, Optional[str]]] = []
    if args.all_subscriptions:
        for s in subs:
            d = _as_dict(s)
            sid = (d.get("subscription_id") or d.get("subscriptionId") or d.get("id") or "").strip()
            name = d.get("display_name") or d.get("displayName") or d.get("name")
            if sid:
                resolved.append((sid, name))
    else:
        requested = [x.strip() for x in (args.subscription or []) if isinstance(x, str) and x.strip()]
        by_id: dict[str, dict[str, Any]] = {}
        by_name: dict[str, dict[str, Any]] = {}
        for s in subs:
            d = _as_dict(s)
            sid = (d.get("subscription_id") or d.get("subscriptionId") or d.get("id") or "").strip()
            name = (d.get("display_name") or d.get("displayName") or d.get("name") or "").strip()
            if sid:
                by_id[sid.lower()] = d
            if name:
                by_name[name.lower()] = d

        for req in requested:
            d = by_id.get(req.lower()) or by_name.get(req.lower())
            if not d:
                print(f"{colored('[-] ', 'red')}Subscription '{req}' not found in accessible subscriptions.")
                continue
            sid = (d.get("subscription_id") or d.get("subscriptionId") or d.get("id") or "").strip()
            name = d.get("display_name") or d.get("displayName") or d.get("name")
            if sid:
                resolved.append((sid, name))

    # De-dup while preserving order.
    seen: set[str] = set()
    subscriptions: list[tuple[str, Optional[str]]] = []
    for sid, name in resolved:
        if sid in seen:
            continue
        seen.add(sid)
        subscriptions.append((sid, name))

    if not subscriptions:
        print(f"{colored('[-] ', 'red')}No subscriptions to analyze.")
        sys.exit(1)

    stages = [
        "role_assignments",
        "role_definitions",
        "resolve_principals",
        "activity_logs",
        "custom_roles",
        "entra_external",
        "mi_federation",
        "render",
    ]
    sp = StageProgress(total=len(subscriptions), desc="Analyzing subscriptions", unit="subscription", tqdm_factory=tqdm, stages=stages)

    all_results: list[SubscriptionScanResult] = []
    all_errors: list[dict] = []

    def worker(task_id: int, sid: str, name: Optional[str]) -> Optional[SubscriptionScanResult]:
        cb = sp.make_callback(task_id)
        try:
            return scan_subscription(
                credential=credential,
                subscription_id=sid,
                subscription_name=name,
                flagged_levels=flagged_levels,
                min_unused_days=args.min_unused_days,
                max_items=args.max_items,
                resolve_principals=args.resolve_principals,
                activity_max_events=args.activity_max_events,
                skip_activity_logs=args.skip_activity_logs,
                scan_entra=args.scan_entra,
                scan_mi_federation=args.scan_mi_federation,
                max_entra_items=args.max_entra_items,
                current_identity=current_identity,
                stage_cb=cb,
            )
        except Exception as e:
            all_errors.append({"subscription_id": sid, "error": str(e)})
            return None
        finally:
            sp.finish(task_id)

    with ThreadPoolExecutor(max_workers=min(args.max_parallel_subscriptions, len(subscriptions))) as ex:
        futs = []
        for i, (sid, name) in enumerate(subscriptions):
            futs.append(ex.submit(worker, i, sid, name))
        for fut in as_completed(futs):
            r = fut.result()
            if r:
                all_results.append(r)

    sp.close()

    all_results.sort(key=lambda r: (r.subscription_name or "", r.subscription_id))
    for r in all_results:
        _print_subscription_stdout(r, flagged_levels=flagged_levels, max_items=args.max_items)

    # Management groups custom roles (only when scanning all subscriptions).
    mg_result: Optional[ManagementGroupScanResult] = None
    if args.all_subscriptions and args.scan_management_groups:
        mg_errors: list[dict] = []
        try:
            mgs = _list_management_groups(credential, max_items=args.max_entra_items)
        except Exception as e:
            mg_errors.append({"where": "management_groups_list", "error": str(e)})
            mgs = []

        assigned_role_def_ids_all: set[str] = set()
        for r in all_results:
            for p in r.principals:
                for role in p.get("roles") or []:
                    rid = role.get("role_definition_id")
                    if isinstance(rid, str) and rid.strip():
                        assigned_role_def_ids_all.add(rid.strip().lower())

        mg_custom_defs: dict[str, dict[str, Any]] = {}

        def scan_one_mg(mg: dict[str, Any]) -> tuple[str, Optional[list[dict[str, Any]]], Optional[str]]:
            mg_id = (mg.get("name") or mg.get("id") or "").strip()
            # mg name is the identifier
            mg_name = (mg.get("name") or "").strip()
            if not mg_name:
                return mg_id or "unknown", [], None
            try:
                defs = _list_mg_custom_role_definitions(credential, management_group_id=mg_name, max_items=args.max_entra_items)
                return mg_name, defs, None
            except Exception as e:
                return mg_name, None, str(e)

        with ThreadPoolExecutor(max_workers=min(8, max(1, len(mgs)))) as ex:
            futs = {ex.submit(scan_one_mg, mg): mg for mg in mgs}
            for fut in as_completed(futs):
                mg_name, defs, err = fut.result()
                if err:
                    mg_errors.append({"where": "management_group_role_definitions", "error": f"{mg_name}: {err}"})
                    continue
                if not defs:
                    continue
                for rd in defs:
                    if not isinstance(rd, dict):
                        continue
                    rid = (rd.get("id") or "").strip()
                    if not rid:
                        continue
                    # Keep the scope for display.
                    rd["_mg_scope"] = mg_name
                    mg_custom_defs[rid.lower()] = rd

        unused_mg_custom_roles: list[dict] = []
        for rd in mg_custom_defs.values():
            rid = (rd.get("id") or "").strip()
            if not rid or rid.lower() in assigned_role_def_ids_all:
                continue
            props = rd.get("properties") or {}
            if not isinstance(props, dict):
                props = {}
            rp = _extract_role_permission_patterns(props)
            perms_by_level = _classify_patterns(rp["patterns"])
            unused_mg_custom_roles.append(
                {
                    "role_definition_id": rid,
                    "role_name": props.get("roleName") or props.get("role_name") or rd.get("name"),
                    "scope": rd.get("_mg_scope"),
                    "permission_patterns_by_risk": perms_by_level,
                    "flagged_permission_patterns_by_risk": _flagged_only(perms_by_level, flagged_levels),
                }
            )
        unused_mg_custom_roles.sort(key=lambda x: (x.get("scope") or "", x.get("role_name") or x.get("role_definition_id") or ""))
        mg_result = ManagementGroupScanResult(
            management_groups_scanned=len(mgs),
            unused_custom_roles=unused_mg_custom_roles,
            errors=mg_errors,
        )
        _print_mg_stdout(mg_result, max_items=args.max_items)

    if args.out_json:
        targets: list[dict] = []
        for r in all_results:
            targets.append(
                Target(
                    target_type="subscription",
                    target_id=r.subscription_id,
                    label=r.subscription_name,
                    data=normalize_azure_subscription(
                        {
                            "subscription_id": r.subscription_id,
                            "subscription_name": r.subscription_name,
                            "stats": r.stats,
                            "principals": r.principals,
                            "inactive_principals": r.inactive_principals,
                            "unused_custom_roles": r.unused_custom_roles,
                            "external_rbac_principals": r.external_rbac_principals,
                            "managed_identity_federated_credentials": r.managed_identity_federated_credentials,
                            "guest_users": r.guest_users,
                            "errors": r.errors,
                        }
                    ),
                ).to_dict()
            )

        if mg_result is not None:
            targets.append(
                Target(
                    target_type="tenant",
                    target_id="management_groups",
                    label="management_groups",
                    data=normalize_azure_management_groups(
                        {
                            "management_groups_scanned": mg_result.management_groups_scanned,
                            "unused_custom_roles": mg_result.unused_custom_roles,
                            "errors": mg_result.errors,
                        }
                    ),
                ).to_dict()
            )
        report = build_report(
            provider="azure",
            targets=targets,
            errors=all_errors or [],
            extra_summary={
                "total_subscriptions": len(subscriptions),
                "successful_subscriptions": len(all_results),
                "failed_subscriptions": len(subscriptions) - len(all_results),
            },
        )
        atomic_write_json(args.out_json, report)

    if not all_results and all_errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
