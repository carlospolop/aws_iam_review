from __future__ import annotations

from typing import Any, Optional


def _risk_levels_present(flagged: dict[str, Any]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    if not isinstance(flagged, dict):
        return out
    for lvl in ("critical", "high", "medium", "low"):
        items = flagged.get(lvl)
        if isinstance(items, list) and items:
            out[lvl] = [str(x) for x in items if isinstance(x, str) and x]
    return out


def _aws_principal_entry(
    *,
    principal_type: str,
    principal_id: str,
    principal_label: Optional[str] = None,
    unused_days: Optional[int] = None,
    flagged_permissions: Optional[dict[str, Any]] = None,
    extra: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    d: dict[str, Any] = {
        "principal_type": principal_type,
        "principal_id": principal_id,
        "principal_label": principal_label or f"{principal_type}:{principal_id}",
    }
    if unused_days is not None:
        d["unused_days"] = unused_days
    if flagged_permissions is not None:
        d["flagged_permissions"] = _risk_levels_present(flagged_permissions)
    if extra:
        d.update(extra)
    return d


def normalize_aws_account(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Normalize Blue-AWSPEAS JSON into the common schema used across providers.
    Does not drop AWS-specific fields; attaches them under `provider_raw`.
    """
    account_id = str(raw.get("account_id") or "unknown")
    profile = raw.get("profile")

    principals_flagged: list[dict[str, Any]] = []
    principals_inactive: list[dict[str, Any]] = []
    principals_unused_perms: list[dict[str, Any]] = []

    # Unused roles
    for arn, data in (raw.get("unused_roles") or {}).items():
        if not isinstance(data, dict):
            continue
        entry = _aws_principal_entry(
            principal_type="role",
            principal_id=str(arn),
            principal_label=str(arn),
            unused_days=data.get("n_days"),
            flagged_permissions=(data.get("permissions") or {}).get("flagged_perms"),
        )
        principals_inactive.append(entry)
        if entry.get("flagged_permissions"):
            principals_flagged.append(entry)

    # Unused user logins
    for arn, data in (raw.get("unused_logins") or {}).items():
        if not isinstance(data, dict):
            continue
        entry = _aws_principal_entry(
            principal_type="user",
            principal_id=str(arn),
            principal_label=str(arn),
            unused_days=data.get("n_days"),
            flagged_permissions=(data.get("permissions") or {}).get("flagged_perms"),
        )
        principals_inactive.append(entry)
        if entry.get("flagged_permissions"):
            principals_flagged.append(entry)

    # Groups with flagged permissions (groups don't have "used" signal)
    for arn, data in (raw.get("unused_groups") or {}).items():
        if not isinstance(data, dict):
            continue
        entry = _aws_principal_entry(
            principal_type="group",
            principal_id=str(arn),
            principal_label=str(arn),
            flagged_permissions=(data.get("permissions") or {}).get("flagged_perms"),
        )
        if entry.get("flagged_permissions"):
            principals_flagged.append(entry)

    # Per-principal unused permissions (Access Analyzer path)
    for arn, data in (raw.get("unused_permissions") or {}).items():
        if not isinstance(data, dict):
            continue
        entry = _aws_principal_entry(
            principal_type=str(data.get("type") or "principal"),
            principal_id=str(arn),
            principal_label=str(arn),
            extra={"unused_permissions": data.get("permissions") or []},
        )
        principals_unused_perms.append(entry)

    # Keys (always reported)
    keys: list[dict[str, Any]] = []
    for user_arn, data in (raw.get("all_access_keys") or {}).items():
        if not isinstance(data, dict):
            continue
        for k in data.get("keys") or []:
            if not isinstance(k, dict):
                continue
            keys.append(
                {
                    "key_type": "access_key",
                    "principal_type": "user",
                    "principal_id": str(user_arn),
                    "access_key_id": k.get("access_key_id"),
                    "status": k.get("status"),
                    "unused_days": k.get("n_days"),
                    "last_used_at": k.get("last_used_date"),
                }
            )

    # Unused customer-managed policies
    unused_custom_defs: list[dict[str, Any]] = []
    for arn, data in (raw.get("unused_custom_policies") or {}).items():
        if not isinstance(data, dict):
            continue
        perms = data.get("permissions") or {}
        unused_custom_defs.append(
            {
                "definition_type": "custom_policy",
                "definition_id": str(arn),
                "definition_name": data.get("policy_name"),
                "flagged_permissions": _risk_levels_present(perms.get("flagged_perms") if isinstance(perms, dict) else {}),
            }
        )

    # External trusts
    external_trusts: list[dict[str, Any]] = []
    for arn, data in (raw.get("external_trust_roles") or {}).items():
        if not isinstance(data, dict):
            continue
        external_trusts.append(
            {
                "trust_type": "role_trust",
                "principal_id": str(arn),
                "details": data,
            }
        )

    return {
        "scope": {"scope_type": "account", "scope_id": account_id, "scope_name": profile},
        "findings": {
            "principals_flagged": principals_flagged,
            "principals_inactive": principals_inactive,
            "principals_with_unused_permissions": principals_unused_perms,
            "keys": keys,
            "unused_custom_definitions": unused_custom_defs,
            "external_trusts": external_trusts,
        },
        "errors": raw.get("errors") or [],
        "provider_raw": raw,
    }


def _gcp_member_to_type_and_id(member: str) -> tuple[str, str]:
    if not isinstance(member, str) or ":" not in member:
        return "principal", str(member)
    t, ident = member.split(":", 1)
    return t, ident


def normalize_gcp_scope(raw: dict[str, Any]) -> dict[str, Any]:
    scope = str(raw.get("scope") or "")
    scope_type = str(raw.get("scope_type") or "")
    scope_id = scope
    scope_name = None
    if scope.startswith("projects/"):
        scope_id = scope.split("/", 1)[1]
        scope_name = scope_id
        scope_type = "project"
    elif scope.startswith("organizations/"):
        scope_id = scope.split("/", 1)[1]
        scope_name = scope_id
        scope_type = "organization"

    principals_flagged: list[dict[str, Any]] = []
    for p in raw.get("principal_risks") or []:
        if not isinstance(p, dict):
            continue
        member = p.get("principal") or p.get("member") or ""
        ptype, pid = _gcp_member_to_type_and_id(str(member))
        principals_flagged.append(
            {
                "principal_type": ptype,
                "principal_id": pid,
                "principal_label": str(member),
                "principal_member": member,
                "flagged_permissions": _risk_levels_present(p.get("flagged_permissions_by_risk") or p.get("flagged_permissions") or {}),
                "bindings": p.get("bindings") or [],
            }
        )

    principals_inactive: list[dict[str, Any]] = []
    for p in raw.get("inactive_principals") or []:
        if not isinstance(p, dict):
            continue
        member = p.get("principal") or p.get("member") or ""
        ptype, pid = _gcp_member_to_type_and_id(str(member))
        principals_inactive.append(
            {
                "principal_type": ptype,
                "principal_id": pid,
                "principal_label": str(member),
                "principal_member": member,
                "reason": p.get("reason"),
            }
        )

    # Keys (service account keys)
    keys: list[dict[str, Any]] = []
    for k in raw.get("service_account_keys") or []:
        if not isinstance(k, dict):
            continue
        member = k.get("service_account") or k.get("principal") or ""
        ptype, pid = _gcp_member_to_type_and_id(str(member))
        keys.append(
            {
                "key_type": "service_account_key",
                "principal_type": ptype,
                "principal_id": pid,
                "principal_member": member,
                "key_id": k.get("key"),
                "status": k.get("status"),
                "inactive": k.get("inactive"),
                "reason": k.get("reason"),
            }
        )

    # Unused custom roles
    unused_custom_defs: list[dict[str, Any]] = []
    for r in raw.get("unused_custom_roles") or []:
        if not isinstance(r, dict):
            continue
        unused_custom_defs.append(
            {
                "definition_type": "custom_role",
                "definition_id": r.get("name"),
                "definition_name": r.get("title") or r.get("name"),
                "flagged_permissions": _risk_levels_present(r.get("flagged_permissions_by_risk") or {}),
            }
        )

    # External trusts: keep normalized records but retain reason/resource.
    external_trusts: list[dict[str, Any]] = []
    for t in raw.get("external_trusts") or []:
        if not isinstance(t, dict):
            continue
        member = t.get("member") or t.get("principal") or ""
        external_trusts.append(
            {
                "trust_type": t.get("kind") or "external_binding",
                "principal_member": member,
                "role": t.get("role"),
                "resource": t.get("resource"),
                "reason": t.get("reason"),
            }
        )

    return {
        "scope": {
            "scope_type": scope_type or "scope",
            "scope_id": scope_id,
            "scope_name": scope_name,
            "scope_full_name": scope,
            "quota_project": raw.get("quota_project"),
        },
        "findings": {
            "principals_flagged": principals_flagged,
            "principals_inactive": principals_inactive,
            "principals_with_unused_permissions": [],
            "keys": keys,
            "unused_custom_definitions": unused_custom_defs,
            "external_trusts": external_trusts,
        },
        "errors": raw.get("errors") or [],
        "provider_raw": raw,
    }


def normalize_azure_subscription(raw: dict[str, Any]) -> dict[str, Any]:
    scope_id = raw.get("subscription_id") or raw.get("subscriptionId") or raw.get("id") or ""
    scope_name = raw.get("subscription_name") or raw.get("subscriptionName") or raw.get("name")

    principals_flagged: list[dict[str, Any]] = []
    for p in raw.get("principals") or []:
        if not isinstance(p, dict):
            continue
        flagged = p.get("flagged_permission_patterns_by_risk") or {}
        if not _risk_levels_present(flagged):
            continue
        principal = p.get("principal") or {}
        principal_display = principal.get("user_principal_name") or principal.get("mail") or principal.get("display_name")
        principals_flagged.append(
            {
                "principal_type": p.get("principal_type"),
                "principal_id": p.get("principal_id"),
                "principal_display": principal_display,
                "principal_label": f"{p.get('principal_type')}:{principal_display}" if principal_display else f"{p.get('principal_type')}:{p.get('principal_id')}",
                "flagged_permissions": _risk_levels_present(flagged),
                "roles": p.get("roles") or [],
            }
        )

    principals_inactive: list[dict[str, Any]] = []
    for p in raw.get("inactive_principals") or []:
        if not isinstance(p, dict):
            continue
        principals_inactive.append(
            {
                "principal_type": p.get("principal_type"),
                "principal_id": p.get("principal_id"),
                "principal_label": p.get("principal_label") or f"{p.get('principal_type')}:{p.get('principal_id')}",
                "reason": p.get("reason"),
            }
        )

    unused_custom_defs: list[dict[str, Any]] = []
    for r in raw.get("unused_custom_roles") or []:
        if not isinstance(r, dict):
            continue
        unused_custom_defs.append(
            {
                "definition_type": "custom_role",
                "definition_id": r.get("role_definition_id"),
                "definition_name": r.get("role_name") or r.get("role_definition_id"),
                "flagged_permissions": _risk_levels_present(r.get("flagged_permission_patterns_by_risk") or {}),
            }
        )

    external_trusts: list[dict[str, Any]] = []
    for t in raw.get("external_rbac_principals") or []:
        if not isinstance(t, dict):
            continue
        external_trusts.append(
            {
                "trust_type": "rbac_foreign_principal",
                "principal_type": t.get("principal_type"),
                "principal_id": t.get("principal_id"),
                "role": t.get("role_definition_name") or t.get("role_definition_id"),
                "scope": t.get("scope"),
                "reason": t.get("reason"),
            }
        )
    for fic in raw.get("managed_identity_federated_credentials") or []:
        if not isinstance(fic, dict):
            continue
        external_trusts.append(
            {
                "trust_type": "managed_identity_federated_credential",
                "principal_id": fic.get("id"),
                "name": fic.get("name"),
                "issuer": fic.get("issuer"),
                "subject": fic.get("subject"),
                "audiences": fic.get("audiences"),
            }
        )
    for u in raw.get("guest_users") or []:
        if not isinstance(u, dict):
            continue
        external_trusts.append(
            {
                "trust_type": "guest_user",
                "principal_id": u.get("id"),
                "principal_display": u.get("user_principal_name") or u.get("mail"),
                "has_rbac_access_in_scope": u.get("has_rbac_access_in_subscription"),
            }
        )

    return {
        "scope": {"scope_type": "subscription", "scope_id": scope_id, "scope_name": scope_name},
        "findings": {
            "principals_flagged": principals_flagged,
            "principals_inactive": principals_inactive,
            "principals_with_unused_permissions": [],
            "keys": [],
            "unused_custom_definitions": unused_custom_defs,
            "external_trusts": external_trusts,
        },
        "errors": raw.get("errors") or [],
        "provider_raw": raw,
    }


def normalize_azure_management_groups(raw: dict[str, Any]) -> dict[str, Any]:
    unused_custom_defs: list[dict[str, Any]] = []
    for r in raw.get("unused_custom_roles") or []:
        if not isinstance(r, dict):
            continue
        unused_custom_defs.append(
            {
                "definition_type": "custom_role",
                "definition_id": r.get("role_definition_id"),
                "definition_name": r.get("role_name") or r.get("role_definition_id"),
                "scope": r.get("scope"),
                "flagged_permissions": _risk_levels_present(r.get("flagged_permission_patterns_by_risk") or {}),
            }
        )
    return {
        "scope": {"scope_type": "tenant", "scope_id": "management_groups", "scope_name": "management_groups"},
        "findings": {
            "principals_flagged": [],
            "principals_inactive": [],
            "principals_with_unused_permissions": [],
            "keys": [],
            "unused_custom_definitions": unused_custom_defs,
            "external_trusts": [],
        },
        "errors": raw.get("errors") or [],
        "provider_raw": raw,
    }
