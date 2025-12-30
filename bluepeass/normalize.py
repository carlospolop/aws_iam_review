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


def _normalize_flagged_sources(flagged_sources: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    if not isinstance(flagged_sources, dict):
        return out
    for lvl in ("critical", "high", "medium", "low"):
        per_level = flagged_sources.get(lvl)
        if not isinstance(per_level, dict):
            continue
        items: list[dict[str, Any]] = []
        for perm, sources in per_level.items():
            if not isinstance(perm, str) or not perm:
                continue
            items.append({"permission": perm, "sources": sources if isinstance(sources, list) else []})
        if items:
            out[lvl] = items
    return out


def _aws_principal_entry(
    *,
    principal_type: str,
    principal_id: str,
    principal_label: Optional[str] = None,
    unused_days: Optional[int] = None,
    flagged_permissions: Optional[dict[str, Any]] = None,
    flagged_permission_sources: Optional[dict[str, Any]] = None,
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
    if flagged_permission_sources is not None:
        d["flagged_permission_sources"] = _normalize_flagged_sources(flagged_permission_sources)
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
    privileged_principals: list[dict[str, Any]] = []
    access_analyzer_enabled = raw.get("access_analyzer_enabled")
    if access_analyzer_enabled is None:
        access_analyzer_enabled = True

    permissions_by_principal: dict[str, dict[str, Any]] = {}
    for arn, data in (raw.get("unused_permissions") or {}).items():
        if not isinstance(data, dict):
            continue
        perms = data.get("permissions")
        if isinstance(perms, dict):
            permissions_by_principal[str(arn)] = perms
    for arn, perms in (raw.get("user_permissions") or {}).items():
        if isinstance(perms, dict):
            permissions_by_principal[str(arn)] = perms
    for arn, perms in (raw.get("role_permissions") or {}).items():
        if isinstance(perms, dict):
            permissions_by_principal[str(arn)] = perms

    # Unused roles
    for arn, data in (raw.get("unused_roles") or {}).items():
        if not isinstance(data, dict):
            continue
        if arn not in permissions_by_principal and isinstance(data.get("permissions"), dict):
            permissions_by_principal[str(arn)] = data.get("permissions")
        entry = _aws_principal_entry(
            principal_type="role",
            principal_id=str(arn),
            principal_label=str(arn),
            unused_days=data.get("n_days"),
            flagged_permissions=(data.get("permissions") or {}).get("flagged_perms"),
            flagged_permission_sources=(data.get("permissions") or {}).get("flagged_perm_sources"),
        )
        principals_inactive.append(entry)
        if entry.get("flagged_permissions"):
            principals_flagged.append(entry)

    # Unused user logins
    for arn, data in (raw.get("unused_logins") or {}).items():
        if not isinstance(data, dict):
            continue
        if arn not in permissions_by_principal and isinstance(data.get("permissions"), dict):
            permissions_by_principal[str(arn)] = data.get("permissions")
        entry = _aws_principal_entry(
            principal_type="user",
            principal_id=str(arn),
            principal_label=str(arn),
            unused_days=data.get("n_days"),
            flagged_permissions=(data.get("permissions") or {}).get("flagged_perms"),
            flagged_permission_sources=(data.get("permissions") or {}).get("flagged_perm_sources"),
        )
        principals_inactive.append(entry)
        if entry.get("flagged_permissions"):
            principals_flagged.append(entry)

    # Groups with flagged permissions (groups don't have "used" signal)
    for arn, data in (raw.get("unused_groups") or {}).items():
        if not isinstance(data, dict):
            continue
        if arn not in permissions_by_principal and isinstance(data.get("permissions"), dict):
            permissions_by_principal[str(arn)] = data.get("permissions")
        entry = _aws_principal_entry(
            principal_type="group",
            principal_id=str(arn),
            principal_label=str(arn),
            flagged_permissions=(data.get("permissions") or {}).get("flagged_perms"),
            flagged_permission_sources=(data.get("permissions") or {}).get("flagged_perm_sources"),
        )
        if entry.get("flagged_permissions"):
            principals_flagged.append(entry)

    # Per-principal unused permissions (Access Analyzer path)
    if access_analyzer_enabled:
        for arn, data in (raw.get("unused_permissions") or {}).items():
            if not isinstance(data, dict):
                continue
            perms = data.get("permissions") or {}
            entry = _aws_principal_entry(
                principal_type=str(data.get("type") or "principal"),
                principal_id=str(arn),
                principal_label=str(arn),
                flagged_permissions=perms.get("flagged_perms"),
                flagged_permission_sources=perms.get("flagged_perm_sources"),
                extra={"unused_permissions": perms},
            )
            principals_unused_perms.append(entry)
    else:
        for arn, data in (raw.get("unused_permissions") or {}).items():
            if not isinstance(data, dict):
                continue
            perms = data.get("permissions") or {}
            entry = _aws_principal_entry(
                principal_type=str(data.get("type") or "principal"),
                principal_id=str(arn),
                principal_label=str(arn),
                flagged_permissions=perms.get("flagged_perms"),
                flagged_permission_sources=perms.get("flagged_perm_sources"),
                extra={"principal_permissions": perms},
            )
            if entry.get("flagged_permissions"):
                privileged_principals.append(entry)

    # Keys (always reported)
    keys: list[dict[str, Any]] = []
    for user_arn, data in (raw.get("all_access_keys") or {}).items():
        if not isinstance(data, dict):
            continue
        for k in data.get("keys") or []:
            if not isinstance(k, dict):
                continue
            principal_perms = permissions_by_principal.get(str(user_arn))
            flagged = _risk_levels_present(principal_perms.get("flagged_perms") if isinstance(principal_perms, dict) else {})
            keys.append(
                {
                    "key_type": "access_key",
                    "principal_type": "user",
                    "principal_id": str(user_arn),
                    "access_key_id": k.get("access_key_id"),
                    "status": k.get("status"),
                    "unused_days": k.get("n_days"),
                    "last_used_at": k.get("last_used_date"),
                    "principal_permissions": principal_perms,
                    "flagged_permissions": flagged,
                    "flagged_permission_sources": _normalize_flagged_sources(
                        principal_perms.get("flagged_perm_sources") if isinstance(principal_perms, dict) else {}
                    ),
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
                "flagged_permission_sources": _normalize_flagged_sources(
                    perms.get("flagged_perm_sources") if isinstance(perms, dict) else {}
                ),
            }
        )

    # External trusts
    external_trusts: list[dict[str, Any]] = []
    for arn, data in (raw.get("external_trust_roles") or {}).items():
        if not isinstance(data, dict):
            continue
        role_perms = permissions_by_principal.get(str(arn))
        flagged = _risk_levels_present(role_perms.get("flagged_perms") if isinstance(role_perms, dict) else {})
        external_trusts.append(
            {
                "trust_type": "role_trust",
                "principal_id": str(arn),
                "details": data,
                "role_permissions": role_perms,
                "flagged_permissions": flagged,
                "flagged_permission_sources": _normalize_flagged_sources(
                    role_perms.get("flagged_perm_sources") if isinstance(role_perms, dict) else {}
                ),
            }
        )

    return {
        "scope": {"scope_type": "account", "scope_id": account_id, "scope_name": profile},
        "findings": {
            "principals_flagged": principals_flagged,
            "principals_inactive": principals_inactive,
            "principals_with_unused_permissions": principals_unused_perms,
            "privileged_principals": privileged_principals,
            "unused_permissions_available": bool(access_analyzer_enabled),
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
    principal_perm_map: dict[str, dict[str, Any]] = {}
    privileged_principals: list[dict[str, Any]] = []
    for p in raw.get("principal_risks") or []:
        if not isinstance(p, dict):
            continue
        member = p.get("principal") or p.get("member") or ""
        flagged_source = p.get("flagged_permissions_by_risk") or p.get("flagged_permissions") or p.get("flagged_perms") or {}
        flagged = _risk_levels_present(flagged_source)
        if flagged and member:
            principal_perm_map[str(member)] = flagged_source
        ptype, pid = _gcp_member_to_type_and_id(str(member))
        principals_flagged.append(
            {
                "principal_type": ptype,
                "principal_id": pid,
                "principal_label": str(member),
                "principal_member": member,
                "flagged_permissions": flagged,
                "flagged_permission_sources": _normalize_flagged_sources(p.get("flagged_perm_sources") or {}),
                "bindings": p.get("bindings") or [],
            }
        )
        if flagged:
            privileged_principals.append(
                {
                    "principal_type": ptype,
                    "principal_id": pid,
                    "principal_label": str(member),
                    "principal_member": member,
                    "flagged_permissions": flagged,
                    "flagged_permission_sources": _normalize_flagged_sources(p.get("flagged_perm_sources") or {}),
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
        flagged_source = principal_perm_map.get(str(member)) or {}
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
                "flagged_permissions": _risk_levels_present(flagged_source),
                "flagged_permission_sources": _normalize_flagged_sources(
                    k.get("flagged_perm_sources") or principal_perm_map.get(str(member)) or {}
                ),
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
                "flagged_permission_sources": _normalize_flagged_sources(r.get("flagged_perm_sources") or {}),
            }
        )

    # External trusts: keep normalized records but retain reason/resource.
    external_trusts: list[dict[str, Any]] = []
    for t in raw.get("external_trusts") or []:
        if not isinstance(t, dict):
            continue
        member = t.get("member") or t.get("principal") or ""
        flagged_source = principal_perm_map.get(str(member)) or {}
        external_trusts.append(
            {
                "trust_type": t.get("kind") or "external_binding",
                "principal_member": member,
                "role": t.get("role"),
                "resource": t.get("resource"),
                "reason": t.get("reason"),
                "flagged_permissions": _risk_levels_present(flagged_source),
                "flagged_permission_sources": _normalize_flagged_sources(t.get("flagged_perm_sources") or {}),
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
            "privileged_principals": privileged_principals,
            "unused_permissions_available": False,
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
    principal_perm_map: dict[str, dict[str, Any]] = {}
    privileged_principals: list[dict[str, Any]] = []
    for p in raw.get("principals") or []:
        if not isinstance(p, dict):
            continue
        flagged = p.get("flagged_permission_patterns_by_risk") or {}
        if not _risk_levels_present(flagged):
            continue
        principal = p.get("principal") or {}
        principal_display = principal.get("user_principal_name") or principal.get("mail") or principal.get("display_name")
        if p.get("principal_id"):
            principal_perm_map[str(p.get("principal_id"))] = flagged
        principals_flagged.append(
            {
                "principal_type": p.get("principal_type"),
                "principal_id": p.get("principal_id"),
                "principal_display": principal_display,
                "principal_label": f"{p.get('principal_type')}:{principal_display}" if principal_display else f"{p.get('principal_type')}:{p.get('principal_id')}",
                "flagged_permissions": _risk_levels_present(flagged),
                "flagged_permission_sources": _normalize_flagged_sources(p.get("flagged_perm_sources") or {}),
                "roles": p.get("roles") or [],
            }
        )
        privileged_principals.append(
            {
                "principal_type": p.get("principal_type"),
                "principal_id": p.get("principal_id"),
                "principal_display": principal_display,
                "principal_label": f"{p.get('principal_type')}:{principal_display}" if principal_display else f"{p.get('principal_type')}:{p.get('principal_id')}",
                "flagged_permissions": _risk_levels_present(flagged),
                "flagged_permission_sources": _normalize_flagged_sources(p.get("flagged_perm_sources") or {}),
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
                "flagged_permission_sources": _normalize_flagged_sources(r.get("flagged_perm_sources") or {}),
            }
        )

    external_trusts: list[dict[str, Any]] = []
    for t in raw.get("external_rbac_principals") or []:
        if not isinstance(t, dict):
            continue
        flagged_source = principal_perm_map.get(str(t.get("principal_id") or "")) or {}
        external_trusts.append(
            {
                "trust_type": "rbac_foreign_principal",
                "principal_type": t.get("principal_type"),
                "principal_id": t.get("principal_id"),
                "role": t.get("role_definition_name") or t.get("role_definition_id"),
                "scope": t.get("scope"),
                "reason": t.get("reason"),
                "flagged_permissions": _risk_levels_present(flagged_source),
                "flagged_permission_sources": _normalize_flagged_sources(t.get("flagged_perm_sources") or {}),
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
            "privileged_principals": privileged_principals,
            "unused_permissions_available": False,
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
