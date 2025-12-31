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


def _catalog_add(
    catalog: dict[Any, int],
    catalog_items: list[dict[str, Any]],
    key: Any,
    payload: dict[str, Any],
) -> int:
    if key in catalog:
        return catalog[key]
    idx = len(catalog_items)
    entry = {"id": idx}
    entry.update(payload)
    catalog_items.append(entry)
    catalog[key] = idx
    return idx


def _catalog_permissions(
    flagged: dict[str, Any],
    perm_catalog: dict[str, int],
    perm_items: list[dict[str, Any]],
) -> dict[str, list[int]]:
    out: dict[str, list[int]] = {}
    if not isinstance(flagged, dict):
        return out
    for lvl in ("critical", "high", "medium", "low"):
        items = flagged.get(lvl)
        if not isinstance(items, list):
            continue
        perm_ids: list[int] = []
        for perm in items:
            if not isinstance(perm, str) or not perm:
                continue
            perm_id = _catalog_add(perm_catalog, perm_items, perm, {"name": perm})
            perm_ids.append(perm_id)
        if perm_ids:
            out[lvl] = perm_ids
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


def _compact_permissions(perms: Optional[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(perms, dict):
        return {}
    out: dict[str, Any] = {}
    if isinstance(perms.get("flagged_perms"), dict):
        out["flagged_perms"] = perms.get("flagged_perms")
    if isinstance(perms.get("flagged_perm_sources"), dict):
        out["flagged_perm_sources"] = perms.get("flagged_perm_sources")
    if "is_admin" in perms:
        out["is_admin"] = perms.get("is_admin")
    all_actions = perms.get("all_actions")
    if isinstance(all_actions, list):
        out["total_actions"] = len(all_actions)
    return out


def _source_descriptor(source: Any) -> Optional[dict[str, Any]]:
    if isinstance(source, dict):
        label = source.get("policy_name") or source.get("policy_arn") or source.get("role") or source.get("attachment_name") or "source"
        stype = source.get("source_type")
        if not stype:
            if source.get("policy_name") or source.get("policy_arn"):
                stype = "policy"
            elif source.get("role"):
                stype = "role"
            else:
                stype = "source"
        return {"label": str(label), "type": str(stype)}
    if isinstance(source, str):
        return {"label": source, "type": "role"}
    return None


def _compact_flagged_sources(
    flagged_permission_sources: dict[str, Any],
    perm_catalog: dict[str, int],
    perm_items: list[dict[str, Any]],
    role_catalog: dict[tuple[str, str], int],
    role_items: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(flagged_permission_sources, dict):
        return {}
    out: dict[str, list[dict[str, Any]]] = {}
    for lvl, items in flagged_permission_sources.items():
        if not isinstance(items, list):
            continue
        perm_sources: dict[int, set[int]] = {}
        for item in items:
            if not isinstance(item, dict):
                continue
            perm = item.get("permission")
            if not isinstance(perm, str) or not perm:
                continue
            perm_id = _catalog_add(perm_catalog, perm_items, perm, {"name": perm})
            for src in item.get("sources") or []:
                desc = _source_descriptor(src)
                if not desc:
                    continue
                key = (desc["label"], desc["type"])
                role_id = _catalog_add(role_catalog, role_items, key, {"label": desc["label"], "type": desc["type"]})
                perm_sources.setdefault(perm_id, set()).add(role_id)
        if perm_sources:
            out[lvl] = [
                {"permission": perm_id, "sources": sorted(source_ids)}
                for perm_id, source_ids in perm_sources.items()
            ]
    return out


def _subject_ref(
    *,
    subject_type: Optional[str],
    subject_id: Optional[str],
    subject_label: Optional[str],
    principal_catalog: dict[tuple[str, str], int],
    principal_items: list[dict[str, Any]],
    group_catalog: dict[str, int],
    group_items: list[dict[str, Any]],
) -> tuple[int, str]:
    stype = str(subject_type or "principal")
    sid = str(subject_id or subject_label or "unknown")
    label = subject_label or sid
    if stype.lower() == "group":
        ref = _catalog_add(group_catalog, group_items, sid, {"label": label, "identifier": sid, "type": stype})
        return ref, "group"
    ref = _catalog_add(
        principal_catalog,
        principal_items,
        (stype, sid),
        {"label": label, "identifier": sid, "type": stype},
    )
    return ref, "principal"


def _aws_principal_entry(
    *,
    principal_type: str,
    principal_id: str,
    principal_label: Optional[str] = None,
    unused_days: Optional[int] = None,
    flagged_permissions: Optional[dict[str, Any]] = None,
    flagged_permission_sources: Optional[dict[str, Any]] = None,
    extra: Optional[dict[str, Any]] = None,
    perm_catalog: dict[str, int],
    perm_items: list[dict[str, Any]],
    role_catalog: dict[tuple[str, str], int],
    role_items: list[dict[str, Any]],
    principal_catalog: dict[tuple[str, str], int],
    principal_items: list[dict[str, Any]],
    group_catalog: dict[str, int],
    group_items: list[dict[str, Any]],
) -> dict[str, Any]:
    subject_ref, subject_kind = _subject_ref(
        subject_type=principal_type,
        subject_id=principal_id,
        subject_label=principal_label,
        principal_catalog=principal_catalog,
        principal_items=principal_items,
        group_catalog=group_catalog,
        group_items=group_items,
    )
    d: dict[str, Any] = {
        "subject_ref": subject_ref,
        "subject_kind": subject_kind,
    }
    if unused_days is not None:
        d["unused_days"] = unused_days
    if flagged_permissions is not None:
        d["flagged_permissions"] = _catalog_permissions(flagged_permissions, perm_catalog, perm_items)
    if flagged_permission_sources is not None:
        d["flagged_permission_sources"] = _compact_flagged_sources(
            _normalize_flagged_sources(flagged_permission_sources),
            perm_catalog,
            perm_items,
            role_catalog,
            role_items,
        )
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
    identity = raw.get("identity") or {}
    caller_arn = identity.get("arn") or identity.get("Arn")
    caller_name = identity.get("name") or identity.get("user_name") or identity.get("UserName")
    caller_email = identity.get("email") or identity.get("mail")
    caller_user_id = identity.get("user_id") or identity.get("UserId")

    perm_catalog: dict[str, int] = {}
    perm_items: list[dict[str, Any]] = []
    principal_catalog: dict[tuple[str, str], int] = {}
    principal_items: list[dict[str, Any]] = []
    group_catalog: dict[str, int] = {}
    group_items: list[dict[str, Any]] = []
    role_catalog: dict[tuple[str, str], int] = {}
    role_items: list[dict[str, Any]] = []

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
            permissions_by_principal[str(arn)] = _compact_permissions(perms)
    for arn, perms in (raw.get("user_permissions") or {}).items():
        if isinstance(perms, dict):
            permissions_by_principal[str(arn)] = _compact_permissions(perms)
    for arn, perms in (raw.get("role_permissions") or {}).items():
        if isinstance(perms, dict):
            permissions_by_principal[str(arn)] = _compact_permissions(perms)

    # Unused roles
    for arn, data in (raw.get("unused_roles") or {}).items():
        if not isinstance(data, dict):
            continue
        if arn not in permissions_by_principal and isinstance(data.get("permissions"), dict):
            permissions_by_principal[str(arn)] = _compact_permissions(data.get("permissions"))
        entry = _aws_principal_entry(
            principal_type="role",
            principal_id=str(arn),
            principal_label=str(arn),
            unused_days=data.get("n_days"),
            flagged_permissions=(data.get("permissions") or {}).get("flagged_perms"),
            flagged_permission_sources=(data.get("permissions") or {}).get("flagged_perm_sources"),
            perm_catalog=perm_catalog,
            perm_items=perm_items,
            role_catalog=role_catalog,
            role_items=role_items,
            principal_catalog=principal_catalog,
            principal_items=principal_items,
            group_catalog=group_catalog,
            group_items=group_items,
        )
        principals_inactive.append(entry)
        if entry.get("flagged_permissions"):
            principals_flagged.append(entry)

    # Unused user logins
    for arn, data in (raw.get("unused_logins") or {}).items():
        if not isinstance(data, dict):
            continue
        if arn not in permissions_by_principal and isinstance(data.get("permissions"), dict):
            permissions_by_principal[str(arn)] = _compact_permissions(data.get("permissions"))
        entry = _aws_principal_entry(
            principal_type="user",
            principal_id=str(arn),
            principal_label=str(arn),
            unused_days=data.get("n_days"),
            flagged_permissions=(data.get("permissions") or {}).get("flagged_perms"),
            flagged_permission_sources=(data.get("permissions") or {}).get("flagged_perm_sources"),
            perm_catalog=perm_catalog,
            perm_items=perm_items,
            role_catalog=role_catalog,
            role_items=role_items,
            principal_catalog=principal_catalog,
            principal_items=principal_items,
            group_catalog=group_catalog,
            group_items=group_items,
        )
        principals_inactive.append(entry)
        if entry.get("flagged_permissions"):
            principals_flagged.append(entry)

    # Groups with flagged permissions (groups don't have "used" signal)
    for arn, data in (raw.get("unused_groups") or {}).items():
        if not isinstance(data, dict):
            continue
        if arn not in permissions_by_principal and isinstance(data.get("permissions"), dict):
            permissions_by_principal[str(arn)] = _compact_permissions(data.get("permissions"))
        entry = _aws_principal_entry(
            principal_type="group",
            principal_id=str(arn),
            principal_label=str(arn),
            flagged_permissions=(data.get("permissions") or {}).get("flagged_perms"),
            flagged_permission_sources=(data.get("permissions") or {}).get("flagged_perm_sources"),
            perm_catalog=perm_catalog,
            perm_items=perm_items,
            role_catalog=role_catalog,
            role_items=role_items,
            principal_catalog=principal_catalog,
            principal_items=principal_items,
            group_catalog=group_catalog,
            group_items=group_items,
        )
        if entry.get("flagged_permissions"):
            principals_flagged.append(entry)

    # Per-principal unused permissions (Access Analyzer path)
    if access_analyzer_enabled:
        for arn, data in (raw.get("unused_permissions") or {}).items():
            if not isinstance(data, dict):
                continue
            perms = data.get("permissions") or {}
            perms = _compact_permissions(perms)
            entry = _aws_principal_entry(
                principal_type=str(data.get("type") or "principal"),
                principal_id=str(arn),
                principal_label=str(arn),
                flagged_permissions=perms.get("flagged_perms"),
                flagged_permission_sources=perms.get("flagged_perm_sources"),
                extra={"unused_permissions": perms},
                perm_catalog=perm_catalog,
                perm_items=perm_items,
                role_catalog=role_catalog,
                role_items=role_items,
                principal_catalog=principal_catalog,
                principal_items=principal_items,
                group_catalog=group_catalog,
                group_items=group_items,
            )
            principals_unused_perms.append(entry)
    else:
        for arn, data in (raw.get("unused_permissions") or {}).items():
            if not isinstance(data, dict):
                continue
            perms = data.get("permissions") or {}
            perms = _compact_permissions(perms)
            entry = _aws_principal_entry(
                principal_type=str(data.get("type") or "principal"),
                principal_id=str(arn),
                principal_label=str(arn),
                flagged_permissions=perms.get("flagged_perms"),
                flagged_permission_sources=perms.get("flagged_perm_sources"),
                extra={"principal_permissions": perms},
                perm_catalog=perm_catalog,
                perm_items=perm_items,
                role_catalog=role_catalog,
                role_items=role_items,
                principal_catalog=principal_catalog,
                principal_items=principal_items,
                group_catalog=group_catalog,
                group_items=group_items,
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
            subject_ref, subject_kind = _subject_ref(
                subject_type="user",
                subject_id=str(user_arn),
                subject_label=str(user_arn),
                principal_catalog=principal_catalog,
                principal_items=principal_items,
                group_catalog=group_catalog,
                group_items=group_items,
            )
            principal_perms = permissions_by_principal.get(str(user_arn))
            flagged = _catalog_permissions(
                principal_perms.get("flagged_perms") if isinstance(principal_perms, dict) else {},
                perm_catalog,
                perm_items,
            )
            keys.append(
                {
                    "key_type": "access_key",
                    "subject_ref": subject_ref,
                    "subject_kind": subject_kind,
                    "access_key_id": k.get("access_key_id"),
                    "status": k.get("status"),
                    "unused_days": k.get("n_days"),
                    "last_used_at": k.get("last_used_date"),
                    "flagged_permissions": flagged,
                    "flagged_permission_sources": _compact_flagged_sources(
                        _normalize_flagged_sources(principal_perms.get("flagged_perm_sources") if isinstance(principal_perms, dict) else {}),
                        perm_catalog,
                        perm_items,
                        role_catalog,
                        role_items,
                    ),
                }
            )

    # Unused customer-managed policies
    unused_custom_defs: list[dict[str, Any]] = []
    for arn, data in (raw.get("unused_custom_policies") or {}).items():
        if not isinstance(data, dict):
            continue
        perms = _compact_permissions(data.get("permissions") or {})
        role_ref = _catalog_add(
            role_catalog,
            role_items,
            (str(data.get("policy_name") or arn), "policy"),
            {"label": str(data.get("policy_name") or arn), "type": "policy", "identifier": str(arn)},
        )
        unused_custom_defs.append(
            {
                "definition_type": "custom_policy",
                "definition_ref": role_ref,
                "flagged_permissions": _catalog_permissions(
                    perms.get("flagged_perms") if isinstance(perms, dict) else {},
                    perm_catalog,
                    perm_items,
                ),
                "flagged_permission_sources": _compact_flagged_sources(
                    _normalize_flagged_sources(perms.get("flagged_perm_sources") if isinstance(perms, dict) else {}),
                    perm_catalog,
                    perm_items,
                    role_catalog,
                    role_items,
                ),
            }
        )

    # External trusts
    external_trusts: list[dict[str, Any]] = []
    for arn, data in (raw.get("external_trust_roles") or {}).items():
        if not isinstance(data, dict):
            continue
        subject_ref, subject_kind = _subject_ref(
            subject_type="role",
            subject_id=str(arn),
            subject_label=str(arn),
            principal_catalog=principal_catalog,
            principal_items=principal_items,
            group_catalog=group_catalog,
            group_items=group_items,
        )
        role_perms = permissions_by_principal.get(str(arn))
        flagged = _catalog_permissions(
            role_perms.get("flagged_perms") if isinstance(role_perms, dict) else {},
            perm_catalog,
            perm_items,
        )
        external_trusts.append(
            {
                "trust_type": "role_trust",
                "subject_ref": subject_ref,
                "subject_kind": subject_kind,
                "details": data,
                "flagged_permissions": flagged,
                "flagged_permission_sources": _compact_flagged_sources(
                    _normalize_flagged_sources(role_perms.get("flagged_perm_sources") if isinstance(role_perms, dict) else {}),
                    perm_catalog,
                    perm_items,
                    role_catalog,
                    role_items,
                ),
            }
        )

    group_memberships: list[dict[str, Any]] = []
    for m in raw.get("group_memberships") or []:
        if not isinstance(m, dict):
            continue
        group_id = m.get("group_id") or m.get("group_arn") or m.get("group") or m.get("group_name")
        if not group_id:
            continue
        group_label = m.get("group_label") or m.get("group_name") or group_id
        group_ref = _catalog_add(
            group_catalog,
            group_items,
            str(group_id),
            {"label": str(group_label), "identifier": str(group_id), "type": "group"},
        )
        member_id = m.get("member_id") or m.get("user_arn") or m.get("member") or m.get("user_name")
        if not member_id:
            continue
        member_label = m.get("member_label") or m.get("user_name") or member_id
        member_type = str(m.get("member_type") or "user")
        is_group = member_type.lower() == "group" or str(member_id).startswith("group:")
        if is_group:
            member_ref = _catalog_add(
                group_catalog,
                group_items,
                str(member_id),
                {"label": str(member_label), "identifier": str(member_id), "type": member_type},
            )
            member_kind = "group"
        else:
            member_ref = _catalog_add(
                principal_catalog,
                principal_items,
                (member_type, str(member_id)),
                {"label": str(member_label), "identifier": str(member_id), "type": member_type},
            )
            member_kind = "principal"
        group_memberships.append(
            {"group_ref": group_ref, "member_ref": member_ref, "member_kind": member_kind}
        )

    return {
        "scope": {
            "scope_type": "account",
            "scope_id": account_id,
            "scope_name": profile,
            "caller_name": caller_name,
            "caller_arn": caller_arn,
            "caller_email": caller_email,
            "caller_user_id": caller_user_id,
        },
        "findings": {
            "principals_flagged": principals_flagged,
            "principals_inactive": principals_inactive,
            "principals_with_unused_permissions": principals_unused_perms,
            "privileged_principals": privileged_principals,
            "unused_permissions_available": bool(access_analyzer_enabled),
            "keys": keys,
            "unused_custom_definitions": unused_custom_defs,
            "external_trusts": external_trusts,
            "group_memberships": group_memberships,
            "permission_catalog": perm_items,
            "principal_catalog": principal_items,
            "group_catalog": group_items,
            "role_catalog": role_items,
        },
        "errors": raw.get("errors") or [],
        "provider_raw": {},
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

    perm_catalog: dict[str, int] = {}
    perm_items: list[dict[str, Any]] = []
    principal_catalog: dict[tuple[str, str], int] = {}
    principal_items: list[dict[str, Any]] = []
    group_catalog: dict[str, int] = {}
    group_items: list[dict[str, Any]] = []
    role_catalog: dict[tuple[str, str], int] = {}
    role_items: list[dict[str, Any]] = []

    principals_flagged: list[dict[str, Any]] = []
    principal_perm_map: dict[str, dict[str, Any]] = {}
    privileged_principals: list[dict[str, Any]] = []
    for p in raw.get("principal_risks") or []:
        if not isinstance(p, dict):
            continue
        member = p.get("principal") or p.get("member") or ""
        flagged_source = p.get("flagged_permissions_by_risk") or p.get("flagged_permissions") or p.get("flagged_perms") or {}
        flagged = _catalog_permissions(flagged_source, perm_catalog, perm_items)
        if flagged and member:
            principal_perm_map[str(member)] = flagged_source
        ptype, pid = _gcp_member_to_type_and_id(str(member))
        subject_ref, subject_kind = _subject_ref(
            subject_type=ptype,
            subject_id=pid,
            subject_label=str(member),
            principal_catalog=principal_catalog,
            principal_items=principal_items,
            group_catalog=group_catalog,
            group_items=group_items,
        )
        binding_refs = []
        for role in p.get("bindings") or []:
            if not isinstance(role, str) or not role:
                continue
            role_id = _catalog_add(role_catalog, role_items, (role, "role"), {"label": role, "type": "role", "identifier": role})
            binding_refs.append(role_id)
        principals_flagged.append(
            {
                "subject_ref": subject_ref,
                "subject_kind": subject_kind,
                "flagged_permissions": flagged,
                "flagged_permission_sources": _compact_flagged_sources(
                    _normalize_flagged_sources(p.get("flagged_perm_sources") or {}),
                    perm_catalog,
                    perm_items,
                    role_catalog,
                    role_items,
                ),
                "binding_refs": binding_refs,
            }
        )
        if flagged:
            privileged_principals.append(
                {
                    "subject_ref": subject_ref,
                    "subject_kind": subject_kind,
                    "flagged_permissions": flagged,
                    "flagged_permission_sources": _compact_flagged_sources(
                        _normalize_flagged_sources(p.get("flagged_perm_sources") or {}),
                        perm_catalog,
                        perm_items,
                        role_catalog,
                        role_items,
                    ),
                    "binding_refs": binding_refs,
                }
            )

    principals_inactive: list[dict[str, Any]] = []
    for p in raw.get("inactive_principals") or []:
        if not isinstance(p, dict):
            continue
        member = p.get("principal") or p.get("member") or ""
        ptype, pid = _gcp_member_to_type_and_id(str(member))
        subject_ref, subject_kind = _subject_ref(
            subject_type=ptype,
            subject_id=pid,
            subject_label=str(member),
            principal_catalog=principal_catalog,
            principal_items=principal_items,
            group_catalog=group_catalog,
            group_items=group_items,
        )
        principals_inactive.append(
            {
                "subject_ref": subject_ref,
                "subject_kind": subject_kind,
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
        subject_ref, subject_kind = _subject_ref(
            subject_type=ptype,
            subject_id=pid,
            subject_label=str(member),
            principal_catalog=principal_catalog,
            principal_items=principal_items,
            group_catalog=group_catalog,
            group_items=group_items,
        )
        flagged_source = principal_perm_map.get(str(member)) or {}
        keys.append(
            {
                "key_type": "service_account_key",
                "subject_ref": subject_ref,
                "subject_kind": subject_kind,
                "key_id": k.get("key"),
                "status": k.get("status"),
                "inactive": k.get("inactive"),
                "reason": k.get("reason"),
                "flagged_permissions": _catalog_permissions(flagged_source, perm_catalog, perm_items),
                "flagged_permission_sources": _compact_flagged_sources(
                    _normalize_flagged_sources(k.get("flagged_perm_sources") or principal_perm_map.get(str(member)) or {}),
                    perm_catalog,
                    perm_items,
                    role_catalog,
                    role_items,
                ),
            }
        )

    # Unused custom roles
    unused_custom_defs: list[dict[str, Any]] = []
    for r in raw.get("unused_custom_roles") or []:
        if not isinstance(r, dict):
            continue
        role_label = r.get("title") or r.get("name")
        role_id = _catalog_add(
            role_catalog,
            role_items,
            (str(role_label), "custom_role"),
            {"label": str(role_label), "type": "custom_role", "identifier": str(r.get("name") or role_label)},
        )
        unused_custom_defs.append(
            {
                "definition_type": "custom_role",
                "definition_ref": role_id,
                "flagged_permissions": _catalog_permissions(r.get("flagged_permissions_by_risk") or {}, perm_catalog, perm_items),
                "flagged_permission_sources": _compact_flagged_sources(
                    _normalize_flagged_sources(r.get("flagged_perm_sources") or {}),
                    perm_catalog,
                    perm_items,
                    role_catalog,
                    role_items,
                ),
            }
        )

    # External trusts: keep normalized records but retain reason/resource.
    external_trusts: list[dict[str, Any]] = []
    for t in raw.get("external_trusts") or []:
        if not isinstance(t, dict):
            continue
        member = t.get("member") or t.get("principal") or ""
        flagged_source = principal_perm_map.get(str(member)) or {}
        ptype, pid = _gcp_member_to_type_and_id(str(member))
        subject_ref, subject_kind = _subject_ref(
            subject_type=ptype,
            subject_id=pid,
            subject_label=str(member),
            principal_catalog=principal_catalog,
            principal_items=principal_items,
            group_catalog=group_catalog,
            group_items=group_items,
        )
        role_label = t.get("role")
        role_ref = None
        if isinstance(role_label, str) and role_label:
            role_ref = _catalog_add(
                role_catalog,
                role_items,
                (role_label, "role"),
                {"label": role_label, "type": "role", "identifier": role_label},
            )
        external_trusts.append(
            {
                "trust_type": t.get("kind") or "external_binding",
                "subject_ref": subject_ref,
                "subject_kind": subject_kind,
                "role_ref": role_ref,
                "resource": t.get("resource"),
                "reason": t.get("reason"),
                "flagged_permissions": _catalog_permissions(flagged_source, perm_catalog, perm_items),
                "flagged_permission_sources": _compact_flagged_sources(
                    _normalize_flagged_sources(t.get("flagged_perm_sources") or {}),
                    perm_catalog,
                    perm_items,
                    role_catalog,
                    role_items,
                ),
            }
        )
    group_memberships: list[dict[str, Any]] = []
    for m in raw.get("group_memberships") or []:
        if not isinstance(m, dict):
            continue
        group_id = m.get("group_id") or m.get("group") or m.get("group_name")
        if not group_id:
            continue
        group_label = m.get("group_label") or m.get("group_name") or group_id
        group_ref = _catalog_add(
            group_catalog,
            group_items,
            str(group_id),
            {"label": str(group_label), "identifier": str(group_id), "type": "group"},
        )
        member_id = m.get("member_id") or m.get("member")
        if not member_id:
            continue
        member_label = m.get("member_label") or member_id
        member_type = str(m.get("member_type") or "member")
        is_group = member_type.lower() == "group" or str(member_id).startswith("group:")
        if is_group:
            member_ref = _catalog_add(
                group_catalog,
                group_items,
                str(member_id),
                {"label": str(member_label), "identifier": str(member_id), "type": member_type},
            )
            member_kind = "group"
        else:
            member_ref = _catalog_add(
                principal_catalog,
                principal_items,
                (member_type, str(member_id)),
                {"label": str(member_label), "identifier": str(member_id), "type": member_type},
            )
            member_kind = "principal"
        group_memberships.append({"group_ref": group_ref, "member_ref": member_ref, "member_kind": member_kind})

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
            "group_memberships": group_memberships,
            "permission_catalog": perm_items,
            "principal_catalog": principal_items,
            "group_catalog": group_items,
            "role_catalog": role_items,
        },
        "errors": raw.get("errors") or [],
        "provider_raw": {},
    }


def normalize_azure_subscription(raw: dict[str, Any]) -> dict[str, Any]:
    scope_id = raw.get("subscription_id") or raw.get("subscriptionId") or raw.get("id") or ""
    scope_name = raw.get("subscription_name") or raw.get("subscriptionName") or raw.get("name")
    stats = raw.get("stats") or {}
    current_identity = stats.get("current_identity") or {}
    caller_name = current_identity.get("upn") or current_identity.get("preferred_username")
    caller_email = current_identity.get("upn") or current_identity.get("preferred_username")
    caller_oid = current_identity.get("oid")

    perm_catalog: dict[str, int] = {}
    perm_items: list[dict[str, Any]] = []
    principal_catalog: dict[tuple[str, str], int] = {}
    principal_items: list[dict[str, Any]] = []
    group_catalog: dict[str, int] = {}
    group_items: list[dict[str, Any]] = []
    role_catalog: dict[tuple[str, str], int] = {}
    role_items: list[dict[str, Any]] = []

    principals_flagged: list[dict[str, Any]] = []
    principal_perm_map: dict[str, dict[str, Any]] = {}
    privileged_principals: list[dict[str, Any]] = []
    for p in raw.get("principals") or []:
        if not isinstance(p, dict):
            continue
        flagged_source = p.get("flagged_permission_patterns_by_risk") or {}
        flagged = _catalog_permissions(flagged_source, perm_catalog, perm_items)
        if not flagged:
            continue
        principal = p.get("principal") or {}
        principal_display = principal.get("user_principal_name") or principal.get("mail") or principal.get("display_name")
        if p.get("principal_id"):
            principal_perm_map[str(p.get("principal_id"))] = flagged_source
        subject_ref, subject_kind = _subject_ref(
            subject_type=p.get("principal_type"),
            subject_id=p.get("principal_id"),
            subject_label=principal_display or str(p.get("principal_id")),
            principal_catalog=principal_catalog,
            principal_items=principal_items,
            group_catalog=group_catalog,
            group_items=group_items,
        )
        role_refs = []
        for role in p.get("roles") or []:
            if not isinstance(role, str) or not role:
                continue
            role_id = _catalog_add(
                role_catalog,
                role_items,
                (role, "role"),
                {"label": role, "type": "role", "identifier": role},
            )
            role_refs.append(role_id)
        principals_flagged.append(
            {
                "subject_ref": subject_ref,
                "subject_kind": subject_kind,
                "flagged_permissions": flagged,
                "flagged_permission_sources": _compact_flagged_sources(
                    _normalize_flagged_sources(p.get("flagged_perm_sources") or {}),
                    perm_catalog,
                    perm_items,
                    role_catalog,
                    role_items,
                ),
                "role_refs": role_refs,
            }
        )
        privileged_principals.append(
            {
                "subject_ref": subject_ref,
                "subject_kind": subject_kind,
                "flagged_permissions": flagged,
                "flagged_permission_sources": _compact_flagged_sources(
                    _normalize_flagged_sources(p.get("flagged_perm_sources") or {}),
                    perm_catalog,
                    perm_items,
                    role_catalog,
                    role_items,
                ),
                "role_refs": role_refs,
            }
        )

    principals_inactive: list[dict[str, Any]] = []
    for p in raw.get("inactive_principals") or []:
        if not isinstance(p, dict):
            continue
        subject_ref, subject_kind = _subject_ref(
            subject_type=p.get("principal_type"),
            subject_id=p.get("principal_id"),
            subject_label=p.get("principal_label") or str(p.get("principal_id")),
            principal_catalog=principal_catalog,
            principal_items=principal_items,
            group_catalog=group_catalog,
            group_items=group_items,
        )
        principals_inactive.append(
            {
                "subject_ref": subject_ref,
                "subject_kind": subject_kind,
                "reason": p.get("reason"),
            }
        )

    unused_custom_defs: list[dict[str, Any]] = []
    for r in raw.get("unused_custom_roles") or []:
        if not isinstance(r, dict):
            continue
        role_label = r.get("role_name") or r.get("role_definition_id")
        role_ref = _catalog_add(
            role_catalog,
            role_items,
            (str(role_label), "custom_role"),
            {"label": str(role_label), "type": "custom_role", "identifier": str(r.get("role_definition_id") or role_label)},
        )
        unused_custom_defs.append(
            {
                "definition_type": "custom_role",
                "definition_ref": role_ref,
                "flagged_permissions": _catalog_permissions(
                    r.get("flagged_permission_patterns_by_risk") or {}, perm_catalog, perm_items
                ),
                "flagged_permission_sources": _compact_flagged_sources(
                    _normalize_flagged_sources(r.get("flagged_perm_sources") or {}),
                    perm_catalog,
                    perm_items,
                    role_catalog,
                    role_items,
                ),
            }
        )

    external_trusts: list[dict[str, Any]] = []
    for t in raw.get("external_rbac_principals") or []:
        if not isinstance(t, dict):
            continue
        flagged_source = principal_perm_map.get(str(t.get("principal_id") or "")) or {}
        subject_ref, subject_kind = _subject_ref(
            subject_type=t.get("principal_type"),
            subject_id=t.get("principal_id"),
            subject_label=str(t.get("principal_id")),
            principal_catalog=principal_catalog,
            principal_items=principal_items,
            group_catalog=group_catalog,
            group_items=group_items,
        )
        role_label = t.get("role_definition_name") or t.get("role_definition_id")
        role_ref = None
        if isinstance(role_label, str) and role_label:
            role_ref = _catalog_add(
                role_catalog,
                role_items,
                (role_label, "role"),
                {"label": role_label, "type": "role", "identifier": role_label},
            )
        external_trusts.append(
            {
                "trust_type": "rbac_foreign_principal",
                "subject_ref": subject_ref,
                "subject_kind": subject_kind,
                "role_ref": role_ref,
                "scope": t.get("scope"),
                "reason": t.get("reason"),
                "flagged_permissions": _catalog_permissions(flagged_source, perm_catalog, perm_items),
                "flagged_permission_sources": _compact_flagged_sources(
                    _normalize_flagged_sources(t.get("flagged_perm_sources") or {}),
                    perm_catalog,
                    perm_items,
                    role_catalog,
                    role_items,
                ),
            }
        )
    for fic in raw.get("managed_identity_federated_credentials") or []:
        if not isinstance(fic, dict):
            continue
        subject_ref, subject_kind = _subject_ref(
            subject_type="federated_credential",
            subject_id=fic.get("id"),
            subject_label=fic.get("name") or fic.get("id"),
            principal_catalog=principal_catalog,
            principal_items=principal_items,
            group_catalog=group_catalog,
            group_items=group_items,
        )
        role_ref = None
        if fic.get("name"):
            role_ref = _catalog_add(
                role_catalog,
                role_items,
                (str(fic.get("name")), "federated_credential"),
                {"label": str(fic.get("name")), "type": "federated_credential", "identifier": str(fic.get("id") or fic.get("name"))},
            )
        external_trusts.append(
            {
                "trust_type": "managed_identity_federated_credential",
                "subject_ref": subject_ref,
                "subject_kind": subject_kind,
                "name": fic.get("name"),
                "issuer": fic.get("issuer"),
                "subject": fic.get("subject"),
                "audiences": fic.get("audiences"),
                "role_ref": role_ref,
            }
        )
    for u in raw.get("guest_users") or []:
        if not isinstance(u, dict):
            continue
        subject_ref, subject_kind = _subject_ref(
            subject_type="Guest",
            subject_id=u.get("id"),
            subject_label=u.get("user_principal_name") or u.get("mail"),
            principal_catalog=principal_catalog,
            principal_items=principal_items,
            group_catalog=group_catalog,
            group_items=group_items,
        )
        external_trusts.append(
            {
                "trust_type": "guest_user",
                "subject_ref": subject_ref,
                "subject_kind": subject_kind,
                "has_rbac_access_in_scope": u.get("has_rbac_access_in_subscription"),
            }
        )
    group_memberships: list[dict[str, Any]] = []
    for m in raw.get("group_memberships") or []:
        if not isinstance(m, dict):
            continue
        group_id = m.get("group_id") or m.get("group") or m.get("group_name")
        if not group_id:
            continue
        group_label = m.get("group_label") or m.get("group_name") or group_id
        group_ref = _catalog_add(
            group_catalog,
            group_items,
            str(group_id),
            {"label": str(group_label), "identifier": str(group_id), "type": "group"},
        )
        member_id = m.get("member_id") or m.get("member")
        if not member_id:
            continue
        member_label = m.get("member_label") or member_id
        member_type = str(m.get("member_type") or "member")
        is_group = member_type.lower() == "group"
        if is_group:
            member_ref = _catalog_add(
                group_catalog,
                group_items,
                str(member_id),
                {"label": str(member_label), "identifier": str(member_id), "type": member_type},
            )
            member_kind = "group"
        else:
            member_ref = _catalog_add(
                principal_catalog,
                principal_items,
                (member_type, str(member_id)),
                {"label": str(member_label), "identifier": str(member_id), "type": member_type},
            )
            member_kind = "principal"
        group_memberships.append({"group_ref": group_ref, "member_ref": member_ref, "member_kind": member_kind})

    return {
        "scope": {
            "scope_type": "subscription",
            "scope_id": scope_id,
            "scope_name": scope_name,
            "caller_name": caller_name,
            "caller_email": caller_email,
            "caller_user_id": caller_oid,
        },
        "findings": {
            "principals_flagged": principals_flagged,
            "principals_inactive": principals_inactive,
            "principals_with_unused_permissions": [],
            "privileged_principals": privileged_principals,
            "unused_permissions_available": False,
            "keys": [],
            "unused_custom_definitions": unused_custom_defs,
            "external_trusts": external_trusts,
            "group_memberships": group_memberships,
            "permission_catalog": perm_items,
            "principal_catalog": principal_items,
            "group_catalog": group_items,
            "role_catalog": role_items,
        },
        "errors": raw.get("errors") or [],
        "provider_raw": {},
    }


def normalize_azure_management_groups(raw: dict[str, Any]) -> dict[str, Any]:
    perm_catalog: dict[str, int] = {}
    perm_items: list[dict[str, Any]] = []
    role_catalog: dict[tuple[str, str], int] = {}
    role_items: list[dict[str, Any]] = []
    unused_custom_defs: list[dict[str, Any]] = []
    for r in raw.get("unused_custom_roles") or []:
        if not isinstance(r, dict):
            continue
        role_label = r.get("role_name") or r.get("role_definition_id")
        role_ref = _catalog_add(
            role_catalog,
            role_items,
            (str(role_label), "custom_role"),
            {"label": str(role_label), "type": "custom_role", "identifier": str(r.get("role_definition_id") or role_label)},
        )
        unused_custom_defs.append(
            {
                "definition_type": "custom_role",
                "definition_ref": role_ref,
                "scope": r.get("scope"),
                "flagged_permissions": _catalog_permissions(
                    r.get("flagged_permission_patterns_by_risk") or {}, perm_catalog, perm_items
                ),
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
            "permission_catalog": perm_items,
            "principal_catalog": [],
            "group_catalog": [],
            "role_catalog": role_items,
        },
        "errors": raw.get("errors") or [],
        "provider_raw": {},
    }
