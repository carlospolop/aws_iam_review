# Permission Categories (Low / Medium / High / Critical)

This repository groups cloud permissions into four **risk buckets**. The goal is to make reviews, diffs, and “what changed?” decisions consistent.

These categories are **not** a statement about business impact; they are a statement about **security blast radius** if the permission is granted and misused.

## Low

**Goal:** Allow safe, non-sensitive read-only visibility.

Use **low** for permissions that:
- Are predominantly **read-only** (List/Get/Describe) and do **not** expose secrets/credentials/tokens.
- Do not materially enable privilege escalation (privesc), lateral movement, or exfiltration.

Typical examples:
- Inventory and status reads: `List*`, `Describe*`, `Get*` (when they return non-secret metadata).

## Medium

**Goal:** Capture routine operational writes that can change configuration or availability, but do not directly enable privesc or clear secret access.

Use **medium** for permissions that:
- Perform **non-sensitive writes** (Create/Update/Put/Delete/Start/Stop) whose main effect is operational (availability, dashboards, alarms, scheduling, reporting, settings).
- Do **not** directly grant new permissions or identities.
- Do **not** grant access to secrets in cleartext.
- Are not obvious “security boundary” changes (policy, role, key, credential, token, trust, broad resource sharing).

Typical examples:
- Monitoring & alerting configuration (alarms, dashboards, metric streams).
- Autoscaling and scheduling knobs.
- Cost/reporting/preferences and similar admin UX configuration.

## High

**Goal:** Flag dangerous writes and high-privilege actions that could materially enable privesc, persistence, broad access, or sensitive-data access—even if not an immediate “one-shot” admin.

Use **high** for permissions that:
- Modify **security boundaries** or access controls (common signals: policy/role/trust/permission, attaching or passing roles, key policy changes).
- Enable **meaningful escalation paths** (e.g., actions that let an attacker run code with a more privileged role, alter who can assume roles, or change encryption/access settings in a way that enables later exfiltration).
- Modify secrets/credential material (even if not directly reading it) because it can enable takeover/persistence.
- Read huge bulks of data even if not super sensitive (like download information about all the services/configurations used, all the IAM configurations...)
- Read and Write from buckets should also be considered as high.

Typical examples:
- IAM/STS mutations that affect trust, permissions, or role usage.
- Secret store writes/rotation/updates (because swapping a secret can compromise downstream systems).

## Critical

**Goal:** Reserve the top bucket for **direct privilege escalation primitives** and **direct cleartext secret/credential/token retrieval**.

Use **critical** for permissions that:
- Directly allow gaining **more permissions** / higher privilege (direct privesc), such as:
  - Creating/attaching/updating policies and roles in ways that grant additional permissions.
  - Assuming/passing roles or equivalent primitives that immediately jump privilege.
- Directly return **cleartext secrets/credentials/tokens** (immediate account or system compromise potential).

Typical examples:
- Cleartext secret/token/credential retrieval actions.
- Role assumption / role passing / policy control primitives.

## Practical decision rules

When deciding between buckets, these heuristics reflect the intended policy:
- **Cleartext secret/token/credential read → Critical**.
- **Direct privesc primitive → Critical**.
- **Secret modification (swap/overwrite) → High**.
- **Security-boundary mutation (policy/role/trust/credential/key policy) → High**.
- **Operational/config/telemetry/reporting writes that don’t change security boundaries → Medium**.
- **Read-only non-sensitive visibility → Low**.

## Notes

- Bucket assignment can be service-specific. A verb like `Put*` is not automatically high: the deciding factor is whether it changes a security boundary or exposes/changes secrets.
- These categories are designed to be applied consistently across AWS/Azure/GCP where possible, while still allowing provider-specific overrides for known sensitive actions.
