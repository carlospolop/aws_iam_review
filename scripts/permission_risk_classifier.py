from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Iterable, Optional

import yaml


RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _split_perm_list_entry(entry: str) -> list[str]:
    return [token.strip() for token in entry.split(",") if token.strip()]


@dataclass(frozen=True)
class HintSets:
    sensitive: set[str]
    privesc: set[str]
    sensitive_lower: set[str]
    privesc_lower: set[str]


def load_hint_sets_aws(path: str = "sensitive_permissions.yaml") -> HintSets:
    if not os.path.exists(path):
        return HintSets(sensitive=set(), privesc=set(), sensitive_lower=set(), privesc_lower=set())

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    sensitive: set[str] = set()
    privesc: set[str] = set()
    if not isinstance(data, dict):
        return HintSets(
            sensitive=sensitive,
            privesc=privesc,
            sensitive_lower={p.lower() for p in sensitive},
            privesc_lower={p.lower() for p in privesc},
        )

    for _, service_data in data.items():
        if not isinstance(service_data, dict):
            continue
        for key, dest in (
            ("sensitive", sensitive),
            ("privesc", privesc),
            ("pivesc", privesc),  # typo in source file
        ):
            values = service_data.get(key)
            if not values:
                continue
            if isinstance(values, str):
                values = [values]
            if not isinstance(values, list):
                continue
            for entry in values:
                if not isinstance(entry, str):
                    continue
                perms = _split_perm_list_entry(entry)
                # `privesc` entries often represent multi-permission chains separated by commas.
                # Only promote to "privesc single-permission hint" when it's exactly one action.
                if key in ("privesc", "pivesc") and len(perms) != 1:
                    continue
                for perm in perms:
                    dest.add(perm)

    return HintSets(
        sensitive=sensitive,
        privesc=privesc,
        sensitive_lower={p.lower() for p in sensitive},
        privesc_lower={p.lower() for p in privesc},
    )


def load_hint_sets_gcp(path: str = "gcp_sensitive_permissions.yaml") -> HintSets:
    if not os.path.exists(path):
        return HintSets(sensitive=set(), privesc=set(), sensitive_lower=set(), privesc_lower=set())

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    sensitive: set[str] = set()
    privesc: set[str] = set()
    if not isinstance(data, dict):
        return HintSets(
            sensitive=sensitive,
            privesc=privesc,
            sensitive_lower={p.lower() for p in sensitive},
            privesc_lower={p.lower() for p in privesc},
        )

    for _, service_data in data.items():
        if not isinstance(service_data, dict):
            continue
        for key, dest in (("sensitive", sensitive), ("privesc", privesc)):
            values = service_data.get(key)
            if not values:
                continue
            if isinstance(values, str):
                values = [values]
            if not isinstance(values, list):
                continue
            for entry in values:
                if not isinstance(entry, str):
                    continue
                perms = _split_perm_list_entry(entry)
                if key == "privesc" and len(perms) != 1:
                    continue
                for perm in perms:
                    dest.add(perm)

    return HintSets(
        sensitive=sensitive,
        privesc=privesc,
        sensitive_lower={p.lower() for p in sensitive},
        privesc_lower={p.lower() for p in privesc},
    )


def load_hint_sets_azure(path: str = "azure_sensitive_permissions.yaml") -> HintSets:
    if not os.path.exists(path):
        return HintSets(sensitive=set(), privesc=set(), sensitive_lower=set(), privesc_lower=set())

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    sensitive: set[str] = set()
    privesc: set[str] = set()
    if not isinstance(data, dict):
        return HintSets(
            sensitive=sensitive,
            privesc=privesc,
            sensitive_lower={p.lower() for p in sensitive},
            privesc_lower={p.lower() for p in privesc},
        )

    for _, service_data in data.items():
        if not isinstance(service_data, dict):
            continue
        for key, dest in (("sensitive", sensitive), ("privesc", privesc), ("pivesc", privesc)):
            values = service_data.get(key)
            if not values:
                continue
            if isinstance(values, str):
                values = [values]
            if not isinstance(values, list):
                continue
            for entry in values:
                if not isinstance(entry, str):
                    continue
                for perm in _split_perm_list_entry(entry):
                    dest.add(perm)

    return HintSets(
        sensitive=sensitive,
        privesc=privesc,
        sensitive_lower={p.lower() for p in sensitive},
        privesc_lower={p.lower() for p in privesc},
    )


def load_aws_permissions_from_managed_policies(path: str) -> set[str]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    policies = data.get("policies", [])
    if not isinstance(policies, list):
        raise ValueError("Unexpected AWS dataset format: expected top-level key 'policies' list")

    permissions: set[str] = set()
    for policy in policies:
        if not isinstance(policy, dict):
            continue
        actions = policy.get("effective_action_names", [])
        if not isinstance(actions, list):
            continue
        for action in actions:
            if isinstance(action, str) and action.strip():
                permissions.add(action.strip())

    return permissions


def load_gcp_permissions_from_sorted(path: str) -> set[str]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict):
        return {k.strip() for k in data.keys() if isinstance(k, str) and k.strip()}
    if isinstance(data, list):
        return {x.strip() for x in data if isinstance(x, str) and x.strip()}
    raise ValueError("Unexpected GCP dataset format: expected dict or list")


def load_azure_permissions_from_provider_operations(path: str) -> set[str]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Dataset format: a list of provider objects. The granular permissions are in the nested
    # `operations` arrays (each element has a `name` like `Microsoft.X/.../read|write|delete|action`).
    permissions: set[str] = set()

    def extract_from_operations_list(ops) -> None:
        if not isinstance(ops, list):
            return
        for op in ops:
            if not isinstance(op, dict):
                continue
            name = op.get("name")
            if isinstance(name, str) and name.strip() and "/" in name:
                permissions.add(name.strip())

    if not isinstance(data, list):
        raise ValueError("Unexpected Azure dataset format: expected a top-level list")

    for provider in data:
        if not isinstance(provider, dict):
            continue
        extract_from_operations_list(provider.get("operations"))
        for rt in provider.get("resourceTypes", []) or []:
            if not isinstance(rt, dict):
                continue
            extract_from_operations_list(rt.get("operations"))

    return permissions


_AWS_CRITICAL_EXACT = {
    # Identity/permission escalation primitives.
    "iam:PassRole",
    # Execute-as-role primitives (common privesc vectors).
    "ssm:SendCommand",
    "ssm:StartSession",
    "ssm:ResumeSession",
    "ssm:TerminateSession",
    "ecs:ExecuteCommand",
    "lambda:UpdateFunctionCode",
    "lambda:UpdateFunctionConfiguration",
    "sagemaker:CreatePresignedNotebookInstanceUrl",
    # Instance-profile attachment (execute as instance role).
    "ec2:AssociateIamInstanceProfile",
    "ec2:ReplaceIamInstanceProfileAssociation",
    # Resource policy that can directly grant broad access (explicitly treated as critical by request).
    "s3:PutBucketPolicy",
    # Explicit escalation-by-secret access (requested).
    "secretsmanager:GetSecretValue",
}

_AWS_SENSITIVE_READ_SERVICES = {
    "secretsmanager",
    "ssm",
    "kms",
    "s3",
    "ecr",
    "codecommit",
    "codestar-connections",
}

_AWS_S3_DATA_READ_VERBS = {
    "GetObject",
    "GetObjectAcl",
    "GetObjectAttributes",
    "GetObjectTagging",
    "GetObjectVersion",
    "GetObjectVersionAcl",
    "GetObjectVersionAttributes",
    "GetObjectVersionTagging",
    "ListBucket",
    "ListBucketMultipartUploads",
    "ListBucketVersions",
    "ListMultipartUploadParts",
    "ListObjects",
    "ListObjectsV2",
}

_AWS_S3_DATA_WRITE_VERBS = {
    "PutObject",
    "PutObjectAcl",
    "PutObjectTagging",
    "PutObjectVersionAcl",
    "PutObjectVersionTagging",
    "DeleteObject",
    "DeleteObjectVersion",
    "AbortMultipartUpload",
    "RestoreObject",
    "ReplicateObject",
}

_AWS_SENSITIVE_READ_SUBSTRINGS = (
    "Secret",
    "Password",
    "Credential",
    "AccessKey",
    "Token",
    "PrivateKey",
    "Certificate",
    "Authorization",
    "Decrypt",
    "Plaintext",
    "GetAuthorizationToken",
    "GetSecretValue",
    "GetParameters",
    "GetParameter",
    "GetObject",
    "GetObjectAcl",
    "GetObjectAttributes",
    "GetBucketPolicy",
    "GetBucketAcl",
    "GetRepositoryPolicy",
    # Sensitive configs / source / infra definitions.
    "Template",
    "Configuration",
    "UserData",
    "DistributionConfig",
)

_AWS_IAM_CRITICAL_VERBS = {
    # Trust / permissions changes.
    "UpdateAssumeRolePolicy",
    "PutRolePolicy",
    "PutUserPolicy",
    "PutGroupPolicy",
    "AttachRolePolicy",
    "AttachUserPolicy",
    "AttachGroupPolicy",
    "DetachRolePolicy",
    "DetachUserPolicy",
    "DetachGroupPolicy",
    "SetDefaultPolicyVersion",
    "CreatePolicyVersion",
    # Identity membership / boundaries.
    "AddUserToGroup",
    "PutRolePermissionsBoundary",
    "PutUserPermissionsBoundary",
    "DeleteRolePermissionsBoundary",
    "DeleteUserPermissionsBoundary",
    # Credential creation / takeover.
    "CreateAccessKey",
    "UpdateAccessKey",
    "CreateLoginProfile",
    "UpdateLoginProfile",
    "CreateServiceSpecificCredential",
    "ResetServiceSpecificCredential",
    # Instance-profile role attachment (execute as role).
    "AddRoleToInstanceProfile",
}

_AWS_READ_PREFIXES = ("Get", "List", "Describe", "View")
_AWS_DELETE_PREFIXES = ("Delete", "Remove", "Destroy")
_AWS_MEDIUM_PREFIXES = (
    "Delete",
    "Remove",
    "Destroy",
    "Terminate",
    "Suspend",
    "Pause",
    # Operational impact (usually not sensitive, not privesc on its own).
    "Start",
    "Stop",
    "Reboot",
    "Restart",
    "Resume",
    "Enable",
    "Disable",
    # Metadata-only changes.
    "Tag",
    "Untag",
)
_AWS_HIGH_PREFIXES = (
    "Put",
    "Create",
    "Update",
    "Write",
    "Start",
    "Stop",
    "Run",
    "Invoke",
    "Attach",
    "Detach",
    "Modify",
    "Enable",
    "Disable",
    "Associate",
    "Disassociate",
    "Authorize",
    "Revoke",
    "Register",
    "Deregister",
    "Upload",
    "Download",
    "Import",
    "Export",
    "Connect",
    "Login",
    "Reset",
    "Rotate",
    "Generate",
    "Assume",  # e.g., "sts:AssumeRole" (treated as high by default)
)


def aws_regex_classify(action: str, hints: HintSets) -> Optional[str]:
    action = action.strip()
    if not action:
        return None

    if action == "*" or action.endswith(":*"):
        return "critical"

    if action in _AWS_CRITICAL_EXACT:
        return "critical"

    if ":" not in action:
        return None

    service, verb = action.split(":", 1)
    service = service.lower().strip()
    verb = verb.strip()

    if service == "iam":
        if verb.startswith(_AWS_READ_PREFIXES):
            return "low"
        # Keep IAM `critical` extremely narrow: only permissions that directly change
        # identities/permissions/trust/credentials (i.e., privilege escalation primitives).
        if verb in _AWS_IAM_CRITICAL_VERBS or verb == "PassRole":
            return "critical"
        if verb.startswith(_AWS_MEDIUM_PREFIXES):
            return "medium"
        return "high"

    if service == "sts" and verb.startswith("AssumeRole"):
        return "critical"

    # AWS "put policy"-style privilege escalation (resource-based policies).
    # This is intentionally narrow to avoid things like `autoscaling:PutScalingPolicy`.
    if verb in (
        "PutBucketPolicy",
        "PutAccessPointPolicy",
        "PutMultiRegionAccessPointPolicy",
        "SetRepositoryPolicy",
        "PutRepositoryPolicy",
        "PutRegistryPolicy",
        "PutResourcePolicy",
    ) or (
        verb.endswith(("ResourcePolicy", "RepositoryPolicy", "BucketPolicy", "RegistryPolicy", "AccessPointPolicy"))
        and verb.startswith(("Put", "Set"))
    ):
        return "critical"

    # Operational and destructive actions first: these are not privilege escalation on their own.
    if verb.startswith(_AWS_MEDIUM_PREFIXES):
        return "medium"

    if verb.startswith(_AWS_READ_PREFIXES):
        if service == "s3" and verb in _AWS_S3_DATA_READ_VERBS:
            return "high"
        if service in _AWS_SENSITIVE_READ_SERVICES:
            return "high"
        if any(sub in verb for sub in _AWS_SENSITIVE_READ_SUBSTRINGS):
            return "high"
        return "low"

    if service == "s3" and verb in _AWS_S3_DATA_WRITE_VERBS:
        if verb.startswith(_AWS_DELETE_PREFIXES):
            return "medium"
        return "high"

    if verb.startswith(_AWS_HIGH_PREFIXES):
        return "high"

    return None


_GCP_CRITICAL_SUFFIXES = (
    ".actAs",
    ".actas",
    ".getAccessToken",
    ".getaccesstoken",
    ".signBlob",
    ".signblob",
    ".signJwt",
    ".signjwt",
)

_GCP_CRITICAL_EXACT = {
    "iam.serviceAccountKeys.create",
    "iam.serviceAccountKeys.createExternalAccountKey",
    "iam.serviceAccounts.signJwt",
    "iam.serviceAccounts.signBlob",
    "iam.serviceAccounts.getAccessToken",
    "iam.serviceAccounts.actAs",
    "cloudfunctions.functions.sourceCodeSet",
    "resourcemanager.projects.setIamPolicy",
    "resourcemanager.folders.setIamPolicy",
    "resourcemanager.organizations.setIamPolicy",
    "iam.serviceAccounts.setIamPolicy",
}

_GCP_BUCKET_READ_PREFIXES = (
    "storage.objects.get",
    "storage.objects.list",
    "storage.objects.read",
)

_GCP_BUCKET_WRITE_PREFIXES = (
    "storage.objects.create",
    "storage.objects.update",
    "storage.objects.delete",
)

_GCP_LOW_VERBS = {"get", "list", "read", "search", "query", "fetch", "describe"}
_GCP_DELETE_PREFIXES = ("delete", "remove", "destroy")
_GCP_MEDIUM_VERBS = {
    "delete",
    "remove",
    "destroy",
    "disable",
    "stop",
    "cancel",
    "deactivate",
    "pause",
    "suspend",
    # Operational impact / execution control.
    "start",
    "restart",
    "resume",
    # Metadata-only changes.
    "tag",
    "untag",
}
_GCP_HIGH_VERBS = {
    "create",
    "update",
    "patch",
    "set",
    "write",
    "insert",
    "add",
    "bind",
    "attach",
    "upload",
    "deploy",
    "execute",
    "run",
    "mutate",
    "approve",
    "import",
    "export",
    "connect",
    "login",
    "invoke",
    "rotate",
    "reset",
    "enable",
}


def _gcp_is_sensitive_read(permission_lower: str, verb_lower: str, hints: HintSets) -> bool:
    # IAM policy reads are generally discovery (not sensitive data access).
    if verb_lower.endswith("iampolicy") or verb_lower == "getiampolicy" or verb_lower == "listiampolicies":
        return False

    # Explicit secret/key material exposures.
    if "getwithsecret" in permission_lower or "listwithsecrets" in permission_lower:
        return True
    if ".accesssecretversion" in permission_lower or ".getsecret" in permission_lower or ".listsecrets" in permission_lower:
        return True

    # API keys and service account keys are sensitive even for reads/listing.
    if permission_lower.startswith("apikeys.") or ".apikeys." in permission_lower:
        return True
    if "serviceaccountkeys" in permission_lower:
        return True
    if verb_lower.startswith("listkeys") or verb_lower.startswith("getkey") or verb_lower.endswith("listkeys"):
        return True
    if ".listkeys" in permission_lower or ".getkey" in permission_lower:
        return True

    # Data-plane reads (common cases).
    if permission_lower.startswith("storage.objects.") and verb_lower.startswith(("get", "list", "read")):
        return True
    if permission_lower.startswith("bigquery.") and verb_lower.startswith(("getdata", "getqueryresults", "read")):
        return True
    if verb_lower in ("getdata", "getqueryresults", "readrows", "getfilecontents"):
        return True
    if permission_lower.startswith("sourcerepo.") and verb_lower.startswith(("get", "list", "read")):
        return True
    if permission_lower.startswith("artifactregistry.") and (
        "download" in verb_lower or verb_lower.startswith(("get", "list", "read"))
    ):
        return True

    # Generic sensitive keywords (kept narrow to avoid false positives like "cryptoKeys").
    if any(k in permission_lower for k in ("secret", "password", "token", "credential")):
        return True

    return False


def gcp_regex_classify(permission: str, hints: HintSets) -> Optional[str]:
    permission = permission.strip()
    if not permission:
        return None

    if permission in _GCP_CRITICAL_EXACT:
        return "critical"

    lower = permission.lower()
    if lower.endswith(_GCP_CRITICAL_SUFFIXES):
        return "critical"

    # Narrow, high-confidence GCP IAM escalation:
    # - Per requirement: treat ALL `*.setIamPolicy` as privilege escalation ("gather yourself more permissions").
    if lower.endswith(".setiampolicy"):
        return "critical"

    if lower.startswith("iam.roles."):
        role_verb = lower.rsplit(".", 1)[-1]
        if role_verb in ("create", "update", "patch"):
            return "critical"
        if role_verb in ("delete", "undelete"):
            return "medium"

    if "." not in permission:
        return None

    verb = permission.rsplit(".", 1)[-1].strip()
    verb_lower = verb.lower()
    if not verb:
        return None

    lower = permission.lower()
    # Bucket data-plane access is always high (read/write objects).
    if lower.startswith(_GCP_BUCKET_READ_PREFIXES):
        return "high"
    if lower.startswith(_GCP_BUCKET_WRITE_PREFIXES):
        return "medium" if lower.endswith(".delete") else "high"

    if verb_lower in _GCP_MEDIUM_VERBS or any(verb_lower.startswith(v) for v in _GCP_MEDIUM_VERBS):
        return "medium"

    if verb_lower in _GCP_LOW_VERBS or any(verb_lower.startswith(v) for v in _GCP_LOW_VERBS):
        if _gcp_is_sensitive_read(lower, verb_lower, hints):
            return "high"
        return "low"

    if verb_lower in _GCP_HIGH_VERBS or any(verb_lower.startswith(v) for v in _GCP_HIGH_VERBS):
        return "high"

    return None


_AZURE_CREDENTIAL_ACTION_RE = re.compile(
    r"/("
    r"listsecrets|listkeys|listcredentials|listcredential|listadminkeys|listadminkey|"
    r"getsecret|getsecrets|getkeys|getkey|getadminkeys|getadminkey|"
    r"getauthtoken|getaccesstoken|"
    r"regeneratekey|regeneratekeys|regeneratepassword|"
    r"generatecredentials|generatecredential|generatekey|generatetoken|"
    r"listpasswords|listpassword"
    r")/action$",
    re.IGNORECASE,
)


def _azure_last_segment(permission: str) -> str:
    return permission.split("/")[-1].strip().lower()


def azure_regex_classify(permission: str, hints: HintSets) -> Optional[str]:
    permission = permission.strip()
    if not permission:
        return None

    lower = permission.lower()

    # Wildcards.
    if permission == "*" or permission.endswith("/*"):
        return "critical"

    last = _azure_last_segment(permission)
    is_read = last == "read"
    is_write = last == "write"
    is_delete = last == "delete"
    is_action = last == "action"

    # RBAC / authorization plane changes.
    if lower.startswith("microsoft.authorization/"):
        if lower.endswith("/roleassignments/write") or lower.endswith("/roledefinitions/write"):
            return "critical"
        if lower.endswith("/elevateaccess/action"):
            return "critical"

    # Storage data-plane (buckets): blob/file/queue/table reads/writes should be high, deletes medium.
    if lower.startswith("microsoft.storage/") and any(
        x in lower for x in ("/blobservices/", "/fileservices/", "/queueservices/", "/tableservices/")
    ):
        if is_delete or "/delete" in lower:
            return "medium"
        if is_read or is_write or is_action:
            return "high"

    # Deletes default to medium.
    if is_delete or "/delete" in lower:
        return "medium"

    # Credentials/secret material exposures (listKeys/listSecrets/etc) are critical.
    if _AZURE_CREDENTIAL_ACTION_RE.search(lower):
        return "medium" if is_delete else "critical"

    # Key Vault secrets/keys/certs read access is treated as critical (often yields credentials).
    if lower.startswith("microsoft.keyvault/") and any(x in lower for x in ("/secrets/", "/keys/", "/certificates/")):
        if is_read:
            return "critical"

    # Reads default to low unless sensitive by keyword.
    if is_read:
        return "low"

    # Writes/actions default to high unless clearly operational-only.
    if is_write or is_action:
        # Identity assignment / RBAC-like changes.
        if "/roleassignments/" in lower or "/roledefinitions/" in lower:
            return "critical"
        if "managedidentity" in lower and ("assign" in lower or "federatedidentitycredentials" in lower):
            return "critical"
        return "high"

    return None


def bump_risk(current: str, minimum: str) -> str:
    return current if RISK_ORDER[current] >= RISK_ORDER[minimum] else minimum


def classify_all(
    provider: str,
    permissions: Iterable[str],
    hints: HintSets,
    unknown_default: str = "high",
) -> dict[str, list[str]]:
    categories: dict[str, list[str]] = {"low": [], "medium": [], "high": [], "critical": []}
    seen: set[str] = set()

    for perm in permissions:
        if not isinstance(perm, str):
            continue
        perm = perm.strip()
        if not perm or perm in seen:
            continue
        seen.add(perm)

        if provider == "aws":
            category = aws_regex_classify(perm, hints)
        elif provider == "gcp":
            category = gcp_regex_classify(perm, hints)
        elif provider == "azure":
            category = azure_regex_classify(perm, hints)
        else:
            raise ValueError(f"Unknown provider: {provider}")

        if category is None:
            category = unknown_default

        categories[category].append(perm)

    for key in categories:
        categories[key].sort()

    return categories
