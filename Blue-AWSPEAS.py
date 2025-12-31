import os
import boto3
import fnmatch
import argparse
import sys
import signal

import json
from termcolor import colored
from datetime import datetime, timezone
from tqdm import tqdm
import threading
import concurrent.futures
import time
from typing import Optional
from botocore.config import Config
from botocore.exceptions import ClientError, NoCredentialsError
from time import sleep
from scripts.permission_risk_classifier import classify_permission, candidate_actions
from bluepeass.report import Target, atomic_write_json, build_report
from bluepeass.progress import StageProgress
from bluepeass.normalize import normalize_aws_account
from bluepeass.progress_pool import SlotStageProgress



#########################
#### CLASSIFIER RULES ###
#########################
# Runtime classification uses `risk_rules/aws.yaml` via `scripts/permission_risk_classifier.py`.
# The legacy full catalog `aws_permissions_cat.yaml` is kept for reference but is not used.


#########################
#### CACHE & CONFIG  ####
#########################
_POLICY_CACHE = {}  # Cache for AWS policy documents
_POLICY_CACHE_LOCK = threading.Lock()

# Boto3 config with retries and connection pooling
BOTO3_CONFIG = Config(
    retries={'max_attempts': 3, 'mode': 'adaptive'},
    max_pool_connections=50
)

# Global tracking for analyzer cleanup on interrupt (for parallel processing)
_ALL_ANALYZERS = []  # List of (accessanalyzer_client, analyzer_name) tuples
_ALL_ANALYZERS_LOCK = threading.Lock()

MIN_UNUSED_DAYS = 90

MAX_PERMS_TO_PRINT = 15

def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully by cleaning up all analyzers across all accounts"""
    global _ALL_ANALYZERS
    print(f"\n{colored('[*] ', 'yellow')}Interrupt received. Cleaning up analyzers...")
    
    with _ALL_ANALYZERS_LOCK:
        if _ALL_ANALYZERS:
            for accessanalyzer_client, analyzer_name in _ALL_ANALYZERS:
                try:
                    accessanalyzer_client.delete_analyzer(analyzerName=analyzer_name)
                    print(f"{colored('[+] ', 'green')}Analyzer {analyzer_name} deleted.")
                except Exception as e:
                    print(f"{colored('[-] ', 'red')}Failed to delete {analyzer_name}: {str(e)}")
            _ALL_ANALYZERS.clear()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def _principal_name_from_arn(arn: Optional[str]) -> Optional[str]:
    if not arn:
        return None
    if arn.endswith(":root"):
        return "root"
    if ":assumed-role/" in arn:
        tail = arn.split(":assumed-role/", 1)[1]
        return tail.split("/", 1)[0] if tail else None
    if ":role/" in arn:
        return arn.split(":role/", 1)[1]
    if ":user/" in arn:
        return arn.split(":user/", 1)[1]
    return None


def print_permissions(ppal_permissions):
    """Print flagged permissions by risk level."""
    if not ppal_permissions or "flagged_perms" not in ppal_permissions:
        return
    
    flagged_perms = ppal_permissions["flagged_perms"]
    
    # Print in order of severity
    risk_colors = {
        'critical': 'red',
        'high': 'yellow',
        'medium': 'blue',
        'low': 'cyan'
    }
    
    for risk_level in ['critical', 'high', 'medium', 'low']:
        if risk_level in flagged_perms and flagged_perms[risk_level]:
            perms = flagged_perms[risk_level]
            more_than_str = " and more..." if len(perms) > MAX_PERMS_TO_PRINT else ""
            color = risk_colors.get(risk_level, 'white')
            print(f"    - {colored(risk_level.upper(), color)}: {', '.join(f'`{p}`' for p in perms[:MAX_PERMS_TO_PRINT])}{more_than_str}")




def print_results(
    account_id,
    profile,
    unused_roles,
    unused_logins,
    unused_acc_keys,
    unused_perms,
    unused_groups,
    external_ppals,
    *,
    identity=None,
    unused_custom_policies=None,
    all_access_keys=None,
    external_trust_roles=None,
    access_analyzer_enabled=None,
    user_permissions=None,
    role_permissions=None,
    group_memberships=None,
    min_unused_days=30,
):
    """Print results for a single account and return a JSON-serializable dict."""
    result = {
        "account_id": account_id,
        "profile": profile,
        "identity": identity or {},
        "unused_roles": unused_roles,
        "unused_logins": unused_logins,
        "unused_access_keys": unused_acc_keys,
        "unused_permissions": unused_perms,
        "unused_groups": unused_groups,
        "external_principals": external_ppals,
        "unused_custom_policies": unused_custom_policies or {},
        "all_access_keys": all_access_keys or {},
        "external_trust_roles": external_trust_roles or {},
        "access_analyzer_enabled": access_analyzer_enabled,
        "user_permissions": user_permissions or {},
        "role_permissions": role_permissions or {},
        "group_memberships": group_memberships or [],
    }

    print(f"Interesting permissions in {colored(account_id, 'yellow')} ({colored(profile, 'blue')}): ")

    if unused_custom_policies:
        print(f"{colored('Unused customer-managed policies', 'yellow', attrs=['bold'])}:")
        for arn, data in unused_custom_policies.items():
            name = data.get("policy_name") or ""
            name_str = f" ({name})" if name else ""
            print(f"  - `{arn}`{name_str}")
            if data.get("permissions"):
                print_permissions(data["permissions"])
            else:
                print("    - (No flagged permissions)")
            print()

    if all_access_keys:
        print(f"{colored('IAM user access keys (review/remove all where possible)', 'yellow', attrs=['bold'])}:")
        for user_arn, data in all_access_keys.items():
            keys = data.get("keys") or []
            if not keys:
                continue
            print(f"  - `{user_arn}` ({data.get('user_name')})")
            for k in keys[:MAX_PERMS_TO_PRINT]:
                akid = k.get("access_key_id")
                status = k.get("status")
                n_days = k.get("n_days")
                last_used = k.get("last_used_date")
                if last_used:
                    age_str = f"Last used {n_days} days ago"
                else:
                    age_str = f"Never used (created {n_days} days ago)" if isinstance(n_days, int) and n_days >= 0 else "Never used"
                print(f"    - `{akid}` ({status}): {age_str}")
            if len(keys) > MAX_PERMS_TO_PRINT:
                print(f"    - and {len(keys) - MAX_PERMS_TO_PRINT} more...")
            print()

    if unused_roles:
        print(f"{colored('Unused roles with flagged permissions', 'yellow', attrs=['bold'])}:")
        for arn, data in unused_roles.items():
            is_external_str = " and is externally accessible" if external_ppals.get(arn) else ""
            no_sensitive_perms = not data.get("permissions")

            # If actually used in the last min_unused_days, skip it
            if data['n_days'] < min_unused_days and data['n_days'] >= 0:
                continue

            if data['n_days'] == -1:
                intro_str = f"  - `{arn}`: Never used{is_external_str}"
            else:
                intro_str = f"  - `{arn}`: Last used {data['n_days']} days ago{is_external_str}"

            if no_sensitive_perms:
                intro_str += " (No flagged permissions granted)"

            print(intro_str)

            if data.get("permissions"):
                print_permissions(data["permissions"])

            print()

    if unused_logins:
        print(f"{colored('Unused user logins with flagged permissions', 'yellow', attrs=['bold'])}:")
        for arn, data in unused_logins.items():
            is_external_str = " and is externally accessible" if external_ppals.get(arn) else ""
            no_sensitive_perms = not data.get("permissions")

            # If actually used in the last min_unused_days, skip it
            if data['n_days'] < min_unused_days and data['n_days'] >= 0:
                continue

            if data['n_days'] == -1:
                intro_str = f"  - `{arn}`: Never used{is_external_str}"
            else:
                intro_str = f"  - `{arn}`: Last used {data['n_days']} days ago{is_external_str}"

            if no_sensitive_perms:
                intro_str += " (No flagged permissions granted)"

            print(intro_str)

            if data.get("permissions"):
                print_permissions(data["permissions"])

            print()

    if unused_acc_keys:
        print(f"{colored('Unused access keys with flagged permissions', 'yellow', attrs=['bold'])}:")
        for arn, data in unused_acc_keys.items():
            is_external_str = " and is externally accessible" if external_ppals.get(arn) else ""
            no_sensitive_perms = not data.get("permissions")

            # If actually used in the last min_unused_days, skip it
            if data['n_days'] < min_unused_days and data['n_days'] >= 0:
                continue

            if data['n_days'] == -1:
                intro_str = f"  - `{arn}`: Never used{is_external_str}"
            else:
                intro_str = f"  - `{arn}`: Last used {data['n_days']} days ago{is_external_str}"

            if no_sensitive_perms:
                intro_str += " (No flagged permissions granted)"

            print(intro_str)

            if data.get("permissions"):
                print_permissions(data["permissions"])

            print()

    if unused_groups:
        print(f"{colored('Unused groups with flagged permissions', 'yellow', attrs=['bold'])}:")
        for arn, data in unused_groups.items():
            is_external_str = " and is externally accessible" if external_ppals.get(arn) else ""
            no_sensitive_perms = not data.get("permissions")

            # If actually used in the last min_unused_days, skip it
            if data['n_days'] < min_unused_days and data['n_days'] >= 0:
                continue

            if no_sensitive_perms:
                print(f"  - `{arn}`: Is empty{is_external_str} (No flagged permissions granted)")
            else:
                print(f"  - `{arn}`: Never used{is_external_str}")

            if data.get("permissions"):
                print_permissions(data["permissions"])

            print()

    if unused_perms:
        flagged_only = {arn: data for arn, data in unused_perms.items() if "last_perms" not in data}
        unused_flagged = {arn: data for arn, data in unused_perms.items() if "last_perms" in data}

        if flagged_only:
            print(f"{colored('Principals with flagged permissions', 'yellow', attrs=['bold'])}:")
            for arn, data in flagged_only.items():
                is_external_str = " and is externally accessible" if external_ppals.get(arn) else ""
                type_str = f" ({data.get('type')})" if data.get("type") else ""
                print(f"  - `{arn}`{type_str}{is_external_str}")
                print_permissions(data["permissions"])
                print()

        if unused_flagged:
            print(f"{colored('Principals with unused flagged permissions', 'yellow', attrs=['bold'])}:")
            for arn, data in unused_flagged.items():
                is_external_str = " and is externally accessible" if external_ppals.get(arn) else ""

                if data["n_days"] == -1:
                    print(f"  - `{arn}`: Never used{is_external_str}")
                else:
                    print(f"  - `{arn}`: Last used {data['n_days']} days ago{is_external_str}")

                print_permissions(data["permissions"])

                print(f"    - {colored('Unused permissions', 'magenta')}:")
                for service in list(data["last_perms"].keys())[:4]:
                    perms = data["last_perms"][service]

                    str_srv = f"      - `{service}`: "
                    if len(perms) == 1:
                        if perms["n_days"] == -1:
                            str_srv += "Never used."
                        else:
                            str_srv += f"Last used {perms['n_days']} days ago."

                    print(str_srv)

                    if len(perms) > 1:
                        i = 0
                        for perm, details in perms.items():
                            if perm == "n_days":
                                continue

                            # If actually used in the last min_unused_days, skip it
                            if details["n_days"] < min_unused_days and details["n_days"] >= 0:
                                continue

                            if details["n_days"] == -1:
                                print(f"        - `{service}:{perm}`: Never used")
                            else:
                                print(f"        - `{service}:{perm}`: Last used {details['n_days']} days ago")

                            i += 1
                            if i == 3:
                                print(f"        - Other {len(perms)-3} `{service}` permissions not used in too much time...")
                                break

                if len(list(data["last_perms"].keys())) > 4:
                    oters_svcs_str = ", ".join("`" + s + "`" for s in list(data["last_perms"].keys())[4:])
                    if oters_svcs_str:
                        print(
                            f"        - It also has sensitive permissions in the services {oters_svcs_str} not used in too much time..."
                        )

                print()
                print()  # Here 2 prints to separate the different principals

    if external_ppals:
        print(f"{colored('Externally accessible principals', 'yellow', attrs=['bold'])}:")
        for arn, data in external_ppals.items():
            conditions_str = f" Conditions: {data['conditions']}" if data['conditions'] else ""

            print(f"  - `{arn}`: Accessible via `{data['action']}` from {data['access']}.{conditions_str}")
            print(f"    - Is public: {colored(data['is_public'], 'red') if data['is_public'] else colored(data['is_public'], 'green')}")
            print()

    if external_trust_roles:
        print(f"{colored('Roles trusting external principals (best-effort)', 'yellow', attrs=['bold'])}:")
        for arn, data in external_trust_roles.items():
            principals = data.get("principals") or []
            conds = data.get("conditions") or []
            plist = ", ".join(f"{p.get('type')}={p.get('value')}" for p in principals[:8])
            more = f" and {len(principals) - 8} more" if len(principals) > 8 else ""
            print(f"  - `{arn}`: {plist}{more}")
            if conds:
                print(f"    - Conditions: {conds[:2]}{' ...' if len(conds) > 2 else ''}")
            print()

    print()
    print()
    return result


########################
## PERMISSION HELPERS ##
########################

def _days_since(dt: datetime) -> int:
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return max(0, (now - dt).days)


def get_all_user_access_keys(iam_client, users, verbose=False):
    """Return {user_arn: {user_name, keys:[{access_key_id,status,create_date,last_used_date,n_days}]}} (best-effort)."""
    out = {}
    for u in users or []:
        user_name = u.get("UserName")
        user_arn = u.get("Arn")
        if not user_name or not user_arn:
            continue
        try:
            keys_resp = iam_client.list_access_keys(UserName=user_name)
        except ClientError as e:
            if verbose and e.response["Error"]["Code"] in ["AccessDenied", "AccessDeniedException"]:
                print(f"{colored('[-] ', 'yellow')}Access denied listing access keys for user {user_name}")
                continue
            if verbose:
                print(f"{colored('[-] ', 'red')}Error listing access keys for user {user_name}: {e}")
            continue
        keys = []
        for meta in keys_resp.get("AccessKeyMetadata", []) or []:
            access_key_id = meta.get("AccessKeyId")
            status = meta.get("Status")
            create_date = meta.get("CreateDate")
            last_used_date = None
            n_days = -1
            try:
                used = iam_client.get_access_key_last_used(AccessKeyId=access_key_id)
                last_used_date = used.get("AccessKeyLastUsed", {}).get("LastUsedDate")
                if last_used_date:
                    n_days = _days_since(last_used_date)
            except Exception:
                pass
            if create_date and not last_used_date:
                try:
                    n_days = _days_since(create_date)
                except Exception:
                    n_days = -1
            keys.append(
                {
                    "access_key_id": access_key_id,
                    "status": status,
                    "create_date": create_date.isoformat() if hasattr(create_date, "isoformat") else str(create_date),
                    "last_used_date": last_used_date.isoformat() if hasattr(last_used_date, "isoformat") else (str(last_used_date) if last_used_date else None),
                    "n_days": n_days,
                }
            )
        out[user_arn] = {"user_name": user_name, "keys": keys}
    return out


def get_unused_custom_policies(iam_client, only_all_resources, risk_levels, verbose=False):
    """
    Return customer-managed policies that are not attached anywhere (AttachmentCount==0),
    plus their high/critical perms.
    """
    unused = {}
    try:
        paginator = iam_client.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local", OnlyAttached=False):
            for pol in page.get("Policies", []) or []:
                if (pol.get("AttachmentCount") or 0) != 0:
                    continue
                arn = pol.get("Arn")
                default_vid = pol.get("DefaultVersionId")
                name = pol.get("PolicyName")
                if not arn or not default_vid:
                    continue
                try:
                    pv = iam_client.get_policy_version(PolicyArn=arn, VersionId=default_vid)
                    doc = pv.get("PolicyVersion", {}).get("Document")
                    if not doc:
                        continue
                    source = {
                        "source_type": "custom_policy",
                        "policy_arn": arn,
                        "policy_name": name,
                    }
                    action_sources = {}
                    for action in extract_actions_from_document(doc, only_all_resources=only_all_resources):
                        action_sources.setdefault(action, []).append(source)
                    flagged = classify_actions_with_sources(action_sources, risk_levels)
                    unused[arn] = {"policy_name": name, "permissions": flagged}
                except Exception as e:
                    if verbose:
                        print(f"{colored('[-] ', 'yellow')}Failed to fetch policy doc for {arn}: {e}")
                    continue
    except Exception as e:
        if verbose:
            print(f"{colored('[-] ', 'yellow')}Failed listing customer managed policies: {e}")
    return unused


def find_external_trust_roles(roles, account_id: str):
    """Best-effort scan of role trust policies for external principals (independent of Access Analyzer)."""
    out = {}
    for r in roles or []:
        arn = r.get("Arn")
        doc = r.get("AssumeRolePolicyDocument")
        if not arn or not isinstance(doc, dict):
            continue
        principals = []
        conditions = []
        for st in doc.get("Statement", []) or []:
            if not isinstance(st, dict) or st.get("Effect") != "Allow":
                continue
            pr = st.get("Principal") or {}
            cond = st.get("Condition") or {}
            if cond:
                conditions.append(cond)
            if pr == "*" or pr == {"AWS": "*"}:
                principals.append({"type": "AWS", "value": "*"})
            if isinstance(pr, dict):
                for ptype, pval in pr.items():
                    vals = pval if isinstance(pval, list) else [pval]
                    for v in vals:
                        if not v:
                            continue
                        principals.append({"type": ptype, "value": v})
        external = []
        for p in principals:
            ptype = p["type"]
            v = str(p["value"])
            if v == "*" and ptype in ("AWS",):
                external.append(p)
                continue
            if ptype == "Federated":
                external.append(p)
                continue
            if ptype == "AWS":
                # External if principal references another account ID/root/role/user.
                if v.isdigit() and v != account_id:
                    external.append(p)
                elif f":{account_id}:" not in v and (":iam::" in v or v.startswith("arn:aws:iam::")):
                    external.append(p)
        if external:
            out[arn] = {"principals": external, "conditions": conditions}
    return out

# Function to combine all permissions from policy documents
def combine_permissions(policy_documents, *, only_all_resources: bool):
    permissions = []
    for document in policy_documents:
        if type(document["Statement"]) == list:
            statements = document["Statement"]
        else:
            statements = []
            statements.append(document["Statement"])
        for statement in statements:
            # Skip Deny statements - only process Allow statements
            if statement.get("Effect", "Allow") != "Allow":
                continue
            
            resource = statement.get("Resource", [])
            if only_all_resources:
                if isinstance(resource, str) and resource != "*" and not resource.endswith(":*"):
                    continue
                elif "*" not in resource and not any(r.endswith(":*") for r in resource):
                    continue

            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            if actions:
                permissions.extend(actions)
    return permissions


def extract_actions_from_document(document, *, only_all_resources: bool):
    actions = []
    if not isinstance(document, dict):
        return actions
    statements = document.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]
    for statement in statements:
        if not isinstance(statement, dict):
            continue
        # Skip Deny statements - only process Allow statements
        if statement.get("Effect", "Allow") != "Allow":
            continue

        resource = statement.get("Resource", [])
        if only_all_resources:
            if isinstance(resource, str) and resource != "*" and not resource.endswith(":*"):
                continue
            elif isinstance(resource, list):
                if "*" not in resource and not any(isinstance(r, str) and r.endswith(":*") for r in resource):
                    continue

        perms = statement.get("Action", [])
        if isinstance(perms, str):
            perms = [perms]
        for perm in perms:
            if isinstance(perm, str) and perm:
                actions.append(perm)
    return actions


def classify_actions_with_sources(action_sources, risk_levels):
    if not action_sources:
        return {
            "flagged_perms": {},
            "flagged_perm_sources": {},
            "is_admin": False,
            "all_actions": [],
        }
    if risk_levels is None:
        risk_levels = ['high', 'critical']

    def _dedupe_sources(sources):
        seen = set()
        out = []
        for src in sources or []:
            if not isinstance(src, dict):
                continue
            key = (
                src.get("source_type"),
                src.get("policy_arn"),
                src.get("policy_name"),
                src.get("attachment"),
                src.get("attachment_name"),
            )
            if key in seen:
                continue
            seen.add(key)
            out.append(src)
        return out

    flagged_perms = {}
    flagged_perm_sources = {}
    is_admin = False
    all_actions = list(action_sources.keys())

    wildcard_sources = []
    for action in all_actions:
        if action in ("*", "*:*"):
            wildcard_sources.extend(action_sources.get(action, []))
            is_admin = True
    if is_admin:
        flagged_perms.setdefault("critical", []).append("*")
        flagged_perm_sources.setdefault("critical", {}).setdefault("*", []).extend(_dedupe_sources(wildcard_sources))

    for action, sources in action_sources.items():
        lvl = classify_permission("aws", action, unknown_default="high")
        if lvl not in risk_levels:
            continue
        if action in ("*", "*:*"):
            continue
        flagged_perms.setdefault(lvl, []).append(action)
        flagged_perm_sources.setdefault(lvl, {}).setdefault(action, []).extend(sources or [])

    # Deduplicate permissions within each risk level
    for risk_level in list(flagged_perms.keys()):
        flagged_perms[risk_level] = list(dict.fromkeys(flagged_perms[risk_level]))
        for perm in list(flagged_perm_sources.get(risk_level, {}).keys()):
            flagged_perm_sources[risk_level][perm] = _dedupe_sources(flagged_perm_sources[risk_level][perm])

    return {
        "flagged_perms": flagged_perms,
        "flagged_perm_sources": flagged_perm_sources,
        "is_admin": False,
        "all_actions": all_actions,
    }


# Function to check if a policy contains sensitive or privesc permissions
def check_policy(all_perm, risk_levels=None):
    if not all_perm:
        return {
            "flagged_perms": {},
            "is_admin": False
        }
    
    # Default to high and critical if not specified
    if risk_levels is None:
        risk_levels = ['high', 'critical']

    flagged_perms = {}  # {risk_level: [permissions]}
    is_admin = False

    # Check for administrator access
    if all_perm and ("*" in all_perm or "*:*" in all_perm):
        flagged_perms['critical'] = ["*"]
        is_admin = True
        return {
            "flagged_perms": flagged_perms,
            "is_admin": is_admin
        }

    if not is_admin and all_perm:
        for perm in all_perm:
            if not isinstance(perm, str) or not perm:
                continue
            lvl = classify_permission("aws", perm, unknown_default="high")
            if lvl not in risk_levels:
                continue
            flagged_perms.setdefault(lvl, []).append(perm)
        
        # Deduplicate permissions within each risk level
        for risk_level in flagged_perms:
            flagged_perms[risk_level] = list(dict.fromkeys(flagged_perms[risk_level]))  # Preserves order

    return {
        "flagged_perms": flagged_perms,
        "is_admin": is_admin
    }



# Function to get inline and attached policies for a principal
def get_policies(
    iam_client,
    principal_type,
    principal_name,
    arn,
    verbose,
    only_all_resources,
    risk_levels,
):
    policy_document = []
    policy_docs_with_sources = []
    all_attached_policies = []

    try:
        # Use paginator for attached policies to handle large policy lists
        if principal_type == "User":
            paginator = iam_client.get_paginator('list_attached_user_policies')
            for page in paginator.paginate(UserName=principal_name):
                all_attached_policies.extend(page.get('AttachedPolicies', []))
        elif principal_type == "Role":
            paginator = iam_client.get_paginator('list_attached_role_policies')
            for page in paginator.paginate(RoleName=principal_name):
                all_attached_policies.extend(page.get('AttachedPolicies', []))
        elif principal_type == "Group":
            paginator = iam_client.get_paginator('list_attached_group_policies')
            for page in paginator.paginate(GroupName=principal_name):
                all_attached_policies.extend(page.get('AttachedPolicies', []))
    except ClientError as e:
        if e.response['Error']['Code'] in ['AccessDenied', 'AccessDeniedException']:
            if verbose:
                print(f"{colored('[-] ', 'yellow')}Access denied listing policies for {principal_type} {principal_name}")
            return None
        raise

    for policy in all_attached_policies:
        try:
            policy_arn = policy["PolicyArn"]
            source = {
                "source_type": "managed_policy",
                "policy_arn": policy_arn,
                "policy_name": policy.get("PolicyName"),
                "attachment": principal_type.lower(),
                "attachment_name": principal_name,
            }
            
            # Check cache first
            with _POLICY_CACHE_LOCK:
                if policy_arn in _POLICY_CACHE:
                    doc = _POLICY_CACHE[policy_arn]
                    policy_document.append(doc)
                    policy_docs_with_sources.append((doc, source))
                    continue
            
            # Fetch policy
            policy_data = iam_client.get_policy(PolicyArn=policy_arn)
            policy_version = iam_client.get_policy_version(
                PolicyArn=policy_arn, VersionId=policy_data["Policy"]["DefaultVersionId"]
            )
            doc = policy_version["PolicyVersion"]["Document"]
            
            # Cache it
            with _POLICY_CACHE_LOCK:
                _POLICY_CACHE[policy_arn] = doc
            
            policy_document.append(doc)
            policy_docs_with_sources.append((doc, source))
        except ClientError as e:
            if e.response['Error']['Code'] in ['AccessDenied', 'AccessDeniedException']:
                if verbose:
                    print(f"{colored('[-] ', 'yellow')}Access denied fetching policy {policy['PolicyArn']}")
            else:
                if verbose:
                    print(f"{colored('[-] ', 'red')}Error fetching policy {policy['PolicyArn']}: {e.response['Error']['Message']}")
            continue
        except Exception as e:
            if verbose:
                print(f"{colored('[-] ', 'red')}Error fetching policy {policy['PolicyArn']} for {principal_type} {principal_name}: {str(e)}")
            continue

    all_inline_policy_names = []
    try:
        # Use paginator for inline policies to handle large policy lists
        if principal_type == "User":
            paginator = iam_client.get_paginator('list_user_policies')
            for page in paginator.paginate(UserName=principal_name):
                all_inline_policy_names.extend(page.get('PolicyNames', []))
        elif principal_type == "Role":
            paginator = iam_client.get_paginator('list_role_policies')
            for page in paginator.paginate(RoleName=principal_name):
                all_inline_policy_names.extend(page.get('PolicyNames', []))
        elif principal_type == "Group":
            paginator = iam_client.get_paginator('list_group_policies')
            for page in paginator.paginate(GroupName=principal_name):
                all_inline_policy_names.extend(page.get('PolicyNames', []))
    except ClientError as e:
        if e.response['Error']['Code'] in ['AccessDenied', 'AccessDeniedException']:
            if verbose:
                print(f"{colored('[-] ', 'yellow')}Access denied listing inline policies for {principal_type} {principal_name}")
            return None
        raise

    for policy_name in all_inline_policy_names:
        inlinepolicy = {}
        try:
            if principal_type == "User":
                inlinepolicy = iam_client.get_user_policy(UserName=principal_name, PolicyName=policy_name)
            elif principal_type == "Role":
                inlinepolicy = iam_client.get_role_policy(RoleName=principal_name, PolicyName=policy_name)
            elif principal_type == "Group":
                inlinepolicy = iam_client.get_group_policy(GroupName=principal_name, PolicyName=policy_name)

            if inlinepolicy:
                doc = inlinepolicy["PolicyDocument"]
                policy_document.append(doc)
                policy_docs_with_sources.append(
                    (
                        doc,
                        {
                            "source_type": "inline_policy",
                            "policy_name": policy_name,
                            "attachment": principal_type.lower(),
                            "attachment_name": principal_name,
                        },
                    )
                )
        except ClientError as e:
            if e.response['Error']['Code'] in ['AccessDenied', 'AccessDeniedException', 'NoSuchEntity']:
                if verbose:
                    print(f"{colored('[-] ', 'yellow')}Cannot access inline policy {policy_name}")
            else:
                if verbose:
                    print(f"{colored('[-] ', 'red')}Error fetching inline policy {policy_name}: {e.response['Error']['Message']}")
            continue
        except Exception as e:
            if verbose:
                print(f"{colored('[-] ', 'red')}Error fetching inline policy {policy_name} for {principal_type} {principal_name}: {str(e)}")
            continue

    if not policy_document:
        return None

    action_sources: dict[str, list[dict]] = {}
    for doc, source in policy_docs_with_sources:
        for action in extract_actions_from_document(doc, only_all_resources=only_all_resources):
            action_sources.setdefault(action, []).append(source)

    interesting_perms = classify_actions_with_sources(action_sources, risk_levels)
    interesting_perms["action_sources"] = action_sources

    return interesting_perms


def get_user_effective_permissions(
    iam_client,
    user,
    verbose,
    only_all_resources,
    risk_levels,
    group_memberships,
    lock,
):
    """Aggregate user + group policies into a single permission view."""
    action_sources: dict[str, list[dict]] = {}

    user_perms = get_policies(
        iam_client,
        "User",
        user["UserName"],
        user["Arn"],
        verbose,
        only_all_resources,
        risk_levels,
    )
    if user_perms and user_perms.get("action_sources"):
        for action, sources in (user_perms.get("action_sources") or {}).items():
            action_sources.setdefault(action, []).extend(sources or [])

    try:
        paginator = iam_client.get_paginator('list_groups_for_user')
        for page in paginator.paginate(UserName=user["UserName"]):
            for group in page.get("Groups", []):
                group_name = group.get("GroupName")
                group_arn = group.get("Arn") or group_name
                if not group_name:
                    continue
                if group_memberships is not None and lock is not None:
                    with lock:
                        group_memberships.append(
                            {
                                "group_arn": group_arn,
                                "group_name": group_name,
                                "user_arn": user.get("Arn"),
                                "user_name": user.get("UserName"),
                            }
                        )
                group_perms = get_policies(
                    iam_client,
                    "Group",
                    group_name,
                    group_arn,
                    verbose,
                    only_all_resources,
                    risk_levels,
                )
                if group_perms and group_perms.get("action_sources"):
                    for action, sources in (group_perms.get("action_sources") or {}).items():
                        action_sources.setdefault(action, []).extend(sources or [])
    except ClientError as e:
        if e.response['Error']['Code'] in ['AccessDenied', 'AccessDeniedException']:
            if verbose:
                print(f"{colored('[-] ', 'yellow')}Access denied listing groups for user {user['UserName']}")
        else:
            if verbose:
                print(f"{colored('[-] ', 'red')}Error listing groups for user {user['UserName']}: {e.response['Error']['Message']}")
    except Exception as e:
        if verbose:
            print(f"{colored('[-] ', 'red')}Error listing groups for user {user['UserName']}: {str(e)}")

    if not action_sources:
        return None

    merged = classify_actions_with_sources(action_sources, risk_levels)
    merged["action_sources"] = action_sources
    return merged


def is_group_empty(iam_client, group_name):
    """
    Check if an IAM group is empty (no users attached).

    :param group_name: str, the name of the IAM group to check.
    :return: bool, True if the group is empty, False otherwise.
    """
    try:
        response = iam_client.get_group(GroupName=group_name)
        users = response.get('Users', [])
        return not users
    except Exception:
        return False


# Get all unused roles
def get_unused_roles(accessanalyzer, analyzer_arn, unused_roles, verbose):
    findings = []
    try:
        paginator = accessanalyzer.get_paginator('list_findings_v2')
        for page in paginator.paginate(analyzerArn=analyzer_arn, filter={'findingType': {'eq': ['UnusedIAMRole']}}):
            findings.extend(page.get('findings', []))
    except ClientError as e:
        if verbose:
            print(f"{colored('[-] ', 'yellow')}Error fetching unused roles: {e.response['Error']['Message']}")
        return
    
    for finding in findings:
        try:
            details = accessanalyzer.get_finding_v2(analyzerArn=analyzer_arn, id=finding["id"])['findingDetails'][0]['unusedIamRoleDetails']
            if 'lastAccessed' in details:
                last_accessed = details['lastAccessed']
                # Normalize only naive datetime to UTC; aware datetimes are already correct
                if last_accessed.tzinfo is None:
                    last_accessed = last_accessed.replace(tzinfo=timezone.utc)
                n_days = (datetime.now(timezone.utc) - last_accessed).days
            else:
                n_days = -1

            unused_roles[finding["resource"]] = {
                "n_days": n_days
            }
        except Exception as e:
            if verbose:
                print(f"{colored('[-] ', 'red')}Error processing finding {finding['id']} for UnusedIAMRole: {str(e)}")
            continue


# Get all unused logins
def get_unused_logins(accessanalyzer, analyzer_arn, unused_logins, verbose):
    findings = []
    try:
        paginator = accessanalyzer.get_paginator('list_findings_v2')
        for page in paginator.paginate(analyzerArn=analyzer_arn, filter={'findingType': {'eq': ['UnusedIAMUserPassword']}}):
            findings.extend(page.get('findings', []))
    except ClientError as e:
        if verbose:
            print(f"{colored('[-] ', 'yellow')}Error fetching unused logins: {e.response['Error']['Message']}")
        return
    
    for finding in findings:
        try:
            details = accessanalyzer.get_finding_v2(analyzerArn=analyzer_arn, id=finding["id"])['findingDetails'][0]['unusedIamUserPasswordDetails']
            if 'lastAccessed' in details:
                last_accessed = details['lastAccessed']
                # Normalize only naive datetime to UTC; aware datetimes are already correct
                if last_accessed.tzinfo is None:
                    last_accessed = last_accessed.replace(tzinfo=timezone.utc)
                n_days = (datetime.now(timezone.utc) - last_accessed).days
            else:
                n_days = -1

            unused_logins[finding["resource"]] = {
                "n_days": n_days
            }
        except Exception as e:
            if verbose:
                print(f"{colored('[-] ', 'red')}Error processing finding {finding['id']} for UnusedIAMUserPassword: {str(e)}")
            continue


# Get all unused access keys
def get_unused_access_keys(accessanalyzer, analyzer_arn, unused_acc_keys, verbose):
    findings = []
    try:
        paginator = accessanalyzer.get_paginator('list_findings_v2')
        for page in paginator.paginate(analyzerArn=analyzer_arn, filter={'findingType': {'eq': ['UnusedIAMUserAccessKey']}}):
            findings.extend(page.get('findings', []))
    except ClientError as e:
        if verbose:
            print(f"{colored('[-] ', 'yellow')}Error fetching unused access keys: {e.response['Error']['Message']}")
        return
    
    for finding in findings:
        try:
            details = accessanalyzer.get_finding_v2(analyzerArn=analyzer_arn, id=finding["id"])['findingDetails'][0]['unusedIamUserAccessKeyDetails']
            if 'lastAccessed' in details:
                last_accessed = details['lastAccessed']
                # Normalize only naive datetime to UTC; aware datetimes are already correct
                if last_accessed.tzinfo is None:
                    last_accessed = last_accessed.replace(tzinfo=timezone.utc)
                n_days = (datetime.now(timezone.utc) - last_accessed).days
            else:
                n_days = -1

            unused_acc_keys[finding["resource"]] = {
                "n_days": n_days
            }
        except Exception as e:
            if verbose:
                print(f"{colored('[-] ', 'red')}Error processing finding {finding['id']} for UnusedIAMUserAccessKey: {str(e)}")
            continue


# Get which permissions haven't been used in a long time - OPTIMIZED batch version
def get_all_unused_permissions(accessanalyzer, analyzer_arn, verbose):
    """
    Fetch all UnusedPermission findings in one batch, then group by resource ARN.
    Returns: dict[resource_arn] -> list[finding_ids]
    """
    findings_by_resource = {}
    findings = []
    
    try:
        paginator = accessanalyzer.get_paginator('list_findings_v2')
        for page in paginator.paginate(analyzerArn=analyzer_arn, filter={'findingType': {'eq': ['UnusedPermission']}}):
            findings.extend(page.get('findings', []))
    except ClientError as e:
        if verbose:
            print(f"{colored('[-] ', 'yellow')}Error fetching unused permissions: {e.response['Error']['Message']}")
        return findings_by_resource
    
    # Group findings by resource ARN
    for finding in findings:
        resource_arn = finding.get("resource")
        if resource_arn:
            findings_by_resource.setdefault(resource_arn, []).append(finding["id"])
    
    return findings_by_resource


def process_unused_permissions_for_principal(accessanalyzer, analyzer_arn, arn, type_ppal, permissions_dict, unused_perms, lock, verbose, finding_ids):
    """Process unused permission findings for a specific principal (given pre-fetched finding IDs)."""
    if not finding_ids or not permissions_dict or permissions_dict.get("is_admin", False):
        return
    
    last_perms = {}
    max_n_days = -1
    
    for finding_id in finding_ids:
        try:
            details = accessanalyzer.get_finding_v2(analyzerArn=analyzer_arn, id=finding_id)['findingDetails']
            
            for detail in details:
                if 'lastAccessed' in detail['unusedPermissionDetails']:
                    last_accessed = detail['unusedPermissionDetails']['lastAccessed']
                    if last_accessed.tzinfo is None:
                        last_accessed = last_accessed.replace(tzinfo=timezone.utc)
                    detail_n_days = (datetime.now(timezone.utc) - last_accessed).days
                else:
                    detail_n_days = -1
                
                if detail_n_days > max_n_days:
                    max_n_days = detail_n_days

                service_namespace = detail['unusedPermissionDetails']['serviceNamespace']

                # Collect all flagged permissions across all risk levels
                all_current_perms = []
                if "flagged_perms" in permissions_dict:
                    for risk_level, perms in permissions_dict["flagged_perms"].items():
                        all_current_perms.extend(perms)

                # If the affected namespace is not in the permissions, skip
                if not any(fnmatch.fnmatch(service_namespace, p.split(":")[0]) for p in all_current_perms):
                    continue

                last_perms[service_namespace] = {
                    "n_days": detail_n_days
                }

                if 'actions' in detail['unusedPermissionDetails']:
                    for perm in detail['unusedPermissionDetails']['actions']:
                        if 'lastAccessed' in perm:
                            perm_last_accessed = perm['lastAccessed']
                            if perm_last_accessed.tzinfo is None:
                                perm_last_accessed = perm_last_accessed.replace(tzinfo=timezone.utc)
                            perm_n_days = (datetime.now(timezone.utc) - perm_last_accessed).days
                        else:
                            perm_n_days = -1

                        if not any(fnmatch.fnmatch(f"{service_namespace}:{perm['action']}", p_pattern) for p_pattern in all_current_perms):
                            continue

                        last_perms[service_namespace][perm["action"]] = {
                            "n_days": perm_n_days
                        }
        except Exception as e:
            if verbose:
                print(f"{colored('[-] ', 'red')}Error processing finding {finding_id} for UnusedPermission: {str(e)}")
            continue
    
    # Only write if we found unused permissions
    if last_perms:
        with lock:
            unused_perms[arn] = {
                "type": type_ppal,
                "n_days": max_n_days,
                "permissions": permissions_dict,
                "last_perms": last_perms
            }


def get_external_principals(accessanalyzer, analyzer_arn_exposed, external_ppals, verbose):
    findings = []
    try:
        paginator = accessanalyzer.get_paginator('list_findings_v2')
        for page in paginator.paginate(analyzerArn=analyzer_arn_exposed, filter={'resourceType': {'eq': ['AWS::IAM::Role']}}):
            findings.extend(page.get('findings', []))
    except ClientError as e:
        if verbose:
            print(f"{colored('[-] ', 'yellow')}Error fetching external principals: {e.response['Error']['Message']}")
        return
    
    for finding in findings:
        try:
            if finding["findingType"] != "ExternalAccess":
                if verbose:
                    print(f"{colored('[-] ', 'red')}Unknown external finding type: {finding['findingType']}")
                continue

            arn = finding["resource"]

            details = accessanalyzer.get_finding_v2(analyzerArn=analyzer_arn_exposed, id=finding["id"])['findingDetails'][0]['externalAccessDetails']
            external_ppals[arn] = {
                "is_public": details["isPublic"],
                "action": ", ".join(details["action"]),
                "access": " AND ".join([f'{k}: `{v}`' for k, v in details["principal"].items()]),
                "conditions": " AND ".join([f'`{k} == {v}`' for k, v in details["condition"].items()])
            }
        except Exception as e:
            if verbose:
                print(f"{colored('[-] ', 'red')}Error processing finding {finding['id']} for ExternalAccess: {str(e)}")
            continue


def check_user_permissions(
    user,
    iam_client,
    verbose,
    only_all_resources,
    accessanalyzer,
    analyzer_arn,
    unused_logins,
    unused_acc_keys,
    unused_perms,
    user_permissions,
    group_memberships,
    lock,
    risk_levels,
    unused_permission_findings_map: dict = None,
):
    """Check permissions for a single user (thread-safe)"""
    if unused_permission_findings_map is None:
        unused_permission_findings_map = {}
    
    try:
        user_perms = get_user_effective_permissions(
            iam_client,
            user,
            verbose,
            only_all_resources,
            risk_levels,
            group_memberships,
            lock,
        )
        if user_perms and user_perms.get("flagged_perms"):
            if user_permissions is not None:
                with lock:
                    user_permissions[user["Arn"]] = user_perms
            # Only check unused permissions if Access Analyzer is available
            if accessanalyzer and analyzer_arn:
                # Check if this user already has unused login/key findings
                with lock:
                    has_login = unused_logins.get(user["Arn"])
                    has_key = unused_acc_keys.get(user["Arn"])
                
                # Update permissions (quick dict write)
                if has_login:
                    with lock:
                        unused_logins[user["Arn"]]["permissions"] = user_perms
                elif has_key:
                    with lock:
                        unused_acc_keys[user["Arn"]]["permissions"] = user_perms
                else:
                    # Use pre-fetched findings if available
                    finding_ids = unused_permission_findings_map.get(user["Arn"], [])
                    if finding_ids:
                        process_unused_permissions_for_principal(
                            accessanalyzer,
                            analyzer_arn,
                            user["Arn"],
                            "user",
                            user_perms,
                            unused_perms,
                            lock,
                            verbose,
                            finding_ids,
                        )
            else:
                # No Access Analyzer: still report principals with flagged permissions.
                with lock:
                    unused_perms[user["Arn"]] = {
                        "type": "user",
                        "permissions": user_perms,
                    }
    except ClientError as e:
        if verbose:
            print(f"{colored('[-] ', 'yellow')}Error processing user {user['UserName']}: {e.response['Error']['Message']}")
    except Exception as e:
        if verbose:
            print(f"{colored('[-] ', 'red')}Error processing user {user['UserName']}: {str(e)}")

def check_group_permissions(
    group,
    iam_client,
    verbose,
    only_all_resources,
    accessanalyzer,
    analyzer_arn,
    unused_groups,
    unused_perms,
    lock,
    risk_levels,
    unused_permission_findings_map: dict = None,
):
    """Check permissions for a single group (thread-safe)"""
    if unused_permission_findings_map is None:
        unused_permission_findings_map = {}
    
    try:
        group_perms = get_policies(
            iam_client,
            "Group",
            group["GroupName"],
            group["Arn"],
            verbose,
            only_all_resources,
            risk_levels,
        )
        is_empty = is_group_empty(iam_client, group["GroupName"])
        
        # Quick dict write with lock (only if Access Analyzer is available)
        if is_empty and accessanalyzer:
            with lock:
                unused_groups[group["Arn"]] = {
                    "type": "group",
                    "n_days": -1,
                    "permissions": group_perms
                }
        
        if group_perms and group_perms.get("flagged_perms"):
            if accessanalyzer and analyzer_arn:
                # Use pre-fetched findings if available
                finding_ids = unused_permission_findings_map.get(group["Arn"], [])
                if finding_ids:
                    process_unused_permissions_for_principal(
                        accessanalyzer,
                        analyzer_arn,
                        group["Arn"],
                        "group",
                        group_perms,
                        unused_perms,
                        lock,
                        verbose,
                        finding_ids,
                    )
            else:
                with lock:
                    unused_perms[group["Arn"]] = {
                        "type": "group",
                        "permissions": group_perms,
                    }
    except ClientError as e:
        if verbose:
            print(f"{colored('[-] ', 'yellow')}Error processing group {group['GroupName']}: {e.response['Error']['Message']}")
    except Exception as e:
        if verbose:
            print(f"{colored('[-] ', 'red')}Error processing group {group['GroupName']}: {str(e)}")

def check_role_permissions(
    role,
    iam_client,
    verbose,
    only_all_resources,
    accessanalyzer,
    analyzer_arn,
    unused_roles,
    unused_perms,
    role_permissions,
    lock,
    risk_levels,
    unused_permission_findings_map: dict = None,
):
    """Check permissions for a single role (thread-safe)"""
    if unused_permission_findings_map is None:
        unused_permission_findings_map = {}
    
    try:
        role_perms = get_policies(
            iam_client,
            "Role",
            role["RoleName"],
            role["Arn"],
            verbose,
            only_all_resources,
            risk_levels,
        )
        if role_perms and role_perms.get("flagged_perms"):
            if role_permissions is not None:
                with lock:
                    role_permissions[role["Arn"]] = role_perms
            # Only check unused permissions if Access Analyzer is available
            if accessanalyzer and analyzer_arn:
                # Check if this role already has unused finding
                with lock:
                    has_unused = unused_roles.get(role["Arn"])
                
                # Update permissions (quick dict write)
                if has_unused:
                    with lock:
                        unused_roles[role["Arn"]]["permissions"] = role_perms
                else:
                    # Use pre-fetched findings if available
                    finding_ids = unused_permission_findings_map.get(role["Arn"], [])
                    if finding_ids:
                        process_unused_permissions_for_principal(
                            accessanalyzer,
                            analyzer_arn,
                            role["Arn"],
                            "role",
                            role_perms,
                            unused_perms,
                            lock,
                            verbose,
                            finding_ids,
                        )
            else:
                with lock:
                    unused_perms[role["Arn"]] = {
                        "type": "role",
                        "permissions": role_perms,
                    }
    except ClientError as e:
        if verbose:
            print(f"{colored('[-] ', 'yellow')}Error processing role {role['RoleName']}: {e.response['Error']['Message']}")
    except Exception as e:
        if verbose:
            print(f"{colored('[-] ', 'red')}Error processing role {role['RoleName']}: {str(e)}")


def process_account(
    profile_name,
    aws_access_key_id,
    aws_secret_access_key,
    aws_session_token,
    role_arn,
    verbose,
    no_access_analyzer,
    only_all_resources,
    max_perms_to_print,
    min_unused_days,
    risk_levels,
    *,
    progress_cb=None,
    show_progress=True,
):
    """Process a single AWS account. Returns (success, result, errors) tuple."""
    global MAX_PERMS_TO_PRINT
    
    # Per-account state
    UNUSED_ROLES = {}
    UNUSED_LOGINS = {}
    UNUSED_ACC_KEYS = {}
    UNUSED_PERMS = {}
    UNUSED_GROUPS = {}
    EXTERNAL_PPALS = {}
    UNUSED_CUSTOM_POLICIES = {}
    ALL_ACCESS_KEYS = {}
    EXTERNAL_TRUST_ROLES = {}
    USER_PERMISSIONS = {}
    ROLE_PERMISSIONS = {}
    USER_GROUP_MEMBERSHIPS = []
    
    # Track missing permissions for this account
    permission_errors = []
    
    # Initialize variables that might be used in cleanup
    created_analyzers = []
    accessanalyzer = None
    account_id = "unknown"
    
    try:
        # Create session
        if aws_access_key_id and aws_secret_access_key:
            session = boto3.Session(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                aws_session_token=aws_session_token
            )
        elif profile_name == "default":
            # Use default credential chain (env vars, EC2 metadata, etc.)
            session = boto3.Session()
        else:
            session = boto3.Session(profile_name=profile_name)
        
        # If role ARN specified, assume the role
        if role_arn:
            sts = session.client("sts", config=BOTO3_CONFIG)
            try:
                assumed_role = sts.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName="aws-iam-review-session"
                )
                session = boto3.Session(
                    aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
                    aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
                    aws_session_token=assumed_role['Credentials']['SessionToken']
                )
                profile_name = f"{profile_name} -> {role_arn}"
            except ClientError as e:
                return (False, None, [{"operation": "AssumeRole", "error": str(e), "role": role_arn}])
        
        # Create clients with retry config
        iam = session.client("iam", config=BOTO3_CONFIG)
        sts = session.client("sts", config=BOTO3_CONFIG)
        
        # Validate credentials and get account ID
        try:
            if progress_cb:
                progress_cb("identity")
            identity = sts.get_caller_identity()
            account_id = identity["Account"]
            caller_arn = identity["Arn"]
            caller_user_id = identity.get("UserId")
            caller_name = _principal_name_from_arn(caller_arn)
            caller_email = None
            if caller_arn and ":user/" in caller_arn and caller_name:
                try:
                    user_details = iam.get_user(UserName=caller_name).get("User", {})
                    caller_name = user_details.get("UserName") or caller_name
                except ClientError:
                    pass
                try:
                    tags = iam.list_user_tags(UserName=caller_name).get("Tags", [])
                    for tag in tags:
                        key = (tag.get("Key") or "").lower()
                        if key in ("email", "mail", "user_email"):
                            caller_email = tag.get("Value")
                            break
                except ClientError:
                    pass
            print(f"{colored('[+] ', 'green')}Analyzing account {account_id} ({profile_name})...")
            if verbose:
                print(f"{colored('[*] ', 'cyan')}Using credentials: {caller_arn}")
        except (NoCredentialsError, ClientError) as e:
            return (False, None, [{"operation": "GetCallerIdentity", "error": str(e)}])
        
        # Access Analyzer setup (optional)
        analyzer_arn = None
        analyzer_arn_exposed = None
        accessanalyzer = None
        created_analyzers = []
        
        if not no_access_analyzer:
            if progress_cb:
                progress_cb("access_analyzer")
            already_created_analyzers = True
            accessanalyzer = session.client("accessanalyzer", "us-east-1", config=BOTO3_CONFIG)

            # Try to create or find unused access analyzer
            try:
                analyzer_arn = accessanalyzer.create_analyzer(
                    analyzerName="iam_analyzer_unused", type="ACCOUNT_UNUSED_ACCESS", archiveRules=[]
                )["arn"]
                created_analyzers.append("iam_analyzer_unused")
                with _ALL_ANALYZERS_LOCK:
                    _ALL_ANALYZERS.append((accessanalyzer, "iam_analyzer_unused"))
                print(f"{colored('[+] ', 'green')}Analyzer iam_analyzer_unused created successfully.")
                already_created_analyzers = False
            except ClientError as e:
                code = (e.response or {}).get("Error", {}).get("Code")
                if code == "ResourceNotFoundException":
                    print(
                        f"{colored('[!] ', 'yellow')}IAM Access Analyzer not available in this account/region. Continuing without analyzer..."
                    )
                    permission_errors.append({"operation": "AccessAnalyzer", "error": "IAM Access Analyzer not available"})
                elif code in ["AccessDeniedException", "AccessDenied"]:
                    permission_errors.append({"operation": "CreateAnalyzer", "error": "Access denied to create analyzer"})
                if verbose:
                    print(f"{colored('[*] ', 'yellow')}Could not create analyzer: {e}")
                analyzer_arn = ""
                try:
                    analyzers = accessanalyzer.list_analyzers(type="ACCOUNT_UNUSED_ACCESS")
                    if analyzers.get("analyzers"):
                        analyzer_arn = analyzers["analyzers"][-1]["arn"]
                except ClientError as e2:
                    permission_errors.append({"operation": "ListAnalyzers", "error": str(e2)})

            # Try to create or find exposed assets analyzer
            try:
                analyzer_arn_exposed = accessanalyzer.create_analyzer(
                    analyzerName="iam_analyzer_exposed", type="ACCOUNT", archiveRules=[]
                )["arn"]
                created_analyzers.append("iam_analyzer_exposed")
                with _ALL_ANALYZERS_LOCK:
                    _ALL_ANALYZERS.append((accessanalyzer, "iam_analyzer_exposed"))
                print(f"{colored('[+] ', 'green')}Analyzer iam_analyzer_exposed created successfully.")
                already_created_analyzers = False
            except ClientError as e:
                code = (e.response or {}).get("Error", {}).get("Code")
                if code in ["AccessDeniedException", "AccessDenied"]:
                    permission_errors.append(
                        {"operation": "CreateExposedAnalyzer", "error": "Access denied to create exposed analyzer"}
                    )
                if verbose:
                    print(f"{colored('[*] ', 'yellow')}Could not create exposed analyzer: {e}")
                analyzer_arn_exposed = ""
                try:
                    analyzers = accessanalyzer.list_analyzers(type="ACCOUNT")
                    if analyzers.get("analyzers"):
                        analyzer_arn_exposed = analyzers["analyzers"][-1]["arn"]
                except ClientError as e2:
                    permission_errors.append({"operation": "ListExposedAnalyzers", "error": str(e2)})

            # Wait for analyzers if just created
            if not already_created_analyzers:
                print(f"{colored('[+] ', 'grey')}Waiting for analyzers to become active...")
                # Poll analyzer status instead of fixed sleep
                max_wait_seconds = 180  # 3 minutes max
                poll_interval = 10  # Check every 10 seconds
                start_time = time.time()
                
                analyzers_to_check = []
                if analyzer_arn:
                    analyzers_to_check.append(("iam_analyzer_unused", analyzer_arn))
                if analyzer_arn_exposed:
                    analyzers_to_check.append(("iam_analyzer_exposed", analyzer_arn_exposed))
                
                all_active = False
                while (time.time() - start_time) < max_wait_seconds and not all_active:
                    time.sleep(poll_interval)
                    all_active = True
                    for analyzer_name, analyzer_arn_to_check in analyzers_to_check:
                        try:
                            analyzer_info = accessanalyzer.get_analyzer(analyzerName=analyzer_name)
                            status = analyzer_info.get("analyzer", {}).get("status")
                            if status != "ACTIVE":
                                all_active = False
                                if verbose:
                                    print(f"{colored('[*] ', 'cyan')}Analyzer {analyzer_name} status: {status}")
                            elif verbose:
                                print(f"{colored('[+] ', 'green')}Analyzer {analyzer_name} is ACTIVE")
                        except Exception as e:
                            all_active = False
                            if verbose:
                                print(f"{colored('[-] ', 'yellow')}Error checking analyzer {analyzer_name}: {e}")
                
                if all_active:
                    elapsed = int(time.time() - start_time)
                    print(f"{colored('[+] ', 'green')}All analyzers are active (waited {elapsed}s)")
                else:
                    print(f"{colored('[!] ', 'yellow')}Timeout waiting for analyzers (waited {max_wait_seconds}s). Proceeding anyway...")


            if analyzer_arn or analyzer_arn_exposed:
                print(f"{colored('[+] ', 'green')}Fetching findings from analyzers...")

            # Fetch unused permission findings once (batch optimization)
            unused_permission_findings_map = {}
            if analyzer_arn:
                unused_permission_findings_map = get_all_unused_permissions(accessanalyzer, analyzer_arn, verbose)

            # Parallel fetch of analyzer findings (only if analyzers are available)
            if analyzer_arn or analyzer_arn_exposed:
                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                    futures_analyzer = []
                    if analyzer_arn_exposed:
                        futures_analyzer.append(
                            executor.submit(
                                get_external_principals,
                                accessanalyzer,
                                analyzer_arn_exposed,
                                EXTERNAL_PPALS,
                                verbose,
                            )
                        )
                    if analyzer_arn:
                        futures_analyzer.append(
                            executor.submit(get_unused_access_keys, accessanalyzer, analyzer_arn, UNUSED_ACC_KEYS, verbose)
                        )
                        futures_analyzer.append(
                            executor.submit(get_unused_logins, accessanalyzer, analyzer_arn, UNUSED_LOGINS, verbose)
                        )
                        futures_analyzer.append(
                            executor.submit(get_unused_roles, accessanalyzer, analyzer_arn, UNUSED_ROLES, verbose)
                        )

                    for fut in concurrent.futures.as_completed(futures_analyzer):
                        try:
                            fut.result()
                        except Exception as exc:
                            if verbose:
                                print(f"{colored('[-] ', 'red')}Analyzer error: {str(exc)}")
                            permission_errors.append({"operation": "AnalyzerFindings", "error": str(exc)})
        else:
            if progress_cb:
                progress_cb("no_access_analyzer")
            print(f"{colored('[*] ', 'yellow')}Access Analyzer disabled. Will only list principals and their sensitive permissions.")
            if only_all_resources:
                print(f"{colored('[*] ', 'yellow')}Filtering to permissions scoped to `Resource: *` only.")
            # Initialize empty map when Access Analyzer is disabled
            unused_permission_findings_map = {}

        # List customer-managed policies not attached anywhere (independent of Access Analyzer)
        try:
            if progress_cb:
                progress_cb("unused_policies")
            UNUSED_CUSTOM_POLICIES = get_unused_custom_policies(
                iam, only_all_resources, risk_levels, verbose=verbose
            )
        except Exception as e:
            permission_errors.append({"operation": "ListUnusedCustomerPolicies", "error": str(e)})

        # Get all users with pagination
        users = []
        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                users.extend(page.get("Users", []))
        except ClientError as e:
            print(f"{colored('[-] ', 'red')}Error listing users: {e.response['Error']['Message']}")
            permission_errors.append({"operation": "ListUsers", "error": e.response["Error"]["Message"]})

        lock = threading.Lock()

        # Check permissions for users in parallel
        if users:
            if progress_cb:
                progress_cb("users")
            # Enumerate all access keys (independent of Access Analyzer)
            try:
                ALL_ACCESS_KEYS = get_all_user_access_keys(iam, users, verbose=verbose)
            except Exception as e:
                permission_errors.append({"operation": "ListAllUserAccessKeys", "error": str(e)})

            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                progress_bar = tqdm(total=len(users), desc="Checking user permissions", disable=not show_progress)
                futures = [
                    executor.submit(
                        check_user_permissions,
                        user,
                        iam,
                        verbose,
                        only_all_resources,
                        accessanalyzer,
                        analyzer_arn,
                        UNUSED_LOGINS,
                        UNUSED_ACC_KEYS,
                        UNUSED_PERMS,
                        USER_PERMISSIONS,
                        USER_GROUP_MEMBERSHIPS,
                        lock,
                        risk_levels,
                        unused_permission_findings_map=unused_permission_findings_map,
                    )
                    for user in users
                ]
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if verbose:
                            print(f"{colored('[-] ', 'red')}Worker error: {str(e)}")
                        permission_errors.append({"operation": "CheckUserPermissions", "error": str(e)})
                    progress_bar.update(1)
                progress_bar.close()

        # Get all groups with pagination
        groups = []
        try:
            paginator = iam.get_paginator("list_groups")
            for page in paginator.paginate():
                groups.extend(page.get("Groups", []))
        except ClientError as e:
            print(f"{colored('[-] ', 'red')}Error listing groups: {e.response['Error']['Message']}")
            permission_errors.append({"operation": "ListGroups", "error": e.response["Error"]["Message"]})

        # Check permissions for groups in parallel
        if groups:
            if progress_cb:
                progress_cb("groups")
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                progress_bar = tqdm(total=len(groups), desc="Checking group permissions", disable=not show_progress)
                futures = [
                    executor.submit(
                        check_group_permissions,
                        group,
                        iam,
                        verbose,
                        only_all_resources,
                        accessanalyzer,
                        analyzer_arn,
                        UNUSED_GROUPS,
                        UNUSED_PERMS,
                        lock,
                        risk_levels,
                        unused_permission_findings_map=unused_permission_findings_map,
                    )
                    for group in groups
                ]
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if verbose:
                            print(f"{colored('[-] ', 'red')}Worker error: {str(e)}")
                        permission_errors.append({"operation": "CheckGroupPermissions", "error": str(e)})
                    progress_bar.update(1)
                progress_bar.close()

        # Get all roles with pagination
        roles = []
        try:
            paginator = iam.get_paginator("list_roles")
            for page in paginator.paginate():
                roles.extend(page.get("Roles", []))
        except ClientError as e:
            print(f"{colored('[-] ', 'red')}Error listing roles: {e.response['Error']['Message']}")
            permission_errors.append({"operation": "ListRoles", "error": e.response["Error"]["Message"]})

        # Detect externally-trustable roles (independent of Access Analyzer)
        try:
            EXTERNAL_TRUST_ROLES = find_external_trust_roles(roles, account_id)
        except Exception as e:
            permission_errors.append({"operation": "ExternalTrustRoles", "error": str(e)})

        # Check permissions for roles in parallel
        if roles:
            if progress_cb:
                progress_cb("roles")
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                progress_bar = tqdm(total=len(roles), desc="Checking role permissions", disable=not show_progress)
                futures = [
                    executor.submit(
                        check_role_permissions,
                        role,
                        iam,
                        verbose,
                        only_all_resources,
                        accessanalyzer,
                        analyzer_arn,
                        UNUSED_ROLES,
                        UNUSED_PERMS,
                        ROLE_PERMISSIONS,
                        lock,
                        risk_levels,
                        unused_permission_findings_map=unused_permission_findings_map,
                    )
                    for role in roles
                ]
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if verbose:
                            print(f"{colored('[-] ', 'red')}Worker error: {str(e)}")
                        permission_errors.append({"operation": "CheckRolePermissions", "error": str(e)})
                    progress_bar.update(1)
                progress_bar.close()

        print()

        if progress_cb:
            progress_cb("render")
        # Pass state variables directly to print_results
        result = print_results(
            account_id,
            profile_name,
            UNUSED_ROLES,
            UNUSED_LOGINS,
            UNUSED_ACC_KEYS,
            UNUSED_PERMS,
            UNUSED_GROUPS,
            EXTERNAL_PPALS,
            identity={
                "account": account_id,
                "arn": caller_arn,
                "user_id": caller_user_id,
                "name": caller_name,
                "email": caller_email,
            },
            unused_custom_policies=UNUSED_CUSTOM_POLICIES,
            all_access_keys=ALL_ACCESS_KEYS,
            external_trust_roles=EXTERNAL_TRUST_ROLES,
            access_analyzer_enabled=not no_access_analyzer,
            user_permissions=USER_PERMISSIONS,
            role_permissions=ROLE_PERMISSIONS,
            group_memberships=USER_GROUP_MEMBERSHIPS,
            min_unused_days=min_unused_days,
        )

        # Cleanup: Remove created analyzers
        for analyzer_name in created_analyzers:
            try:
                if accessanalyzer is not None:
                    accessanalyzer.delete_analyzer(analyzerName=analyzer_name)
                with _ALL_ANALYZERS_LOCK:
                    _ALL_ANALYZERS[:] = [
                        (client, name)
                        for client, name in _ALL_ANALYZERS
                        if not (client == accessanalyzer and name == analyzer_name)
                    ]
                print(f"{colored('[+] ', 'green')}Analyzer {analyzer_name} deleted successfully.")
            except Exception as e:
                if verbose:
                    print(f"{colored('[-] ', 'red')}Failed to delete analyzer {analyzer_name}: {str(e)}")

        # Add permission errors to result if any
        if permission_errors and result and isinstance(result, dict):
            result["permission_errors"] = permission_errors

        if progress_cb:
            progress_cb("done")
        return (True, result, permission_errors)
        
    except Exception as e:
        # Cleanup analyzers on error
        try:
            if accessanalyzer is not None and created_analyzers:
                for analyzer_name in created_analyzers:
                    try:
                        accessanalyzer.delete_analyzer(analyzerName=analyzer_name)
                        # Remove from global tracking (filter by both client and name)
                        with _ALL_ANALYZERS_LOCK:
                            _ALL_ANALYZERS[:] = [(client, name) for client, name in _ALL_ANALYZERS if not (client == accessanalyzer and name == analyzer_name)]
                    except:
                        pass
        except:
            pass
        
        error_msg = f"Error in account: {str(e)}"
        if verbose:
            traceback.print_exc()
        return (False, None, [{"operation": "General", "error": error_msg}])


def main(
    profiles,
    assume_roles,
    verbose,
    no_access_analyzer,
    only_all_resources,
    max_perms_to_print,
    min_unused_days,
    risk_levels,
    *,
    out_json_path=None,
):
    global MAX_PERMS_TO_PRINT

    if max_perms_to_print:
        MAX_PERMS_TO_PRINT = max_perms_to_print

    all_results = []
    all_errors = []  # Collect all errors across accounts

    # Prepare accounts to process
    accounts_to_process = []
    
    if assume_roles:
        # If --assume-roles specified, process those roles instead of current account
        for role_arn in assume_roles:
            profile_name, aws_access_key_id, aws_secret_access_key, aws_session_token = profiles[0]
            accounts_to_process.append((profile_name, aws_access_key_id, aws_secret_access_key, aws_session_token, role_arn))
    else:
        # Process the account of the credentials provided
        for profile_name, aws_access_key_id, aws_secret_access_key, aws_session_token in profiles:
            accounts_to_process.append((profile_name, aws_access_key_id, aws_secret_access_key, aws_session_token, None))
    
    # Process accounts in parallel:
    # - if --assume-roles is used, default cap is 5
    # - otherwise default cap is 10
    max_workers = max(1, int(args.max_parallel_accounts or 10))
    multi = len(accounts_to_process) > 1
    stage_progress = None
    slot_progress = None
    stages = [
        "identity",
        "access_analyzer",
        "no_access_analyzer",
        "unused_policies",
        "users",
        "groups",
        "roles",
        "render",
    ]
    if multi:
        stage_progress = StageProgress(
            total=len(accounts_to_process),
            desc="Analyzing accounts",
            unit="account",
            tqdm_factory=tqdm,
            stages=stages,
        )
        slot_progress = SlotStageProgress(
            max_slots=min(max_workers, len(accounts_to_process)),
            stages=stages,
            unit="account",
            enabled=True,
            position_offset=1,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(max_workers, len(accounts_to_process))) as executor:
        futures = []
        for idx, (profile_name, aws_access_key_id, aws_secret_access_key, aws_session_token, role_arn) in enumerate(accounts_to_process):
            def _worker(
                _idx=idx,
                _profile_name=profile_name,
                _aws_access_key_id=aws_access_key_id,
                _aws_secret_access_key=aws_secret_access_key,
                _aws_session_token=aws_session_token,
                _role_arn=role_arn,
            ):
                label = f"{_profile_name} -> {_role_arn}" if _role_arn else _profile_name
                _slot = slot_progress.acquire(label) if slot_progress else 0
                cb = stage_progress.make_callback(_idx) if stage_progress else None
                cb2 = (
                    slot_progress.make_callback(_slot, forward=cb)
                    if (slot_progress and cb)
                    else (slot_progress.make_callback(_slot) if slot_progress else cb)
                )
                try:
                    return process_account(
                        _profile_name,
                        _aws_access_key_id,
                        _aws_secret_access_key,
                        _aws_session_token,
                        _role_arn,
                        verbose,
                        no_access_analyzer,
                        only_all_resources,
                        max_perms_to_print,
                        min_unused_days,
                        risk_levels,
                        progress_cb=cb2,
                        show_progress=not multi,
                    )
                finally:
                    if slot_progress:
                        slot_progress.finish(_slot)
                        slot_progress.release(_slot)

            future = executor.submit(_worker)
            futures.append((idx, profile_name, role_arn, future))
        
        # Collect results as they complete
        for idx, profile_name, role_arn, future in futures:
            try:
                success, result, errors = future.result()
                if not success:
                    account_name = f"{profile_name} -> {role_arn}" if role_arn else profile_name
                    print(f"{colored('[-] ', 'red')}Failed to process account {account_name}")
                    if errors:
                        print(f"{colored('[*] ', 'yellow')}Permission errors encountered:")
                        for err in errors:
                            print(f"  - {err['operation']}: {err['error']}")
                    all_errors.extend(errors)
                elif result:
                    all_results.append(result)
                    if errors and verbose:
                        print(f"{colored('[*] ', 'yellow')}Some operations had permission errors (results may be incomplete)")
            except Exception as e:
                account_name = f"{profile_name} -> {role_arn}" if role_arn else profile_name
                print(f"{colored('[-] ', 'red')}Exception processing account {account_name}: {str(e)}")
                if verbose:
                    traceback.print_exc()
                all_errors.append({"account": account_name, "operation": "General", "error": str(e)})
            finally:
                if stage_progress:
                    stage_progress.finish(idx)

    if stage_progress:
        stage_progress.close()
    if slot_progress:
        slot_progress.close()


    if out_json_path:
        targets: list[dict] = []
        for r in all_results:
            if not isinstance(r, dict):
                continue
            account_id = r.get("account_id") or "unknown"
            profile = r.get("profile") or ""
            targets.append(
                Target(
                    target_type="account",
                    target_id=str(account_id),
                    label=str(profile) if profile else None,
                    data=normalize_aws_account(r),
                ).to_dict()
            )
        report = build_report(
            provider="aws",
            targets=targets,
            errors=all_errors or [],
            extra_summary={
                "total_accounts": len(accounts_to_process),
                "successful_accounts": len(all_results),
                "failed_accounts": len(accounts_to_process) - len(all_results),
            },
        )
        atomic_write_json(out_json_path, report)
    
    # Return success if at least one account was processed
    if not all_results and all_errors:
        sys.exit(1)


HELP = "Find AWS unused principals and permissions in one or several AWS accounts.\n"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=HELP)
    parser.add_argument("--profile", help="AWS profile to check")
    parser.add_argument("-v", "--verbose", default=False, help="Get info about why a permission is sensitive or useful for privilege escalation.", action="store_true")
    parser.add_argument("--no-access-analyzer", default=False, help="Disable AWS Access Analyzer (will not report unused resources/permissions, but will still list all principals and their sensitive permissions)", action="store_true")
    parser.add_argument(
        "--only-all-resources",
        default=False,
        help="Only consider permissions that apply to `Resource: *` (filters out resource-scoped statements).",
        action="store_true",
    )
    parser.add_argument("--risk-levels", default="high,critical", help="Comma-separated list of risk levels to flag (low,medium,high,critical). Default: high,critical")
    parser.add_argument("--max-perms-to-print", type=int, help="Maximum number of permissions to print per row", default=15)
    parser.add_argument("--min-unused-days", type=int, help="Minimum number of days a resource must be unused to be reported (default: 90)", default=90)
    parser.add_argument("--out-json", dest="out_json", help="Write full JSON results to this path (stdout stays human-readable).")
    parser.add_argument(
        "--max-parallel-accounts",
        type=int,
        default=10,
        help="Max accounts to analyze in parallel when multiple accounts are targeted (default: 10).",
    )
    
    
    # AWS credentials arguments
    parser.add_argument("--access-key-id", help="AWS Access Key ID (alternative to profile)")
    parser.add_argument("--secret-access-key", help="AWS Secret Access Key (required with --access-key-id)")
    parser.add_argument("--session-token", help="AWS Session Token (optional, for temporary credentials)")
    parser.add_argument(
        "--assume-roles",
        nargs="+",
        help="List of role ARNs to assume for multi-account analysis (space- or comma-separated)",
    )

    args = parser.parse_args()
    
    # Parse and validate risk levels
    valid_risk_levels = ['low', 'medium', 'high', 'critical']
    risk_levels = [r.strip().lower() for r in args.risk_levels.split(',')]
    for risk in risk_levels:
        if risk not in valid_risk_levels:
            print(f"{colored('[-] ', 'red')}Error: Invalid risk level '{risk}'. Valid values: {', '.join(valid_risk_levels)}")
            sys.exit(1)

    # Validate arguments
    if args.access_key_id and not args.secret_access_key:
        print(f"{colored('[-] ', 'red')}Error: --secret-access-key is required when using --access-key-id")
        sys.exit(1)
    
    if not args.access_key_id and args.secret_access_key:
        print(f"{colored('[-] ', 'red')}Error: --access-key-id is required when using --secret-access-key")
        sys.exit(1)
    
    if args.profile and args.access_key_id:
        print(f"{colored('[-] ', 'red')}Error: Provide either --profile OR credentials (--access-key-id), not both")
        sys.exit(1)
    
    # If no profile or credentials specified, use default credentials (env vars, EC2 metadata, etc.)
    use_default_credentials = not args.profile and not args.access_key_id

    # Use dummy profile name based on credential source
    if args.access_key_id:
        profiles = [("credentials", args.access_key_id, args.secret_access_key, args.session_token)]
    elif args.profile:
        profiles = [(args.profile, None, None, None)]
    elif use_default_credentials:
        profiles = [("default", None, None, None)]
    else:
        profiles = []
    
    # Handle --assume-roles (if specified, override profiles)
    assume_roles = []
    if hasattr(args, 'assume_roles') and args.assume_roles:
        # Support both:
        #   --assume-roles arn1 arn2
        # and:
        #   --assume-roles arn1,arn2
        expanded = []
        for item in args.assume_roles:
            if not isinstance(item, str):
                continue
            parts = [p.strip() for p in item.split(",")]
            expanded.extend([p for p in parts if p])
        assume_roles = expanded

        # Validate role ARNs format
        for role_arn in assume_roles:
            if not role_arn.startswith('arn:aws:iam::'):
                print(f"{colored('[-] ', 'red')}Error: Invalid role ARN format: {role_arn}")
                sys.exit(1)

    main(
        profiles,
        assume_roles,
        args.verbose,
        args.no_access_analyzer,
        args.only_all_resources,
        int(args.max_perms_to_print),
        int(args.min_unused_days),
        risk_levels,
        out_json_path=args.out_json,
    )
