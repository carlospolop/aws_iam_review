import os
import boto3
import yaml
import fnmatch
import argparse
import sys
import signal

import json
from termcolor import colored
from datetime import datetime, timezone
import pytz
from tqdm import tqdm
import threading
import concurrent.futures
import time
from botocore.config import Config
from botocore.exceptions import ClientError, NoCredentialsError



#########################
##### YAML SETTINGS #####
#########################

# Load YAML data with validation
try:
    if not os.path.exists("aws_permissions_cat.yaml"):
        print(f"{colored('[-] ', 'red')}Error: aws_permissions_cat.yaml file not found.")
        sys.exit(1)
    with open("aws_permissions_cat.yaml", "r") as file:
        PERMISSIONS_CAT_DATA = yaml.safe_load(file)
    if not PERMISSIONS_CAT_DATA or not isinstance(PERMISSIONS_CAT_DATA, dict):
        print(f"{colored('[-] ', 'red')}Error: aws_permissions_cat.yaml is empty or invalid.")
        sys.exit(1)
                
except yaml.YAMLError as e:
    print(f"{colored('[-] ', 'red')}Error parsing YAML file: {e}")
    sys.exit(1)


#########################
#### CACHE & CONFIG  ####
#########################
_POLICY_CACHE = {}  # Cache for AWS policy documents
_POLICY_CACHE_LOCK = threading.Lock()
READONLY_PERMS_CACHE = None  # Global cache for ReadOnly permissions

# Boto3 config with retries and connection pooling
BOTO3_CONFIG = Config(
    retries={'max_attempts': 3, 'mode': 'adaptive'},
    max_pool_connections=50
)

# Global tracking for analyzer cleanup on interrupt (for parallel processing)
_ALL_ANALYZERS = []  # List of (accessanalyzer_client, analyzer_name) tuples
_ALL_ANALYZERS_LOCK = threading.Lock()

MIN_UNUSED_DAYS = 30

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




def print_results(account_id, profile, unused_roles, unused_logins, unused_acc_keys, unused_perms, unused_groups, external_ppals, min_unused_days=30, json_output=False):
    """Print or return results for a single account."""
    # Return JSON if requested
    if json_output:
        return {
            "account_id": account_id,
            "profile": profile,
            "unused_roles": unused_roles,
            "unused_logins": unused_logins,
            "unused_access_keys": unused_acc_keys,
            "unused_permissions": unused_perms,
            "unused_groups": unused_groups,
            "external_principals": external_ppals
        }

    print(f"Interesting permissions in {colored(account_id, 'yellow')} ({colored(profile, 'blue')}): ")

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
        print(f"{colored('Principals with unused flagged permissions', 'yellow', attrs=['bold'])}:")
        for arn, data in unused_perms.items():
            is_external_str = " and is externally accessible" if external_ppals.get(arn) else ""

            if data['n_days'] == -1:
                print(f"  - `{arn}`: Never used{is_external_str}")
            else:
                print(f"  - `{arn}`: Last used {data['n_days']} days ago{is_external_str}")

            print_permissions(data["permissions"])

            print(f"    - {colored('Unused permissions', 'magenta')}:")
            for service in list(data['last_perms'].keys())[:4]:
                perms = data['last_perms'][service]

                str_srv = f"      - `{service}`: "
                if len(perms) == 1:
                    if perms['n_days'] == -1:
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
                        if details['n_days'] < min_unused_days and details['n_days'] >= 0:
                            continue

                        if details['n_days'] == -1:
                            print(f"        - `{service}:{perm}`: Never used")
                        else:
                            print(f"        - `{service}:{perm}`: Last used {details['n_days']} days ago")

                        i += 1
                        if i == 3:
                            print(f"        - Other {len(perms)-3} `{service}` permissions not used in too much time...")
                            break

            if len(list(data['last_perms'].keys())) > 4:
                oters_svcs_str = ", ".join("`"+s+"`" for s in list(data['last_perms'].keys())[4:])
                if oters_svcs_str:
                    print(f"        - It also has sensitive permissions in the services {oters_svcs_str} not used in too much time...")

            print()
            print()  # Here 2 prints to separate the different principals

    if external_ppals:
        print(f"{colored('Externally accessible principals', 'yellow', attrs=['bold'])}:")
        for arn, data in external_ppals.items():
            conditions_str = f" Conditions: {data['conditions']}" if data['conditions'] else ""

            print(f"  - `{arn}`: Accessible via `{data['action']}` from {data['access']}.{conditions_str}")
            print(f"    - Is public: {colored(data['is_public'], 'red') if data['is_public'] else colored(data['is_public'], 'green')}")
            print()

    print()


########################
## READ ONLY SETTINGS ##
########################

def get_readonly_perms(iam_client):
    """Get ReadOnly permissions from AWS managed policy (cached globally)"""
    global READONLY_PERMS_CACHE
    
    # Return cached value if available
    if READONLY_PERMS_CACHE is not None:
        return READONLY_PERMS_CACHE
    
    policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    
    try:
        policy = iam_client.get_policy(PolicyArn=policy_arn)
        policy_version_id = policy['Policy']['DefaultVersionId']
        
        policy_version = iam_client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=policy_version_id
        )
        
        perms = []
        for statement in policy_version['PolicyVersion']['Document']['Statement']:
            if statement['Effect'] != 'Allow':
                continue
            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            perms.extend(actions)
        
        READONLY_PERMS_CACHE = perms
        return perms
    except ClientError as e:
        print(f"{colored('[-] ', 'red')}Error fetching ReadOnly permissions: {e.response['Error']['Message']}")
        return []
    except Exception as e:
        print(f"{colored('[-] ', 'red')}Error fetching ReadOnly permissions: {str(e)}")
        return []


# Function to combine all permissions from policy documents
def combine_permissions(policy_documents, all_resources, all_actions, readonly_perms):
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
            if not all_resources:
                if isinstance(resource, str) and resource != "*" and not resource.endswith(":*"):
                    continue
                elif "*" not in resource and not any(r.endswith(":*") for r in resource):
                    continue

            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            if not all_actions and readonly_perms:
                actions = [a for a in actions if not any(fnmatch.fnmatch(a, p_pattern) for p_pattern in readonly_perms)]

            if actions:
                permissions.extend(actions)
    return permissions


# Function to check if a policy contains sensitive or privesc permissions
def check_policy(all_perm, risk_levels=None):
    global PERMISSIONS_CAT_DATA
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
    if all_perm and "*" in all_perm:
        flagged_perms['critical'] = ["*"]
        is_admin = True
        return {
            "flagged_perms": flagged_perms,
            "is_admin": is_admin
        }

    if not is_admin and all_perm:
        # Check permissions by risk level
        for risk_level in ['low', 'medium', 'high', 'critical']:
            if risk_level not in risk_levels:
                continue  # Skip risk levels not requested
                
            if risk_level in PERMISSIONS_CAT_DATA:
                for perm_pattern in PERMISSIONS_CAT_DATA[risk_level]:
                    # Handle comma-separated permissions (all must be present)
                    if "," in perm_pattern:
                        required_perms = [p.strip() for p in perm_pattern.split(",")]
                    else:
                        required_perms = [perm_pattern]

                    # Check if all required permissions match
                    if all(any(fnmatch.fnmatch(req_perm, p) for p in all_perm) for req_perm in required_perms):
                        if risk_level not in flagged_perms:
                            flagged_perms[risk_level] = []
                        flagged_perms[risk_level].extend(required_perms)
        
        # Deduplicate permissions within each risk level
        for risk_level in flagged_perms:
            flagged_perms[risk_level] = list(dict.fromkeys(flagged_perms[risk_level]))  # Preserves order

    return {
        "flagged_perms": flagged_perms,
        "is_admin": is_admin
    }



# Function to get inline and attached policies for a principal
def get_policies(iam_client, principal_type, principal_name, arn, verbose, all_resources, all_actions, readonly_perms, risk_levels):
    policy_document = []
    attached_policies = {}

    try:
        if principal_type == "User":
            attached_policies = iam_client.list_attached_user_policies(UserName=principal_name)
        elif principal_type == "Role":
            attached_policies = iam_client.list_attached_role_policies(RoleName=principal_name)
        elif principal_type == "Group":
            attached_policies = iam_client.list_attached_group_policies(GroupName=principal_name)
    except ClientError as e:
        if e.response['Error']['Code'] in ['AccessDenied', 'AccessDeniedException']:
            if verbose:
                print(f"{colored('[-] ', 'yellow')}Access denied listing policies for {principal_type} {principal_name}")
            return None
        raise

    for policy in attached_policies.get("AttachedPolicies", []):
        try:
            policy_arn = policy["PolicyArn"]
            
            # Check cache first
            with _POLICY_CACHE_LOCK:
                if policy_arn in _POLICY_CACHE:
                    policy_document.append(_POLICY_CACHE[policy_arn])
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

    inline_policies = {}
    try:
        if principal_type == "User":
            inline_policies = iam_client.list_user_policies(UserName=principal_name)
        elif principal_type == "Role":
            inline_policies = iam_client.list_role_policies(RoleName=principal_name)
        elif principal_type == "Group":
            inline_policies = iam_client.list_group_policies(GroupName=principal_name)
    except ClientError as e:
        if e.response['Error']['Code'] in ['AccessDenied', 'AccessDeniedException']:
            if verbose:
                print(f"{colored('[-] ', 'yellow')}Access denied listing inline policies for {principal_type} {principal_name}")
            return None
        raise

    for policy_name in inline_policies.get("PolicyNames", []):
        inlinepolicy = {}
        try:
            if principal_type == "User":
                inlinepolicy = iam_client.get_user_policy(UserName=principal_name, PolicyName=policy_name)
            elif principal_type == "Role":
                inlinepolicy = iam_client.get_role_policy(RoleName=principal_name, PolicyName=policy_name)
            elif principal_type == "Group":
                inlinepolicy = iam_client.get_group_policy(GroupName=principal_name, PolicyName=policy_name)

            if inlinepolicy:
                policy_document.append(inlinepolicy["PolicyDocument"])
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

    if policy_document:
        all_perm = combine_permissions(policy_document, all_resources, all_actions, readonly_perms)
        interesting_perms = check_policy(all_perm, risk_levels)
        return interesting_perms
    else:
        return None


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
                n_days = (datetime.now(pytz.utc) - last_accessed).days
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
                n_days = (datetime.now(pytz.utc) - last_accessed).days
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
                n_days = (datetime.now(pytz.utc) - last_accessed).days
            else:
                n_days = -1

            unused_acc_keys[finding["resource"]] = {
                "n_days": n_days
            }
        except Exception as e:
            if verbose:
                print(f"{colored('[-] ', 'red')}Error processing finding {finding['id']} for UnusedIAMUserAccessKey: {str(e)}")
            continue


# Get which permissions haven't been used in a long time
def get_unused_pers_of_ppal(accessanalyzer, analyzer_arn, arn, type_ppal, permissions_dict, unused_perms, lock, verbose):
    findings = []
    try:
        paginator = accessanalyzer.get_paginator('list_findings_v2')
        for page in paginator.paginate(analyzerArn=analyzer_arn, filter={'resource': {'eq': [arn]}, 'findingType': {'eq': ["UnusedPermission"]}}):
            findings.extend(page.get('findings', []))
    except ClientError as e:
        if verbose:
            print(f"{colored('[-] ', 'yellow')}Error fetching unused permissions for {arn}: {e.response['Error']['Message']}")
        return
    
    for finding in findings:
        try:
            # Check if not administrator
            if not permissions_dict.get("is_admin", False):
                details = accessanalyzer.get_finding_v2(analyzerArn=analyzer_arn, id=finding["id"])['findingDetails']
                last_perms = {}
                max_n_days = -1  # Track the maximum (oldest) n_days across all details

                for detail in details:
                    if 'lastAccessed' in detail['unusedPermissionDetails']:
                        last_accessed = detail['unusedPermissionDetails']['lastAccessed']
                        # Normalize naive datetime to UTC before subtraction
                        if last_accessed.tzinfo is None:
                            last_accessed = last_accessed.replace(tzinfo=timezone.utc)
                        detail_n_days = (datetime.now(pytz.utc) - last_accessed).days
                    else:
                        detail_n_days = -1
                    
                    # Track the maximum (oldest) days across all details
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
                                # Normalize naive datetime to UTC before subtraction
                                if perm_last_accessed.tzinfo is None:
                                    perm_last_accessed = perm_last_accessed.replace(tzinfo=timezone.utc)
                                perm_n_days = (datetime.now(pytz.utc) - perm_last_accessed).days
                            else:
                                perm_n_days = -1

                            if not any(fnmatch.fnmatch(f"{service_namespace}:{perm['action']}", p_pattern) for p_pattern in all_current_perms):
                                continue

                            last_perms[service_namespace][perm["action"]] = {
                                "n_days": perm_n_days
                            }

                # Protect dict write with lock (dict mutations aren't thread-safe)
                with lock:
                    unused_perms[arn] = {
                        "type": type_ppal,
                        "n_days": max_n_days,  # Use max (oldest) instead of last detail's value
                        "permissions": permissions_dict,
                        "last_perms": last_perms
                    }
        except Exception as e:
            if verbose:
                print(f"{colored('[-] ', 'red')}Error processing finding {finding['id']} for UnusedPermission: {str(e)}")
            continue


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


def check_user_permissions(user, iam_client, verbose, all_resources, all_actions, accessanalyzer, analyzer_arn, unused_logins, unused_acc_keys, unused_perms, lock, readonly_perms, risk_levels):
    """Check permissions for a single user (thread-safe)"""
    try:
        user_perms = get_policies(iam_client, "User", user["UserName"], user["Arn"], verbose, all_resources, all_actions, readonly_perms, risk_levels)
        if user_perms and user_perms.get("flagged_perms"):
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
                    # Network-heavy call outside lock for parallelism
                    get_unused_pers_of_ppal(accessanalyzer, analyzer_arn, user["Arn"], "user", user_perms, unused_perms, lock, verbose)
    except ClientError as e:
        if verbose:
            print(f"{colored('[-] ', 'yellow')}Error processing user {user['UserName']}: {e.response['Error']['Message']}")
    except Exception as e:
        if verbose:
            print(f"{colored('[-] ', 'red')}Error processing user {user['UserName']}: {str(e)}")

def check_group_permissions(group, iam_client, verbose, all_resources, all_actions, accessanalyzer, analyzer_arn, unused_groups, unused_perms, lock, readonly_perms, risk_levels):
    """Check permissions for a single group (thread-safe)"""
    try:
        group_perms = get_policies(iam_client, "Group", group["GroupName"], group["Arn"], verbose, all_resources, all_actions, readonly_perms, risk_levels)
        is_empty = is_group_empty(iam_client, group["GroupName"])
        
        # Quick dict write with lock (only if Access Analyzer is available)
        if is_empty and accessanalyzer:
            with lock:
                unused_groups[group["Arn"]] = {
                    "type": "group",
                    "n_days": -1,
                    "permissions": group_perms
                }
        
        # Network-heavy call outside lock for parallelism (only if Access Analyzer is available)
        if group_perms and group_perms.get("flagged_perms") and accessanalyzer and analyzer_arn:
            get_unused_pers_of_ppal(accessanalyzer, analyzer_arn, group["Arn"], "group", group_perms, unused_perms, lock, verbose)
    except ClientError as e:
        if verbose:
            print(f"{colored('[-] ', 'yellow')}Error processing group {group['GroupName']}: {e.response['Error']['Message']}")
    except Exception as e:
        if verbose:
            print(f"{colored('[-] ', 'red')}Error processing group {group['GroupName']}: {str(e)}")

def check_role_permissions(role, iam_client, verbose, all_resources, all_actions, accessanalyzer, analyzer_arn, unused_roles, unused_perms, lock, readonly_perms, risk_levels):
    """Check permissions for a single role (thread-safe)"""
    try:
        role_perms = get_policies(iam_client, "Role", role["RoleName"], role["Arn"], verbose, all_resources, all_actions, readonly_perms, risk_levels)
        if role_perms and role_perms.get("flagged_perms"):
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
                    # Network-heavy call outside lock for parallelism
                    get_unused_pers_of_ppal(accessanalyzer, analyzer_arn, role["Arn"], "role", role_perms, unused_perms, lock, verbose)
    except ClientError as e:
        if verbose:
            print(f"{colored('[-] ', 'yellow')}Error processing role {role['RoleName']}: {e.response['Error']['Message']}")
    except Exception as e:
        if verbose:
            print(f"{colored('[-] ', 'red')}Error processing role {role['RoleName']}: {str(e)}")


def process_account(profile_name, aws_access_key_id, aws_secret_access_key, aws_session_token, role_arn, verbose, no_access_analyzer, all_resources, all_actions, max_perms_to_print, min_unused_days, risk_levels, json_output=False):
    """Process a single AWS account. Returns (success, result, errors) tuple."""
    global MAX_PERMS_TO_PRINT
    
    # Per-account state
    UNUSED_ROLES = {}
    UNUSED_LOGINS = {}
    UNUSED_ACC_KEYS = {}
    UNUSED_PERMS = {}
    UNUSED_GROUPS = {}
    EXTERNAL_PPALS = {}
    
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
            identity = sts.get_caller_identity()
            account_id = identity["Account"]
            caller_arn = identity["Arn"]
            if not json_output:
                print(f"{colored('[+] ', 'green')}Analyzing account {account_id} ({profile_name})...")
                if verbose:
                    print(f"{colored('[*] ', 'cyan')}Using credentials: {caller_arn}")
        except (NoCredentialsError, ClientError) as e:
            return (False, None, [{"operation": "GetCallerIdentity", "error": str(e)}])
        
        # Get ReadOnly permissions once
        readonly_perms = get_readonly_perms(iam)
        if not readonly_perms and verbose:
            permission_errors.append({"operation": "GetReadOnlyPermissions", "error": "Failed to fetch ReadOnly policy"})
        
        # Access Analyzer setup (optional)
        analyzer_arn = None
        analyzer_arn_exposed = None
        accessanalyzer = None
        created_analyzers = []
        
        if not no_access_analyzer:
            already_created_analyzers = True
            accessanalyzer = session.client("accessanalyzer", "us-east-1", config=BOTO3_CONFIG)
            
            # Try to create or find unused access analyzer
            try:
                analyzer_arn = accessanalyzer.create_analyzer(analyzerName="iam_analyzer_unused", type='ACCOUNT_UNUSED_ACCESS', archiveRules=[])["arn"]
                created_analyzers.append("iam_analyzer_unused")
                # Register for global cleanup on interrupt
                with _ALL_ANALYZERS_LOCK:
                    _ALL_ANALYZERS.append((accessanalyzer, "iam_analyzer_unused"))
                if not json_output:
                    print(f"{colored('[+] ', 'green')}Analyzer iam_analyzer_unused created successfully.")
                already_created_analyzers = False
            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceNotFoundException':
                    if not json_output:
                        print(f"{colored('[!] ', 'yellow')}IAM Access Analyzer not available in this account/region. Continuing without analyzer...")
                    permission_errors.append({"operation": "AccessAnalyzer", "error": "IAM Access Analyzer not available"})
                elif e.response['Error']['Code'] in ['AccessDeniedException', 'AccessDenied']:
                    permission_errors.append({"operation": "CreateAnalyzer", "error": "Access denied to create analyzer"})
                # Try to find existing analyzer
                if verbose and not json_output:
                    print(f"{colored('[*] ', 'yellow')}Could not create analyzer: {e.response['Error']['Message']}")
                analyzer_arn = ""
                try:
                    analyzers = accessanalyzer.list_analyzers(type="ACCOUNT_UNUSED_ACCESS")
                    if 'analyzers' in analyzers and analyzers['analyzers']:
                        analyzer_arn = analyzers['analyzers'][-1]['arn']
                except ClientError as e:
                    permission_errors.append({"operation": "ListAnalyzers", "error": str(e)})

            # Try to create or find exposed assets analyzer
            try:
                analyzer_arn_exposed = accessanalyzer.create_analyzer(analyzerName="iam_analyzer_exposed", type='ACCOUNT', archiveRules=[])["arn"]
                created_analyzers.append("iam_analyzer_exposed")
                # Register for global cleanup on interrupt
                with _ALL_ANALYZERS_LOCK:
                    _ALL_ANALYZERS.append((accessanalyzer, "iam_analyzer_exposed"))
                if not json_output:
                    print(f"{colored('[+] ', 'green')}Analyzer iam_analyzer_exposed created successfully.")
                already_created_analyzers = False
            except ClientError as e:
                if e.response['Error']['Code'] in ['AccessDeniedException', 'AccessDenied']:
                    permission_errors.append({"operation": "CreateExposedAnalyzer", "error": "Access denied to create exposed analyzer"})
                if verbose and not json_output:
                    print(f"{colored('[*] ', 'yellow')}Could not create exposed analyzer: {e.response['Error']['Message']}")
                analyzer_arn_exposed = ""
                try:
                    analyzers = accessanalyzer.list_analyzers(type="ACCOUNT")
                    if 'analyzers' in analyzers and analyzers['analyzers']:
                        analyzer_arn_exposed = analyzers['analyzers'][-1]['arn']
                except ClientError as e:
                    permission_errors.append({"operation": "ListExposedAnalyzers", "error": str(e)})

            # Wait for analyzers if just created
            if not already_created_analyzers:
                if not json_output:
                    print(f"{colored('[+] ', 'grey')}Analyzers were just created. Waiting 3 minutes for them to analyze the account, don't stop the script...")
                sleep(60*3)

            if not json_output and (analyzer_arn or analyzer_arn_exposed):
                print(f"{colored('[+] ', 'green')}Fetching findings from analyzers...")
            
            # Parallel fetch of analyzer findings (only if analyzers are available)
            if analyzer_arn or analyzer_arn_exposed:
                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                    futures_analyzer = []
                    if analyzer_arn_exposed:
                        futures_analyzer.append(executor.submit(get_external_principals, accessanalyzer, analyzer_arn_exposed, EXTERNAL_PPALS, verbose))
                    if analyzer_arn:
                        futures_analyzer.append(executor.submit(get_unused_access_keys, accessanalyzer, analyzer_arn, UNUSED_ACC_KEYS, verbose))
                        futures_analyzer.append(executor.submit(get_unused_logins, accessanalyzer, analyzer_arn, UNUSED_LOGINS, verbose))
                        futures_analyzer.append(executor.submit(get_unused_roles, accessanalyzer, analyzer_arn, UNUSED_ROLES, verbose))
                    
                    # Wait for all analyzer futures to complete
                    for fut in concurrent.futures.as_completed(futures_analyzer):
                        try:
                            fut.result()
                        except Exception as e:
                            if verbose and not json_output:
                                print(f"{colored('[-] ', 'red')}Analyzer error: {str(e)}")
                            permission_errors.append({"operation": "AnalyzerFindings", "error": str(e)})
        else:
            if not json_output:
                print(f"{colored('[*] ', 'yellow')}Access Analyzer disabled. Will only list principals and their sensitive permissions.")

        # Get all users with pagination
        users = []
        try:
            paginator = iam.get_paginator('list_users')
            for page in paginator.paginate():
                users.extend(page.get('Users', []))
        except ClientError as e:
            if not json_output:
                print(f"{colored('[-] ', 'red')}Error listing users: {e.response['Error']['Message']}")
            permission_errors.append({"operation": "ListUsers", "error": e.response['Error']['Message']})
        
        # Check permissions for users in parallel
        lock = threading.Lock()
        if users:
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                progress_bar = tqdm(total=len(users), desc=f"Checking user permissions", disable=json_output)
                futures = [executor.submit(check_user_permissions, user, iam, verbose, all_resources, all_actions, accessanalyzer, analyzer_arn, UNUSED_LOGINS, UNUSED_ACC_KEYS, UNUSED_PERMS, lock, readonly_perms, risk_levels) for user in users]
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()  # Raise any exception from the worker
                    except Exception as e:
                        if verbose and not json_output:
                            print(f"{colored('[-] ', 'red')}Worker error: {str(e)}")
                        permission_errors.append({"operation": "CheckUserPermissions", "error": str(e)})
                    progress_bar.update(1)
                progress_bar.close()

        # Get all groups with pagination
        groups = []
        try:
            paginator = iam.get_paginator('list_groups')
            for page in paginator.paginate():
                groups.extend(page.get('Groups', []))
        except ClientError as e:
            if not json_output:
                print(f"{colored('[-] ', 'red')}Error listing groups: {e.response['Error']['Message']}")
            permission_errors.append({"operation": "ListGroups", "error": e.response['Error']['Message']})
        
        # Check permissions for groups in parallel
        if groups:
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                progress_bar = tqdm(total=len(groups), desc=f"Checking group permissions", disable=json_output)
                futures = [executor.submit(check_group_permissions, group, iam, verbose, all_resources, all_actions, accessanalyzer, analyzer_arn, UNUSED_GROUPS, UNUSED_PERMS, lock, readonly_perms, risk_levels) for group in groups]
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()  # Raise any exception from the worker
                    except Exception as e:
                        if verbose and not json_output:
                            print(f"{colored('[-] ', 'red')}Worker error: {str(e)}")
                        permission_errors.append({"operation": "CheckGroupPermissions", "error": str(e)})
                    progress_bar.update(1)
                progress_bar.close()

        # Get all roles with pagination
        roles = []
        try:
            paginator = iam.get_paginator('list_roles')
            for page in paginator.paginate():
                roles.extend(page.get('Roles', []))
        except ClientError as e:
            if not json_output:
                print(f"{colored('[-] ', 'red')}Error listing roles: {e.response['Error']['Message']}")
            permission_errors.append({"operation": "ListRoles", "error": e.response['Error']['Message']})
        
        # Check permissions for roles in parallel
        if roles:
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                progress_bar = tqdm(total=len(roles), desc=f"Checking role permissions", disable=json_output)
                futures = [executor.submit(check_role_permissions, role, iam, verbose, all_resources, all_actions, accessanalyzer, analyzer_arn, UNUSED_ROLES, UNUSED_PERMS, lock, readonly_perms, risk_levels) for role in roles]
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()  # Raise any exception from the worker
                    except Exception as e:
                        if verbose and not json_output:
                            print(f"{colored('[-] ', 'red')}Worker error: {str(e)}")
                        permission_errors.append({"operation": "CheckRolePermissions", "error": str(e)})
                    progress_bar.update(1)
                progress_bar.close()

        if not json_output:
            print()
        
        # Pass state variables directly to print_results (thread-safe)
        result = print_results(
            account_id, 
            profile_name, 
            UNUSED_ROLES,
            UNUSED_LOGINS,
            UNUSED_ACC_KEYS,
            UNUSED_PERMS,
            UNUSED_GROUPS,
            EXTERNAL_PPALS,
            min_unused_days=min_unused_days,
            json_output=json_output
        )
        
        # Cleanup: Remove created analyzers
        for analyzer_name in created_analyzers:
            try:
                accessanalyzer.delete_analyzer(analyzerName=analyzer_name)
                # Remove from global tracking (filter by both client and name)
                with _ALL_ANALYZERS_LOCK:
                    _ALL_ANALYZERS[:] = [(client, name) for client, name in _ALL_ANALYZERS if not (client == accessanalyzer and name == analyzer_name)]
                if not json_output:
                    print(f"{colored('[+] ', 'green')}Analyzer {analyzer_name} deleted successfully.")
            except Exception as e:
                if verbose and not json_output:
                    print(f"{colored('[-] ', 'red')}Failed to delete analyzer {analyzer_name}: {str(e)}")
        
        # Add permission errors to result if any
        if permission_errors and result and isinstance(result, dict):
            result['permission_errors'] = permission_errors
        
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


def main(profiles, assume_roles, verbose, no_access_analyzer, all_resources, all_actions, max_perms_to_print, min_unused_days, risk_levels, json_output=False):
    global MAX_PERMS_TO_PRINT

    if max_perms_to_print:
        MAX_PERMS_TO_PRINT = max_perms_to_print

    all_results = []  # Collect results for JSON output
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
    
    # Process accounts in parallel (max 10 accounts at a time)
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(10, len(accounts_to_process))) as executor:
        futures = []
        for profile_name, aws_access_key_id, aws_secret_access_key, aws_session_token, role_arn in accounts_to_process:
            future = executor.submit(
                process_account,
                profile_name,
                aws_access_key_id,
                aws_secret_access_key,
                aws_session_token,
                role_arn,
                verbose,
                no_access_analyzer,
                all_resources,
                all_actions,
                max_perms_to_print,
                min_unused_days,
                risk_levels,
                json_output
            )
            futures.append((profile_name, role_arn, future))
        
        # Collect results as they complete
        for profile_name, role_arn, future in futures:
            try:
                success, result, errors = future.result()
                if not success:
                    account_name = f"{profile_name} -> {role_arn}" if role_arn else profile_name
                    if not json_output:
                        print(f"{colored('[-] ', 'red')}Failed to process account {account_name}")
                        if errors:
                            print(f"{colored('[*] ', 'yellow')}Permission errors encountered:")
                            for err in errors:
                                print(f"  - {err['operation']}: {err['error']}")
                    all_errors.extend(errors)
                elif result:
                    all_results.append(result)
                    if errors and verbose and not json_output:
                        print(f"{colored('[*] ', 'yellow')}Some operations had permission errors (results may be incomplete)")
            except Exception as e:
                account_name = f"{profile_name} -> {role_arn}" if role_arn else profile_name
                if not json_output:
                    print(f"{colored('[-] ', 'red')}Exception processing account {account_name}: {str(e)}")
                    if verbose:
                        traceback.print_exc()
                all_errors.append({"account": account_name, "operation": "General", "error": str(e)})


    # Output JSON if requested
    if json_output:
        output = {
            "accounts": all_results,
            "summary": {
                "total_accounts": len(accounts_to_process),
                "successful_accounts": len(all_results),
                "failed_accounts": len(accounts_to_process) - len(all_results),
                "permission_errors": len(all_errors)
            }
        }
        if all_errors:
            output["errors"] = all_errors
        print(json.dumps(output, indent=2, default=str))
    
    # Return success if at least one account was processed
    if not all_results and all_errors:
        sys.exit(1)


HELP = "Find AWS unused sensitive permissions given to principals in the accounts of the specified profiles.\n"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=HELP)
    parser.add_argument("--profile", help="AWS profile to check")
    parser.add_argument("-v", "--verbose", default=False, help="Get info about why a permission is sensitive or useful for privilege escalation.", action="store_true")
    parser.add_argument("--no-access-analyzer", default=False, help="Disable AWS Access Analyzer (will not report unused resources/permissions, but will still list all principals and their sensitive permissions)", action="store_true")
    parser.add_argument("--all-resources", default=False, help="Do not filter only permissions over '*'", action="store_true")
    parser.add_argument("--risk-levels", default="high,critical", help="Comma-separated list of risk levels to flag (low,medium,high,critical). Default: high,critical")
    parser.add_argument("--all-actions", default=False, help="Do not filter permissions inside the readOnly policy", action="store_true")
    parser.add_argument("--max-perms-to-print", type=int, help="Maximum number of permissions to print per row", default=15)
    parser.add_argument("--min-unused-days", type=int, help="Minimum number of days a resource must be unused to be reported (default: 30)", default=30)
    parser.add_argument("--json", dest="json_output", default=False, action="store_true", help="Output results in JSON format")
    
    # AWS credentials arguments
    parser.add_argument("--access-key-id", help="AWS Access Key ID (alternative to profile)")
    parser.add_argument("--secret-access-key", help="AWS Secret Access Key (required with --access-key-id)")
    parser.add_argument("--session-token", help="AWS Session Token (optional, for temporary credentials)")
    parser.add_argument("--assume-roles", nargs="+", help="List of role ARNs to assume for multi-account analysis")

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
        assume_roles = args.assume_roles
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
        args.all_resources,
        args.all_actions,
        int(args.max_perms_to_print),
        int(args.min_unused_days),
        risk_levels,
        json_output=args.json_output if hasattr(args, 'json_output') else False
    )
