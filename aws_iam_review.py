import os
import boto3
import yaml
import fnmatch
import argparse
import tiktoken
from openai import OpenAI
import json
from termcolor import colored
from datetime import datetime, timezone
import pytz
from tqdm import tqdm
import threading
import concurrent.futures


#########################
##### YAML SETTINGS #####
#########################

# Load YAML data
with open("sensitive_permissions.yaml", "r") as file:
    PERMISSIONS_DATA = yaml.safe_load(file)


#########################
#### OPENAI SETTINGS ####
#########################
PERSONALITY = """You are an AWS security expert. You review policies searching for sensitive or privilege escalation permissions.
A privilege escalation permission or set of permissions, is a permissions that could allow the user to escalate to other AWS principal (user, group or role) in any way. For example, a user with permissions to create a new lambda with a role can escalate to that role. Or a user with permission to add users to other IAM groups can escalate to those groups.
Sensitive permissions are permissions that would allow a user to access sensitive data or perform sensitive actions. For example, a user with permissions to read secret manager or to modify infrastructure (create, update, delete...) could be considered sensitive permissions.
Your answer is always a valid JSON without any other thing (it should start with '{' and end with '}')."""

FINAL_CLARIFICATIONS = """Your response must be a valid JSON with the format specified before (it should start with '{' and end with '}')."""

PROMPT_ASK_PERMISSIONS = """An AWS principal has the permissions: __PERMISSIONS__

Check for privilege escalation and sensitive permissions and respond with a valid JSON with the following format:
{
    "privesc": ["permission1", "permission2"],
    "privesc_reasons": "Reason why it's possible to escalate privileges to other roles, users, groups... with these permissions",
    "sensitive": ["permission3", "permission4"],
    "sensitive_reasons": "Reason why the permissions are considered sensitive"
}

Do not return permissions that allow only with low probability the user to read sensitive information.
Give only the permissions that will allow the user to perform sensitive actions or that higly probable will allow the user to access sensitive information (like read bucket, secrets, code...).
Do not return as reason of sensitive permissions that there wasn't privilege escalation permissions.

If there aren't privilege escalation or sensitive permissions return an empty array for the permissions and an empty string for the reasons:
{
    "privesc": [],
    "privesc_reasons": "",
    "sensitive": [],
    "sensitive_reasons": ""
}
"""

PROMPT_CONFIRM_PERMISSIONS = """An AWS principal has the permissions: __PERMISSIONS__

You have previously been asked for privilege escalation and sensitive permissions.
Privilege escalation permissions allow to escalate to other AWS principal (user, group or role) or increase the current permissions.
Sensitive permissions allow to access sensitive data or perform sensitive actions (create, update, delete...).

From the previous permissions you responded that these are the privesc and sensitive ones:

__GIVEN_PERMISSIONS__

Please, re-evaluate the response and respond with a valid JSON with the following format with the privesc and sensitive permissions:

{
    "privesc": ["permission1", "permission2"],
    "privesc_reasons": "Reason why it's possible to escalate privileges to other roles, users, groups... with these permissions",
    "sensitive": ["permission3", "permission4"],
    "sensitive_reasons": "Reason why the permissions are considered sensitive"
}

If there aren't privilege escalation or sensitive permissions return an empty array for the permissions and an empty string for the reasons:
{
    "privesc": [],
    "privesc_reasons": "",
    "sensitive": [],
    "sensitive_reasons": ""
}
"""


MAX_PERMS_TO_PRINT = 15

OPENAI_CLIENT = None
READONLY_PERMS = []

UNUSED_ROLES = {}
UNUSED_LOGINS = {}
UNUSED_ACC_KEYS = {}
UNUSED_PERMS = {}
UNUSED_GROUPS = {}
EXTERNAL_PPALS = {}
SEMAPHORE_THREAD = threading.Semaphore()
IS_ADMINISTRATOR_REASON = "Is administrator"


def print_permissions(ppal_permissions, print_reasons, merge_perms):
    if merge_perms:
        ppal_permissions["known_privesc_perms"] = list(set(ppal_permissions["known_privesc_perms"] + ppal_permissions["ai_privesc_perms"]))
        ppal_permissions["known_sensitive_perms"] = list(set(ppal_permissions["known_sensitive_perms"] + ppal_permissions["ai_sensitive_perms"]))
        ppal_permissions['known_privesc_perms_reasons'] = ppal_permissions['known_privesc_perms_reasons'] + ". " + ppal_permissions['ai_privesc_perms_reasons']
        ppal_permissions['known_sensitive_perms_reasons'] = ppal_permissions['known_sensitive_perms_reasons'] + ". " + ppal_permissions['ai_sensitive_perms_reasons']

    if ppal_permissions["known_privesc_perms"]:
        more_than_str = " and more..." if len(ppal_permissions["known_privesc_perms"]) > MAX_PERMS_TO_PRINT else ""
        print(f"    - {colored('Privilege escalation', 'green')}: {', '.join(f"`{p}`" for p in ppal_permissions['known_privesc_perms'][:MAX_PERMS_TO_PRINT])}{more_than_str}")
        if print_reasons:
            print(f"    - Reasons: {ppal_permissions['known_privesc_perms_reasons']}")
    
    if ppal_permissions["known_sensitive_perms"]:
        more_than_str = " and more..." if len(ppal_permissions["known_sensitive_perms"]) > MAX_PERMS_TO_PRINT else ""
        print(f"    - {colored('Sensitive', 'blue')}: {', '.join(f"`{p}`" for p in ppal_permissions['known_sensitive_perms'][:MAX_PERMS_TO_PRINT])}{more_than_str}")
        if print_reasons:
            print(f"    - Reasons: {ppal_permissions['known_sensitive_perms_reasons']}")
    
    unknown_ai_permissions = [p for p in ppal_permissions["ai_privesc_perms"] if p not in ppal_permissions["known_privesc_perms"]]
    if unknown_ai_permissions:
        more_than_str = " and more..." if len(ppal_permissions["ai_privesc_perms"]) > MAX_PERMS_TO_PRINT else ""
        print(f"    - {colored('AI Privilege escalation', 'green')}: {', '.join(f"`{p}`" for p in unknown_ai_permissions[:MAX_PERMS_TO_PRINT])}{more_than_str}")
        if print_reasons:
            print(f"    - Reasons: {ppal_permissions['ai_privesc_perms_reasons']}")
    
    unknown_ai_permissions = [p for p in ppal_permissions["ai_sensitive_perms"] if p not in ppal_permissions["known_sensitive_perms"]]
    if unknown_ai_permissions:
        more_than_str = " and more..." if len(ppal_permissions["ai_sensitive_perms"]) > MAX_PERMS_TO_PRINT else ""
        print(f"    - {colored('AI Sensitive', 'blue')}: {', '.join(f"`{p}`" for p in unknown_ai_permissions[:MAX_PERMS_TO_PRINT])}{more_than_str}")
        if print_reasons:
            print(f"    - Reasons: {ppal_permissions['ai_sensitive_perms_reasons']}")


def print_results(account_id, profile, print_reasons, merge_perms):
    global UNUSED_ROLES, UNUSED_LOGINS, UNUSED_ACC_KEYS, UNUSED_PERMS, EXTERNAL_PPALS

    print(f"Interesting permissions in {colored(account_id, 'yellow')} ({colored(profile, 'blue')}): ")

    if UNUSED_ROLES:
        print(f"{colored('Unused roles with sensitive permissions', 'yellow', attrs=['bold'])}:")
        for arn, data in UNUSED_ROLES.items():
            is_external_str = " and is externally accessible" if EXTERNAL_PPALS.get(arn) else ""
            no_sensitive_perms = not data.get("permissions")
            
            if data['n_days'] == -1:
                intro_str = f"  - `{arn}`: Never used{is_external_str}"
            else:
                intro_str = f"  - `{arn}`: Last used {data['n_days']} days ago{is_external_str}"
            
            if no_sensitive_perms:
                intro_str += " (No sensitive permissions granted)"
            
            print(intro_str)

            if data.get("permissions"):
                print_permissions(data["permissions"], print_reasons, merge_perms)
            
            print()

    if UNUSED_LOGINS:
        print(f"{colored('Unused user logins with sensitive permissions', 'yellow', attrs=['bold'])}:")
        for arn, data in UNUSED_LOGINS.items():
            is_external_str = " and is externally accessible" if EXTERNAL_PPALS.get(arn) else ""
            no_sensitive_perms = not data.get("permissions")
            
            if data['n_days'] == -1:
                intro_str = f"  - `{arn}`: Never used{is_external_str}"
            else:
                intro_str = f"  - `{arn}`: Last used {data['n_days']} days ago{is_external_str}"
            
            if no_sensitive_perms:
                intro_str += " (No sensitive permissions granted)"
            
            print(intro_str)
            
            if data.get("permissions"):
                print_permissions(data["permissions"], print_reasons, merge_perms)
            
            print()

    if UNUSED_ACC_KEYS:
        print(f"{colored('Unused access keys with sensitive permissions', 'yellow', attrs=['bold'])}:")
        for arn, data in UNUSED_ACC_KEYS.items():
            is_external_str = " and is externally accessible" if EXTERNAL_PPALS.get(arn) else ""
            no_sensitive_perms = not data.get("permissions")
            
            if data['n_days'] == -1:
                intro_str = f"  - `{arn}`: Never used{is_external_str}"
            else:
                intro_str = f"  - `{arn}`: Last used {data['n_days']} days ago{is_external_str}"
            
            if no_sensitive_perms:
                intro_str += " (No sensitive permissions granted)"
            
            print(intro_str)
            
            if data.get("permissions"):
                print_permissions(data["permissions"], print_reasons, merge_perms)
                
            print()
    
    if UNUSED_GROUPS:
        print(f"{colored('Unused groups with sensitive permissions', 'yellow', attrs=['bold'])}:")
        for arn, data in UNUSED_GROUPS.items():
            is_external_str = " and is externally accessible" if EXTERNAL_PPALS.get(arn) else ""
            no_sensitive_perms = not data.get("permissions")

            if no_sensitive_perms:
                print(f"  - `{arn}`: Is empty{is_external_str} (No sensitive permissions granted)")
            else:
                print(f"  - `{arn}`: Never used{is_external_str}")
            
            if data.get("permissions"):
                print_permissions(data["permissions"], print_reasons, merge_perms)

            print()

    if UNUSED_PERMS:
        print(f"{colored('Principals with unused sensitive permissions', 'yellow', attrs=['bold'])}:")
        for arn, data in UNUSED_PERMS.items():
            is_external_str = " and is externally accessible" if EXTERNAL_PPALS.get(arn) else ""

            if data['n_days'] == -1:
                print(f"  - `{arn}`: Never used{is_external_str}")
            else:
                print(f"  - `{arn}`: {data['n_days']} days ago{is_external_str}")
            
            print_permissions(data["permissions"], print_reasons, merge_perms)
            
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
            print() # Here 2 prints to separate the different principals
    
    if EXTERNAL_PPALS:
        print(f"{colored('Externally accessible principals', 'yellow', attrs=['bold'])}:")
        for arn, data in EXTERNAL_PPALS.items():
            conditions_str = f" Conditions: {data['conditions']}" if data['conditions'] else ""
            
            print(f"  - `{arn}`: Accesible via `{data['action']}` from {data['access']}.{conditions_str}")
            print(f"    - Is public: {colored(data['is_public'], "red") if data['is_public'] else colored(data['is_public'], "green")}")
            print()

    print()


def get_len_tokens(prompt, model="gpt-4"):
    encoding = tiktoken.encoding_for_model(model)
    return len(encoding.encode(prompt))

def remove_fences(text: str) -> str:
    """Function that removes code fences from the response"""

    text = text.strip()
    if len(text.split("```")) == 3:
        text = "\n".join(text.split("```")[1].split("\n")[1:])
    
    elif len(text.split("```")) > 3:
        if text.startswith("```"):
            text = "\n".join(text.split("\n")[1:])
        if text.endswith("```"):
            text = "\n".join(text.split("\n")[:-1])
            
    return text


def fix_json(orig_text: str, orig_response: str, json_error: str) -> str:
    """Function that asks to fix a given json"""

    all_msg = f"{orig_text}\n\n You already gave this reponse:\n{orig_response}\n\nWhich resulted in this error:\n{json_error}\n\nPlease fix it and respond with a valid json."
    response = contact(all_msg)
    return response

# Ask OpenAI
def contact(prompt: str, p_info_msg: bool = True, model: str = "gpt-4o") -> str:
    """Function that asks the model"""

    global OPENAI_CLIENT

    if get_len_tokens(prompt) > 50000:
        print(f"{colored('[-] ', 'red')}Too many permissions.")
        return None

    messages = [
        {"role": "system", "content": PERSONALITY},
        {"role": "user", "content": prompt},
        {"role": "system", "content": FINAL_CLARIFICATIONS}
    ]

    try:
        response = OPENAI_CLIENT.chat.completions.create(
            model=model,
            messages=messages,
            temperature=0
        )
    except Exception as e:
        print(f"{colored('[-] Error contacting OpenAI: ', 'yellow')}" + str(e))
        return None

    all_text = response.choices[0].message.content

    all_text = remove_fences(all_text)
    try:
        json_text = json.loads(all_text)
    except json.decoder.JSONDecodeError as e:
        json_text = fix_json(prompt, all_text, str(e))

    return json_text


########################
## READ ONLY SETTINGS ##
########################

def get_readonly_perms(profile):
    global READONLY_PERMS
    
    # Get the policy ARN for the ReadOnly managed policy
    # Note: For AWS managed policies, the ARN pattern is arn:aws:iam::aws:policy/ReadOnlyAccess
    policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"

    session = boto3.Session(profile_name=profile)
    iam = session.client("iam")

    # Retrieve the policy details
    policy = iam.get_policy(PolicyArn=policy_arn)
    policy_version_id = policy['Policy']['DefaultVersionId']

    # Retrieve the policy document
    policy_version = iam.get_policy_version(
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

    READONLY_PERMS = perms

# Function to combine all permissions from policy documents
def combine_permissions(policy_documents, all_resources, all_actions):
    global READONLY_PERMS

    permissions = []
    for document in policy_documents:
        if type(document["Statement"]) == list:
            statements = document["Statement"]
        else:
            statements = []
            statements.append(document["Statement"])
        for statement in statements:
            resource = statement.get("Resource", [])
            if not all_resources:
                if type(resource) == str and resource != "*" and not resource.endswith(":*"):
                    continue
                elif "*" not in resource and not any(r.endswith(":*") for r in resource):
                    continue
            
            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            
            if not all_actions:
                actions = [a for a in actions if not any(fnmatch.fnmatch(a, p_pattern) for p_pattern in READONLY_PERMS)]
            
            if actions:
                permissions.extend(actions)
    return permissions

# Function to check if a policy contains sensitive or privesc permissions
def check_policy(all_perm, arn, api_key, verbose, only_yaml, only_openai):
    global PERMISSIONS_DATA
    if not all_perm:
        return
    
    all_privesc_perms = []
    all_sensitive_perms = []
    all_privesc_perms_reasons = ""
    all_sensitive_perms_reasons = ""
    all_privesc_perms_ai = []
    all_sensitive_perms_ai = []
    all_privesc_perms_ai_reasons = ""
    all_sensitive_perms_ai_reasons = ""
    is_admin = False

    if all_perm and "*" in all_perm:
        all_privesc_perms = ["*"]
        all_privesc_perms_reasons = IS_ADMINISTRATOR_REASON
        is_admin = True
        # Just return from here

    if not is_admin and all_perm:

        # Check yaml permissions
        if only_yaml or not only_openai:
            for aws_svc, permissions in PERMISSIONS_DATA.items():
                for perm_type in ["privesc", "sensitive"]:
                    if perm_type in permissions:
                        
                        for perm in permissions[perm_type]:
                            if "," in perm:
                                required_perms = perm.replace(" ", "").split(",")
                            else:
                                required_perms = [perm]
                            
                            if any(
                                    all(fnmatch.fnmatch(p, p_pattern) for p in required_perms)
                                for p_pattern in all_perm):
                                
                                if perm_type == "privesc":
                                    all_privesc_perms.extend(required_perms)
                                    all_privesc_perms_reasons += ", ".join(permissions["urls"])
                                elif perm_type == "sensitive":
                                    all_sensitive_perms.extend(required_perms)
                                    all_sensitive_perms_reasons += ", ".join(permissions["urls"])

        # Check permissions with OpenAI
        if only_openai or not only_yaml:
            if api_key:
                all_perm_str = ", ".join(all_perm)
                prompt = PROMPT_ASK_PERMISSIONS.replace("__PERMISSIONS__", all_perm_str)
                response = contact(prompt)
                if response:
                    if response["privesc"] or response["sensitive"]:
                        prompt = PROMPT_CONFIRM_PERMISSIONS.replace("__PERMISSIONS__", all_perm_str).replace("__GIVEN_PERMISSIONS__", json.dumps(response, indent=4))
                        response = contact(prompt)
                        if "privesc" in response:
                            all_privesc_perms_ai.extend(response["privesc"])
                            all_privesc_perms_ai_reasons = response["privesc_reasons"]
                        if "sensitive" in response:
                            all_sensitive_perms_ai.extend(response["sensitive"])
                            all_sensitive_perms_ai_reasons = response["sensitive_reasons"]
    
    return {
        "known_privesc_perms": all_privesc_perms,
        "known_sensitive_perms": all_sensitive_perms,
        "known_privesc_perms_reasons": all_privesc_perms_reasons if all_privesc_perms_reasons else all_sensitive_perms_reasons,
        "known_sensitive_perms_reasons": all_sensitive_perms_reasons if all_sensitive_perms_reasons else all_privesc_perms_reasons,

        "ai_privesc_perms": all_privesc_perms_ai,
        "ai_sensitive_perms": all_sensitive_perms_ai,
        "ai_privesc_perms_reasons": all_privesc_perms_ai_reasons,
        "ai_sensitive_perms_reasons": all_sensitive_perms_ai_reasons
    }


# Function to get inline and attached policies for a principal
def get_policies(principal_type, principal_name, arn, api_key, verbose, only_yaml, only_openai, all_resources, all_actions):
    policy_document = []

    if principal_type == "User":
        attached_policies = iam.list_attached_user_policies(UserName=principal_name)
    elif principal_type == "Role":
        attached_policies = iam.list_attached_role_policies(RoleName=principal_name)
    elif principal_type == "Group":
        attached_policies = iam.list_attached_group_policies(GroupName=principal_name)

    for policy in attached_policies["AttachedPolicies"]:
        policy_data = iam.get_policy(PolicyArn=policy["PolicyArn"])
        policy_version = iam.get_policy_version(
            PolicyArn=policy["PolicyArn"], VersionId=policy_data["Policy"]["DefaultVersionId"]
        )
        policy_document.append(policy_version["PolicyVersion"]["Document"])


    if principal_type == "User":
        inline_policies = iam.list_user_policies(UserName=principal_name)
    elif principal_type == "Role":
        inline_policies = iam.list_role_policies(RoleName=principal_name)
    elif principal_type == "Group":
        inline_policies = iam.list_group_policies(GroupName=principal_name)


    for policy_name in inline_policies.get("PolicyNames", []):
        if principal_type == "User":
            inlinepolicy = iam.get_user_policy(UserName=principal_name, PolicyName=policy_name)
        elif principal_type == "Role":
            inlinepolicy = iam.get_role_policy(RoleName=principal_name, PolicyName=policy_name)
        elif principal_type == "Group":
            inlinepolicy = iam.get_group_policy(GroupName=principal_name, PolicyName=policy_name)
        
        policy_document.append(inlinepolicy["PolicyDocument"])

    if policy_document:
        all_perm = combine_permissions(policy_document, all_resources, all_actions)
        interesting_perms = check_policy(all_perm, arn, api_key, verbose, only_yaml, only_openai)
        return interesting_perms
    else:
        return None

def is_group_empty(iam_client, group_name):
    """
    Check if an IAM group is empty (no users attached).

    :param group_name: str, the name of the IAM group to check.
    :return: bool, True if the group is empty, False otherwise.
    """
    # List users in the specified IAM group
    try:
        response = iam_client.get_group(GroupName=group_name)
        users = response['Users']
        if not users:
            return True
        else:
            return False
    except Exception as e:
        return False


# Get all unused roles
def get_unused_roles(accessanalyzer, analyzer_arn):
    global UNUSED_ROLES

    findings = accessanalyzer.list_findings_v2(analyzerArn=analyzer_arn, filter={'findingType': {'eq': ['UnusedIAMRole']}})["findings"]
    for finding in findings:
        details = accessanalyzer.get_finding_v2(analyzerArn=analyzer_arn, id=finding["id"])['findingDetails'][0]['unusedIamRoleDetails']
        if 'lastAccessed' in details:
            n_days = (datetime.now(pytz.utc) - details['lastAccessed'].replace(tzinfo=timezone.utc)).days
        else:
            n_days = -1

        UNUSED_ROLES[finding["resource"]] = {
            "n_days": n_days
        }

# Get all unused logins
def get_unused_logins(accessanalyzer, analyzer_arn):
    global UNUSED_LOGINS

    findings = accessanalyzer.list_findings_v2(analyzerArn=analyzer_arn, filter={'findingType': {'eq': ['UnusedIAMUserPassword']}})["findings"]
    for finding in findings:
        details = accessanalyzer.get_finding_v2(analyzerArn=analyzer_arn, id=finding["id"])['findingDetails'][0]['unusedIamUserPasswordDetails']
        if 'lastAccessed' in details:
            n_days = (datetime.now(pytz.utc) - details['lastAccessed'].replace(tzinfo=timezone.utc)).days
        else:
            n_days = -1

        UNUSED_LOGINS[finding["resource"]] = {
            "n_days": n_days
        }

# Get all unused access keys
def get_unused_access_keys(accessanalyzer, analyzer_arn):
    global UNUSED_ACC_KEYS

    findings = accessanalyzer.list_findings_v2(analyzerArn=analyzer_arn, filter={'findingType': {'eq': ['UnusedIAMUserAccessKey']}})["findings"]
    for finding in findings:
        details = accessanalyzer.get_finding_v2(analyzerArn=analyzer_arn, id=finding["id"])['findingDetails'][0]['unusedIamUserAccessKeyDetails']
        if 'lastAccessed' in details:
            n_days = (datetime.now(pytz.utc) - details['lastAccessed'].replace(tzinfo=timezone.utc)).days
        else:
            n_days = -1

        UNUSED_ACC_KEYS[finding["resource"]] = {
            "n_days": n_days
        }

# Get which permissions haven't been used in a long time
def get_unused_pers_of_ppal(accessanalyzer, analyzer_arn, arn, type_ppal, permissions_dict):
    global UNUSED_PERMS

    findings = accessanalyzer.list_findings_v2(analyzerArn=analyzer_arn, filter={'resource': {'eq': [arn]}, 'findingType': {'eq': ["UnusedPermission"]}})["findings"]
    for finding in findings:    
        if permissions_dict["known_privesc_perms_reasons"] != IS_ADMINISTRATOR_REASON:
            details = accessanalyzer.get_finding_v2(analyzerArn=analyzer_arn, id=finding["id"])['findingDetails']
            last_perms = {}

            for detail in details:
                if 'lastAccessed' in detail['unusedPermissionDetails']:
                    n_days = (datetime.now(pytz.utc) - detail['unusedPermissionDetails']['lastAccessed']).days
                else:
                    n_days = -1
                
                service_namespace = detail['unusedPermissionDetails']['serviceNamespace']

                all_current_perms = permissions_dict["known_privesc_perms"] + permissions_dict["known_sensitive_perms"] + permissions_dict["ai_privesc_perms"] + permissions_dict["ai_sensitive_perms"]
                
                # If the affected namespace is not in the permissions, skip
                if not any(fnmatch.fnmatch(service_namespace, p.split(":")[0]) for p in all_current_perms):
                    continue
                
                last_perms[service_namespace] = {
                    "n_days": n_days
                }

                if 'actions' in detail['unusedPermissionDetails']:
                    for perm in detail['unusedPermissionDetails']['actions']:
                        if 'lastAccessed' in perm:
                            n_days = (datetime.now(pytz.utc) - perm['lastAccessed']).days
                        else:
                            n_days = -1
                        
                        if not any(fnmatch.fnmatch(service_namespace+":"+perm["action"], p_pattern) for p_pattern in all_current_perms):
                            continue
                        
                        last_perms[service_namespace][perm["action"]] = {
                            "n_days": n_days
                        }

            UNUSED_PERMS[arn] = {
                "type": type_ppal,
                "n_days": n_days,
                "permissions": permissions_dict,
                "last_perms": last_perms
            }

def get_external_principals(accessanalyzer, analyzer_arn_exposed):
    global EXTERNAL_PPALS

    findings = accessanalyzer.list_findings_v2(analyzerArn=analyzer_arn_exposed, filter={'resourceType': {'eq': ['AWS::IAM::Role']}})["findings"]
    for finding in findings:
        if finding["findingType"] != "ExternalAccess":
            print(f"{colored('[-] ', 'red')}Unknown external finding type: {finding['findingType']}")
            return

        arn = finding["resource"]

        details = accessanalyzer.get_finding_v2(analyzerArn=analyzer_arn_exposed, id=finding["id"])['findingDetails'][0]['externalAccessDetails']
        EXTERNAL_PPALS[arn] = {
            "is_public": details["isPublic"],
            "action": ", ".join(details["action"]),
            "access": " AND ".join([f'{k}: `{v}`' for k,v in details["principal"].items()]),
            "conditions": " AND ".join([f'`{k} == {v}`' for k,v in details["condition"].items()])
        }


def check_role_permissions(role, api_key, verbose, only_yaml, only_openai, all_resources, all_actions, accessanalyzer, analyzer_arn):
    global SEMAPHORE_THREAD, UNUSED_ROLES

    try:
        role_perms = get_policies("Role", role["RoleName"], role["Arn"], api_key, verbose, only_yaml, only_openai, all_resources, all_actions)
        if role_perms and any(v for v in role_perms.values()):
            SEMAPHORE_THREAD.acquire()  # Acquire semaphore before modifying shared resources
            try:
                if UNUSED_ROLES.get(role["Arn"]):
                    UNUSED_ROLES[role["Arn"]]["permissions"] = role_perms
                else:
                    get_unused_pers_of_ppal(accessanalyzer, analyzer_arn, role["Arn"], "role", role_perms)
            finally:
                SEMAPHORE_THREAD.release()  # Always release semaphore
    except Exception as e:
        print(f"Error processing role {role['RoleName']}: {str(e)}")



def main(profiles, api_key, verbose, only_yaml, only_openai, all_resources, print_reasons, all_actions, merge_perms, max_perms_to_print):
    global OPENAI_CLIENT, UNUSED_GROUPS, UNUSED_LOGINS, UNUSED_ACC_KEYS, UNUSED_ROLES, MAX_PERMS_TO_PRINT

    if max_perms_to_print:
        MAX_PERMS_TO_PRINT = max_perms_to_print

    if not api_key:
        api_key = os.getenv("OPENAI_API_KEY")
    
    if not api_key:
        print(f"{colored('[-] ', 'red')}No OpenAI API key specified.")
        if only_openai:
            print(f"{colored('[-] ', 'red')} Only OpenAI was specified without key. Exiting...")
    else:
        OPENAI_CLIENT = OpenAI(api_key=api_key)
    
    # Get the permissions from the ReadOnly managed policy to remove them from the analysis
    get_readonly_perms(profiles[0])

    for profile in profiles:
        # Share the boto3 client with other functions
        session = boto3.Session(profile_name=profile)
        global iam
        iam = session.client("iam")

        # Get the account ID
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]

        # Get unused annalizer
        created_analyzers = []
        accessanalyzer = session.client("accessanalyzer", "us-east-1")
        try:
            analyzer_arn = accessanalyzer.create_analyzer(analyzerName="iam_analyzer_unused",type='ACCOUNT_UNUSED_ACCESS',archiveRules=[])["arn"]
            created_analyzers.append("iam_analyzer_unused")
        except Exception as e:
            analyzer_arn = ""
            analyzers = accessanalyzer.list_analyzers(type="ACCOUNT_UNUSED_ACCESS")
            if 'analyzers' in analyzers:
                analyzers = analyzers['analyzers']
                if len(analyzers) > 0:
                    analyzer_arn = analyzers[-1]['arn']
            if not analyzer_arn:
                print(f"{colored('[-] ', 'red')}No analyzer found.")
                return
        
        # Get exposed assets analyzer
        try:
            analyzer_arn_exposed = accessanalyzer.create_analyzer(analyzerName="iam_analyzer_exposed",type='ACCOUNT',archiveRules=[])["arn"]
            created_analyzers.append("iam_analyzer_exposed")
        except Exception as e:
            analyzer_arn_exposed = ""
            analyzers = accessanalyzer.list_analyzers(type="ACCOUNT")
            if 'analyzers' in analyzers:
                analyzers = analyzers['analyzers']
                if len(analyzers) > 0:
                    analyzer_arn_exposed = analyzers[-1]['arn']
            if not analyzer_arn_exposed:
                print(f"{colored('[-] ', 'red')}No exposed analyzer found.")
                return
        
        try:
            # Get extrernal and unused ppals
            get_external_principals(accessanalyzer, analyzer_arn_exposed)
            get_unused_access_keys(accessanalyzer, analyzer_arn)
            get_unused_logins(accessanalyzer, analyzer_arn)
            get_unused_roles(accessanalyzer, analyzer_arn)

            # Check permissions for users
            users = iam.list_users()["Users"]
            for user in tqdm(users, desc=f"Checking user permissions in account {account_id} ({profile})"):
                user_perms = get_policies("User", user["UserName"], user["Arn"], api_key, verbose, only_yaml, only_openai, all_resources, all_actions)
                if user_perms and any(v for v in user_perms.values()):
                    if UNUSED_LOGINS.get(user["Arn"]):
                        UNUSED_LOGINS[user["Arn"]]["permissions"] = user_perms
                    elif UNUSED_ACC_KEYS.get(user["Arn"]):
                        UNUSED_ACC_KEYS[user["Arn"]]["permissions"] = user_perms
                    else:
                        get_unused_pers_of_ppal(accessanalyzer, analyzer_arn, user["Arn"], "user", user_perms)

            # Check permissions for groups
            groups = iam.list_groups()["Groups"]
            for group in tqdm(groups, desc=f"Checking group permissions in account {account_id} ({profile})"):
                group_perms = get_policies("Group", group["GroupName"], group["Arn"], api_key, verbose, only_yaml, only_openai, all_resources, all_actions)
                is_empty = is_group_empty(iam, group["GroupName"])
                if is_empty:
                        UNUSED_GROUPS[group["Arn"]] = {
                            "type": "group",
                            "n_days": -1, # Never used
                            "permissions": group_perms
                        }
                
                if group_perms and any(v for v in group_perms.values()):
                    get_unused_pers_of_ppal(accessanalyzer, analyzer_arn, group["Arn"], "group", group_perms)

            # Check permissions for roles
            roles = iam.list_roles()["Roles"]
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                # Create tqdm instance with the total count of tasks to be executed
                progress_bar = tqdm(total=len(roles), desc=f"Checking role permissions in account {account_id} ({profile})")
                futures = {executor.submit(check_role_permissions, role, api_key, verbose, only_yaml, only_openai, all_resources, all_actions, accessanalyzer, analyzer_arn): role for role in roles}
                for future in concurrent.futures.as_completed(futures):
                    # Update progress bar on each task completion
                    progress_bar.update(1)
                progress_bar.close()

            
            """
            for role in tqdm(roles, desc=f"Checking role permissions in account {account_id} ({profile})"):
                role_perms = get_policies("Role", role["RoleName"], role["Arn"], api_key, verbose, only_yaml, only_openai, all_resources, all_actions)
                if role_perms and any(v for v in role_perms.values()):
                    if UNUSED_ROLES.get(role["Arn"]):
                        UNUSED_ROLES[role["Arn"]]["permissions"] = role_perms
                    else:
                        get_unused_pers_of_ppal(accessanalyzer, analyzer_arn, role["Arn"], "role", role_perms)
            """
            
            print()
            print_results(account_id, profile, print_reasons, merge_perms)
        
        except Exception as e:
            print(f"{colored('[-] ', 'red')}Error: {str(e)}")
        
        finally:
            # Cleanup: Remove created analyzers
            for analyzer_name in created_analyzers:
                try:
                    accessanalyzer.delete_analyzer(analyzerName=analyzer_name)
                    print(f"{colored('[+] ', 'green')}Analyzer {analyzer_name} deleted successfully.")
                except Exception as e:
                    print(f"{colored('[-] ', 'red')}Failed to delete analyzer {analyzer_name}: {str(e)}")


HELP = "Find AWS unused sensitive permissions given to principals in the accounts of the specified profiles.\n"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=HELP)
    parser.add_argument("profiles", nargs="+", help="One or more AWS profiles to check.")
    parser.add_argument("-k", "--api-key", help="OpenAI API key. The env variable OPENAI_API_KEY can also be used.")
    parser.add_argument("-v", "--verbose", default=False, help="Get info about why a permission is sensitive or useful for privilege escalation.", action="store_true")
    parser.add_argument("--only-yaml", default=False, help="Only check permissions inside the yaml file", action="store_true")
    parser.add_argument("--only-openai", default=False, help="Only check permissions with OpenAI", action="store_true")
    parser.add_argument("--all-resources", default=False, help="Do not filter only permissions over '*'", action="store_true")
    parser.add_argument("--print-reasons", default=False, help="Print the reasons why a permission is considered sensitive or useful for privilege escalation.", action="store_true")
    parser.add_argument("--all-actions", default=False, help="Do not filter permissions inside the readOnly policy", action="store_true")
    parser.add_argument("--merge-perms", default=False, help="Print permissions from yaml and OpenAI merged", action="store_true")
    parser.add_argument("--max-perms-to-print", type=int, help="Maximum number of permissions to print per row", default=15)
    args = parser.parse_args()

    main(args.profiles, args.api_key, args.verbose, args.only_yaml, args.only_openai, args.all_resources, args.print_reasons, args.all_actions, args.merge_perms, int(args.max_perms_to_print))
