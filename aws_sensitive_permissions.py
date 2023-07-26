import boto3
import yaml
import fnmatch
import argparse
from termcolor import colored


# Load YAML data
with open("sensitive_permissions.yaml", "r") as file:
    permissions_data = yaml.safe_load(file)

# Function to combine all permissions from policy documents
def combine_permissions(policy_documents):
    permissions = []
    for document in policy_documents:
        if type(document["Statement"]) == list:
            statements = document["Statement"]
        else:
            statements = []
            statements.append(document["Statement"])
        for statement in statements:
            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            permissions.extend(actions)
    return permissions

# Function to check if a policy contains sensitive or privesc permissions
def check_policy(all_perm, arn):
    if not all_perm:
        return
    
    all_privesc_perms = []
    all_sensitive_perms = []

    for aws_svc, permissions in permissions_data.items():
        for perm_type in ["privesc", "sensitive"]:
            if perm_type in permissions:
                
                for perm in permissions[perm_type]:
                    if "," in perm:
                        required_perms = perm.replace(" ", "").split(",")
                    else:
                        required_perms = [perm]
                    
                    if "*" in all_perm:
                        msg = f"{colored('-', 'yellow')} {colored(arn, 'green')} has the " + colored("administrator", 'red') + " permission " + colored("*", 'red') + "."
                        print(msg)
                        return

                    elif any(
                            all(fnmatch.fnmatch(p, p_pattern) for p in required_perms)
                        for p_pattern in all_perm):
                        
                        if perm_type == "privesc":
                            all_privesc_perms.extend(required_perms)
                        elif perm_type == "sensitive":
                            all_sensitive_perms.extend(required_perms)

    if all_privesc_perms:
        msg = f"{colored('-', 'yellow')} {colored(arn, 'green')} has the {colored('privilege escalation', 'cyan')} permission(s): {colored(', '.join(all_privesc_perms), 'red')}"
        print(msg)
    
    if all_sensitive_perms:
        msg = f"{colored('-', 'yellow')} {colored(arn, 'green')} has the {colored('sensitive', 'cyan')} permission(s): {colored(', '.join(all_sensitive_perms), 'red')}"
        print(msg)


# Function to get inline and attached policies for a principal
def get_policies(principal_type, principal_name, arn):
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
        all_perm = combine_permissions(policy_document)
        check_policy(all_perm, arn)
    else:
        msg = f"- {arn} doesn't have any permissions."
        print(msg)
        

def main(profiles):
    for profile in profiles:
        # Share the boto3 client with other functions
        session = boto3.Session(profile_name=profile)
        global iam
        iam = session.client("iam")

        # Get the account ID
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]

        print(f"Interesting permissions in {colored(account_id, 'yellow')} ({colored(profile, 'blue')}): ")

        # Check permissions for users
        for user in iam.list_users()["Users"]:
            get_policies("User", user["UserName"], user["Arn"])

        # Check permissions for groups
        for group in iam.list_groups()["Groups"]:
            get_policies("Group", group["GroupName"], group["Arn"])

        # Check permissions for roles
        for role in iam.list_roles()["Roles"]:
            get_policies("Role", role["RoleName"], role["Arn"])
        
        print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check AWS sensitive permissions given to principals in the specified profiles.")
    parser.add_argument("profiles", nargs="+", help="One or more AWS profiles to check.")
    args = parser.parse_args()

    main(args.profiles)
