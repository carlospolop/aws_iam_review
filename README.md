# AWS IAM Review

<p align="center">
  <img src="logo.webp" alt="AWS IAM Review Logo" width="50%"/>
</p>

This script:

- **Print unused roles, users logins, users keys and empty groups**
  - It'll also indicated if the principals have dangerous permissions and which ones.
  - It'll also indicate if the principal is accessible externally (for example via federation or trusting other AWS accounts).

- **Print externally accessible principals**
  - It'll also indicate how are they accessible (federation, trusted accounts, etc) and the conditions to meet.

Dangerous permissions are divided in 2 categories:
- Privilege escalation permissions are permissions that would allow a principal in AWS to obtain more permissions (by aumenting his own permissions or by pivoting to other principals for example).
- Sensitive permissions are permissions that could allow an attacker to perform actions that could be harmful for the organization (like deleting resources, reading sensitive data, etc).

Moreover, this tool offer **2 ways to find dangerous permissions**:
- Using a **YAML file with sensitive and privescs permissions predefined** (based on https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation and https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation).
- Using **OpenAI to ask** if a set of permissions contains sensitive or a privesc permissions. **You need to provide your own OpenAI api key**.

Note that this **tool only sends permissions names to OpenAI, no private information is shared**.

If you know more interesting AWS permissions feel free to send a **PR here and to [HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)**

## Parameters

- You can use the `--only-yaml` flag to only check the permissions inside the YAML file withuot using HackTricksAI.
- By default, to increase speed, the **permissions included in the readOnly** managed policy are removed before asking the AI (you can disable this behaviour with `--all-actions`).
- By default the tool will filter out permissions assigned to specific resources (so not to `*`). You can re-enable this by using the `--all-resources` flag.

## Needed AWS permissions

As for any other security review, it's recommended to ask for the `arn:aws:iam::aws:policy/ReadOnlyAccess` role. From these role you will at least need permissions to list roles, users, groups and policies, and enumerate the permissions of these entities.

For the AWS access analyzer you will need the `arn:aws:iam::aws:policy/AWSAccessAnalyzerReadOnlyAccess` if access analizers for `ACCOUNT` and `ACCOUNT_UNUSED_ACCESS` are already created.

If they aren't created, you will need the permissions:
- `access-analyzer:CreateAnalyzer`
- `access-analyzer:List*`
- `access-analyzer:Get*`
- `access-analyzer:DeleteAnalyzer`
- `iam:CreateServiceLinkedRole`

<details>
<summary>Expand JSON example</summary>

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "access-analyzer:List*",
                "access-analyzer:Get*",
                "access-analyzer:DeleteAnalyzer",
                "access-analyzer:CreateAnalyzer"
            ],
            "Effect": "Allow",
            "Resource": "*",
            "Sid": "AccessAnalyzerOperator"
        },
        {
            "Action": [
                "iam:CreateServiceLinkedRole"
            ],
            "Effect": "Allow",
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "iam:AWSServiceName": "access-analyzer.amazonaws.com"
                }
            },
            "Sid": "AccessAnalyzerOperatorCreateServiceLinkedRole"
        }
    ]
}
```
</details>


So the script can create it, query it and finally delete it.

## Quick Start

```bash
pip3 install -r requirements.txt

# Help
usage: aws_iam_review.py [-h] [-k API_KEY] [-v] [--only-yaml] [--all-resources] [--print-reasons]
                         [--all-actions] [--merge-perms] [--max-perms-to-print MAX_PERMS_TO_PRINT] [-m MODEL]
                         profiles [profiles ...]

Find AWS unused sensitive permissions given to principals in the accounts of the specified profiles.

positional arguments:
  profiles              One or more AWS profiles to check.

options:
  -h, --help            show this help message and exit
  -v, --verbose         Get info about why a permission is sensitive or useful for privilege escalation.
  --only-yaml           Only check permissions inside the yaml file
  --all-resources       Do not filter only permissions over '*'
  --print-reasons       Print the reasons why a permission is considered sensitive or useful for privilege escalation.
  --all-actions         Do not filter permissions inside the readOnly policy
  --merge-perms         Print permissions from yaml and OpenAI merged
  --max-perms-to-print MAX_PERMS_TO_PRINT
                        Maximum number of permissions to print per row


# Run the 2 modes with 3 profiles
python3 aws_iam_review.py profile-name profile-name2 profile-name3 -v

# Run only the yaml mode with 1 profile
python3 aws_iam_review.py profile-name --only-yaml -v
```
