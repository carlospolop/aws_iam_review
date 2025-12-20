# Blue Cloud PEASS

Blue Cloud PEASS helps blue teams and auditors quickly identify risky IAM permissions and access patterns across cloud providers.

This repo currently includes:
- `aws_iam_review.py`: AWS IAM review (unused permissions + risky access)
- `gcp_iam_review.py`: GCP IAM review (Recommender + Cloud Asset Inventory)
- Weekly, auto-updated permission risk catalogs:
  - `aws_permissions_cat.yaml`
  - `gcp_permissions_cat.yaml`
  - `azure_permissions_cat.yaml`

<p align="center">
  <img src="logo.webp" alt="AWS IAM Review Logo" width="50%"/>
</p>

## AWS (`aws_iam_review.py`)

This script:

- **Print unused roles, users logins, users keys and empty groups**
  - It'll also indicated if the principals have dangerous permissions and which ones.
  - It'll also indicate if the principal is accessible externally (for example via federation or trusting other AWS accounts).

- **Print externally accessible principals**
  - It'll also indicate how are they accessible (federation, trusted accounts, etc) and the conditions to meet.

Dangerous permissions are divided in 2 categories:
- Privilege escalation permissions are permissions that would allow a principal in AWS to obtain more permissions (by aumenting his own permissions or by pivoting to other principals for example).
- Sensitive permissions are permissions that could allow an attacker to perform actions that could be harmful for the organization (like deleting resources, reading sensitive data, etc).

Moreover, this tool can optionally use an AI backend to help classify permissions (you must provide your own API key when enabled).

Note that this **tool only sends permission names to the AI backend**, no private data is intended to be shared.

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
                         [--all-actions] [--merge-perms] [--max-perms-to-print MAX_PERMS_TO_PRINT]
                         [--min-unused-days MIN_UNUSED_DAYS] [--json] [-m MODEL] profiles [profiles ...]

Find AWS unused sensitive permissions given to principals in the accounts of the specified profiles.

positional arguments:
  profiles              One or more AWS profiles to check.

options:
  -h, --help            show this help message and exit
  -k API_KEY            HackTricks AI API key for permission analysis
  -v, --verbose         Get info about why a permission is sensitive or useful for privilege escalation.
  --only-yaml           Only check permissions inside the yaml file
  --all-resources       Do not filter only permissions over '*'
  --print-reasons       Print the reasons why a permission is considered sensitive or useful for privilege escalation.
  --all-actions         Do not filter permissions inside the readOnly policy
  --merge-perms         Print permissions from yaml and OpenAI merged
  --max-perms-to-print MAX_PERMS_TO_PRINT
                        Maximum number of permissions to print per row (default: 15)
  --min-unused-days MIN_UNUSED_DAYS
                        Minimum days a permission must be unused to be flagged (default: 30)
  --json                Output results in JSON format (includes all data unfiltered)
  -m MODEL              AI model to use for permission analysis


# Run the 2 modes with 3 profiles
python3 aws_iam_review.py profile-name profile-name2 profile-name3 -v

# Run only the yaml mode with 1 profile
python3 aws_iam_review.py profile-name --only-yaml -v

# Custom unused threshold (90 days)
python3 aws_iam_review.py profile-name --min-unused-days 90

# JSON output with all data
python3 aws_iam_review.py profile-name --json > results.json
```

## Output Modes

**Console Output** (default): Color-coded, filtered view showing the most critical findings. Applies `--min-unused-days` filtering and limits display to 4 services and 3 permissions per service for readability.

**JSON Output** (`--json`): Complete unfiltered data including all services, permissions, and metadata. Ignores display limits and filtering thresholds. Use for automated processing or comprehensive analysis.

---

## GCP (`gcp_iam_review.py`) (Recommender + Cloud Asset)

The repository also includes `gcp_iam_review.py`, which uses:
- **Recommender API** (`google.iam.policy.Recommender`) to suggest IAM bindings/roles that can be removed or reduced based on observed usage.
- **Cloud Asset Inventory** to highlight risky IAM trust patterns (public access, Workload Identity Federation trusts, external domains).
- Optional AI classification to categorize effective permissions (expanded from bound roles) into privilege-escalation vs sensitive permissions.

It authenticates via:
- `--sa-json` (service account JSON key), or
- your current `gcloud` login, or
- ADC/metadata credentials (GCE/GKE).
When using `--allowed-domain`, the script always includes the current `gcloud` account domain in the allowlist by default.

## Needed Permissions (GCP)

- Recommender recommendations: `recommender.iamPolicyRecommendations.list` (role `roles/recommender.iamViewer`)
- Cloud Asset IAM search: `cloudasset.assets.searchAllIamPolicies` (role `roles/cloudasset.viewer`)
- Role expansion for AI classification: `iam.roles.get`
 - Auto-enabling APIs (always attempted): `serviceusage.services.enable`

## Quick Start (GCP)

```bash
# Login
gcloud auth login

# Optional: set a default project
gcloud config set project <PROJECT_ID>

# Analyze the current project
python3 gcp_iam_review.py

# Analyze specific projects
python3 gcp_iam_review.py --project <PROJECT_ID> --project <PROJECT_ID_2>

# Analyze the whole organization
python3 gcp_iam_review.py --organization <ORG_ID> --quota-project <BILLING_OR_QUOTA_PROJECT>

# JSON output (for tooling)
python3 gcp_iam_review.py --project <PROJECT_ID> --json > gcp_results.json

# Flag domain-wide grants outside your company domains
python3 gcp_iam_review.py --project <PROJECT_ID> --allowed-domain example.com --allowed-domain example.org

# Disable AI classification (faster, no external call)
python3 gcp_iam_review.py --project <PROJECT_ID> --no-ai
```

---

## Permission Catalogs (Weekly Updates)

This repo maintains provider-wide granular permission risk catalogs in:
- `aws_permissions_cat.yaml`
- `gcp_permissions_cat.yaml`
- `azure_permissions_cat.yaml`

They are updated automatically by the GitHub Action in `.github/workflows/weekly-permission-categories.yml`.
