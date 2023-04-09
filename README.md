# AWS Sensitive Permissions

This script enumerates the permissions of all the AWS principals (groups, users & roles) of an account and prints the ones that have interesting permissions:
- **Adminitrator (*) privileges**
- **Privilege Escalation privileges** (based on https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation)
- **Privileges to perform potential sensitive actions / Indirect privilege escalations** (based on https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation)

If you know more interesting AWS permissions feel free to send a **PR here and to [HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)**

## Quick Start

```bash
pip3 install -r requirements.txt

# Help
python3 aws_sensitive_permissions.py -h
usage: aws_sensitive_permissions.py [-h] profiles [profiles ...]

Check AWS sensitive permissions given to principals in the specified profiles.

positional arguments:
  profiles    One or more AWS profiles to check.

options:
  -h, --help  show this help message and exit

# Run example
aws_sensitive_permissions.py profile-name profile-name2 profile-name3
```
