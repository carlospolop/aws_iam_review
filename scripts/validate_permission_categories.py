#!/usr/bin/env python3

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml


SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))


def _load_yaml(path: str) -> dict[str, list[str]]:
    data = yaml.safe_load(Path(path).read_text("utf-8")) or {}
    if not isinstance(data, dict):
        raise SystemExit(f"Invalid YAML structure: {path}")
    expected = ["low", "medium", "high", "critical"]
    if list(data.keys()) != expected:
        raise SystemExit(f"{path} must contain exactly top-level keys {expected} (in that order). Got: {list(data.keys())}")
    for k in expected:
        if not isinstance(data.get(k), list):
            raise SystemExit(f"{path}:{k} must be a list")
    return {k: list(data[k]) for k in expected}


def _check_unique(path: str, data: dict[str, list[str]]) -> set[str]:
    all_perms: list[str] = []
    for k in ("low", "medium", "high", "critical"):
        all_perms += data[k]
    if len(all_perms) != len(set(all_perms)):
        raise SystemExit(f"Duplicate permissions found in {path}")
    return set(all_perms)


def _load_aws_dataset(path: str) -> set[str]:
    d = json.loads(Path(path).read_text("utf-8"))
    policies = d.get("policies", [])
    if not isinstance(policies, list):
        raise SystemExit(f"Unexpected AWS dataset format in {path}")
    perms: set[str] = set()
    for pol in policies:
        if not isinstance(pol, dict):
            continue
        for a in (pol.get("effective_action_names") or []):
            if isinstance(a, str) and a.strip():
                perms.add(a.strip())
    return perms


def _load_gcp_dataset(path: str) -> set[str]:
    d = json.loads(Path(path).read_text("utf-8"))
    if isinstance(d, dict):
        return {k.strip() for k in d.keys() if isinstance(k, str) and k.strip()}
    if isinstance(d, list):
        return {x.strip() for x in d if isinstance(x, str) and x.strip()}
    raise SystemExit(f"Unexpected GCP dataset format in {path}")


def main() -> int:
    aws_yaml = _load_yaml("aws_permissions_cat.yaml")
    gcp_yaml = _load_yaml("gcp_permissions_cat.yaml")
    azure_yaml = _load_yaml("azure_permissions_cat.yaml")

    aws_set = _check_unique("aws_permissions_cat.yaml", aws_yaml)
    gcp_set = _check_unique("gcp_permissions_cat.yaml", gcp_yaml)
    azure_set = _check_unique("azure_permissions_cat.yaml", azure_yaml)

    aws_ds = _load_aws_dataset("tmp_perms/aws_managed_policies.json")
    gcp_ds = _load_gcp_dataset("tmp_perms/gcp_permissions_sorted.json")
    from permission_risk_classifier import load_azure_permissions_from_provider_operations

    azure_ds = load_azure_permissions_from_provider_operations("tmp_perms/azure-provider-operations.json")

    missing_aws = aws_ds - aws_set
    extra_aws = aws_set - aws_ds
    missing_gcp = gcp_ds - gcp_set
    extra_gcp = gcp_set - gcp_ds
    missing_azure = azure_ds - azure_set
    extra_azure = azure_set - azure_ds

    if missing_aws or extra_aws or missing_gcp or extra_gcp or missing_azure or extra_azure:
        if missing_aws:
            print(f"AWS missing: {len(missing_aws)}", file=sys.stderr)
        if extra_aws:
            print(f"AWS extra: {len(extra_aws)}", file=sys.stderr)
        if missing_gcp:
            print(f"GCP missing: {len(missing_gcp)}", file=sys.stderr)
        if extra_gcp:
            print(f"GCP extra: {len(extra_gcp)}", file=sys.stderr)
        if missing_azure:
            print(f"Azure missing: {len(missing_azure)}", file=sys.stderr)
        if extra_azure:
            print(f"Azure extra: {len(extra_azure)}", file=sys.stderr)
        return 2

    print("OK: category YAMLs are unique and match datasets.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
