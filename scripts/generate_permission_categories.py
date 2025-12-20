#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os

import yaml

from permission_risk_classifier import (
    HintSets,
    classify_all,
    load_aws_permissions_from_managed_policies,
    load_azure_permissions_from_provider_operations,
    load_gcp_permissions_from_sorted,
)


def _dump_yaml(path: str, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(
            data,
            f,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
            width=120,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate AWS/GCP permission risk category YAMLs from local datasets.")
    parser.add_argument("--aws-json", default="tmp_perms/aws_managed_policies.json")
    parser.add_argument("--gcp-json", default="tmp_perms/gcp_permissions_sorted.json")
    parser.add_argument("--azure-json", default="tmp_perms/azure-provider-operations.json")
    parser.add_argument("--aws-out", default="aws_permissions_cat.yaml")
    parser.add_argument("--gcp-out", default="gcp_permissions_cat.yaml")
    parser.add_argument("--azure-out", default="azure_permissions_cat.yaml")
    args = parser.parse_args()

    if not os.path.exists(args.aws_json):
        raise SystemExit(f"Missing AWS dataset: {args.aws_json}")
    if not os.path.exists(args.gcp_json):
        raise SystemExit(f"Missing GCP dataset: {args.gcp_json}")
    if not os.path.exists(args.azure_json):
        raise SystemExit(f"Missing Azure dataset: {args.azure_json}")

    aws_perms = load_aws_permissions_from_managed_policies(args.aws_json)
    gcp_perms = load_gcp_permissions_from_sorted(args.gcp_json)
    azure_perms = load_azure_permissions_from_provider_operations(args.azure_json)

    # Hint YAML files (e.g. `*_sensitive_permissions.yaml`) are intentionally not used here:
    # classification relies on hardcoded heuristics so the workflow keeps working if those files are removed.
    empty_hints = HintSets(sensitive=set(), privesc=set(), sensitive_lower=set(), privesc_lower=set())

    aws_categories = classify_all("aws", aws_perms, empty_hints, unknown_default="high")
    gcp_categories = classify_all("gcp", gcp_perms, empty_hints, unknown_default="high")
    azure_categories = classify_all("azure", azure_perms, empty_hints, unknown_default="high")

    _dump_yaml(args.aws_out, aws_categories)
    _dump_yaml(args.gcp_out, gcp_categories)
    _dump_yaml(args.azure_out, azure_categories)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
