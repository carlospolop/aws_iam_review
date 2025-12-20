#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
from typing import Optional

import requests
import yaml

from permission_risk_classifier import (
    HintSets,
    aws_regex_classify,
    gcp_regex_classify,
    azure_regex_classify,
    load_aws_permissions_from_managed_policies,
    load_azure_permissions_from_provider_operations,
    load_gcp_permissions_from_sorted,
)


AWS_DATASET_URL = "https://raw.githubusercontent.com/iann0036/iam-dataset/refs/heads/main/aws/managed_policies.json"
GCP_DATASET_URL = "https://raw.githubusercontent.com/iann0036/iam-dataset/refs/heads/main/gcp/permissions_sorted.json"
AZURE_DATASET_URL = "https://raw.githubusercontent.com/iann0036/iam-dataset/refs/heads/main/azure/provider-operations.json"


def _download(url: str, dest: str) -> None:
    os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
    r = requests.get(url, timeout=120)
    r.raise_for_status()
    with open(dest, "wb") as f:
        f.write(r.content)


def _load_categories(path: str) -> dict[str, list[str]]:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict) or set(data.keys()) != {"low", "medium", "high", "critical"}:
        raise SystemExit(f"Invalid categories YAML structure: {path}")
    for key in ("low", "medium", "high", "critical"):
        if not isinstance(data.get(key), list):
            raise SystemExit(f"Invalid list for key '{key}' in {path}")
    return {k: list(v) for k, v in data.items()}  # copy


def _dump_categories(path: str, data: dict[str, list[str]]) -> None:
    ordered = {k: data[k] for k in ("low", "medium", "high", "critical")}
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(
            ordered,
            f,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
            width=120,
        )


def _load_unclassified(path: str) -> dict[str, list[str]]:
    if not os.path.exists(path):
        return {"aws": [], "gcp": [], "azure": []}
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        return {"aws": [], "gcp": [], "azure": []}
    aws = data.get("aws") if isinstance(data.get("aws"), list) else []
    gcp = data.get("gcp") if isinstance(data.get("gcp"), list) else []
    azure = data.get("azure") if isinstance(data.get("azure"), list) else []
    return {"aws": list(aws), "gcp": list(gcp), "azure": list(azure)}


def _dump_unclassified(path: str, data: dict[str, list[str]]) -> None:
    ordered = {
        "aws": sorted(set(data.get("aws", []))),
        "gcp": sorted(set(data.get("gcp", []))),
        "azure": sorted(set(data.get("azure", []))),
    }
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(
            ordered,
            f,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
            width=120,
        )


def _openai_classify(permission: str, provider: str) -> Optional[str]:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return None

    try:
        from openai import OpenAI  # type: ignore
    except Exception:
        return None

    model = os.environ.get("OPENAI_MODEL") or "gpt-4o-mini"
    client = OpenAI(api_key=api_key)

    sys = (
        "Return only one token: low, medium, high, or critical.\n"
        "Critical means it can independently enable privilege escalation (IAM/policy/trust changes, impersonation/act-as, or code execution as another identity).\n"
        "High means sensitive data access or sensitive modifications without direct privilege escalation.\n"
        "Medium means destructive/operational impact (delete/remove/destroy) without privilege escalation.\n"
        "Low means read-only/discovery with no sensitive data access.\n"
    )
    msg = (
        f"Classify this {provider.upper()} permission by risk level: {permission}\n"
        "Respond with only: low | medium | high | critical"
    )

    try:
        resp = client.responses.create(
            model=model,
            input=[
                {"role": "system", "content": sys},
                {"role": "user", "content": msg},
            ],
            temperature=0,
        )
        text = (resp.output_text or "").strip().lower()
    except Exception:
        return None

    for token in ("low", "medium", "high", "critical"):
        if text == token:
            return token
    return None


def _existing_map(categories: dict[str, list[str]]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for level, perms in categories.items():
        for p in perms:
            mapping[p] = level
    return mapping


def _classify_new(
    provider: str,
    permission: str,
    hints: HintSets,
) -> Optional[str]:
    if provider == "aws":
        level = aws_regex_classify(permission, hints)
    elif provider == "gcp":
        level = gcp_regex_classify(permission, hints)
    elif provider == "azure":
        level = azure_regex_classify(permission, hints)
    else:
        raise ValueError(provider)

    if level is None:
        level = _openai_classify(permission, provider)

    if level is None:
        return None

    return level


def main() -> int:
    parser = argparse.ArgumentParser(description="Weekly updater for permission risk categories.")
    parser.add_argument("--aws-url", default=AWS_DATASET_URL)
    parser.add_argument("--gcp-url", default=GCP_DATASET_URL)
    parser.add_argument("--azure-url", default=AZURE_DATASET_URL)
    parser.add_argument("--aws-json", default="tmp_perms/aws_managed_policies.json")
    parser.add_argument("--gcp-json", default="tmp_perms/gcp_permissions_sorted.json")
    parser.add_argument("--azure-json", default="tmp_perms/azure-provider-operations.json")
    parser.add_argument("--aws-yaml", default="aws_permissions_cat.yaml")
    parser.add_argument("--gcp-yaml", default="gcp_permissions_cat.yaml")
    parser.add_argument("--azure-yaml", default="azure_permissions_cat.yaml")
    parser.add_argument("--unclassified-yaml", default="unclassified_permissions.yaml")
    args = parser.parse_args()

    _download(args.aws_url, args.aws_json)
    _download(args.gcp_url, args.gcp_json)
    _download(args.azure_url, args.azure_json)

    # Hint YAML files (e.g. `*_sensitive_permissions.yaml`) are intentionally not used here:
    # classification relies on hardcoded heuristics so the workflow keeps working if those files are removed.
    empty_hints = HintSets(sensitive=set(), privesc=set(), sensitive_lower=set(), privesc_lower=set())

    aws_dataset = load_aws_permissions_from_managed_policies(args.aws_json)
    gcp_dataset = load_gcp_permissions_from_sorted(args.gcp_json)
    azure_dataset = load_azure_permissions_from_provider_operations(args.azure_json)

    aws_categories = _load_categories(args.aws_yaml)
    gcp_categories = _load_categories(args.gcp_yaml)
    azure_categories = _load_categories(args.azure_yaml)
    aws_existing = _existing_map(aws_categories)
    gcp_existing = _existing_map(gcp_categories)
    azure_existing = _existing_map(azure_categories)

    unclassified = _load_unclassified(args.unclassified_yaml)

    aws_new = sorted(aws_dataset - set(aws_existing.keys()))
    gcp_new = sorted(gcp_dataset - set(gcp_existing.keys()))
    azure_new = sorted(azure_dataset - set(azure_existing.keys()))

    unknown_fallback_level = "high"
    newly_added = {"aws": 0, "gcp": 0, "azure": 0}
    for perm in aws_new:
        level = _classify_new("aws", perm, empty_hints)
        if level is None:
            unclassified["aws"].append(perm)
            level = unknown_fallback_level
        aws_categories[level].append(perm)
        newly_added["aws"] += 1

    for perm in gcp_new:
        level = _classify_new("gcp", perm, empty_hints)
        if level is None:
            unclassified["gcp"].append(perm)
            level = unknown_fallback_level
        gcp_categories[level].append(perm)
        newly_added["gcp"] += 1

    for perm in azure_new:
        level = _classify_new("azure", perm, empty_hints)
        if level is None:
            unclassified["azure"].append(perm)
            level = unknown_fallback_level
        azure_categories[level].append(perm)
        newly_added["azure"] += 1

    # Keep existing ordering, but append new permissions deterministically.
    _dump_categories(args.aws_yaml, aws_categories)
    _dump_categories(args.gcp_yaml, gcp_categories)
    _dump_categories(args.azure_yaml, azure_categories)
    _dump_unclassified(args.unclassified_yaml, unclassified)

    print(f"AWS new permissions: {len(aws_new)} (classified: {newly_added['aws']}, unclassified: {len(aws_new) - newly_added['aws']})")
    print(f"GCP new permissions: {len(gcp_new)} (classified: {newly_added['gcp']}, unclassified: {len(gcp_new) - newly_added['gcp']})")
    print(
        f"Azure new permissions: {len(azure_new)} (classified: {newly_added['azure']}, unclassified: {len(azure_new) - newly_added['azure']})"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
