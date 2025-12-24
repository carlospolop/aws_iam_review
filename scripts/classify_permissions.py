#!/usr/bin/env python3

import argparse
import json
import sys

from permission_risk_classifier import classify_all, classify_permission
from bluepeass.report import atomic_write_json


def main() -> int:
    ap = argparse.ArgumentParser(description="Classify cloud permissions by risk using regex/exact rule YAMLs.")
    ap.add_argument("--cloud", required=True, choices=["aws", "gcp", "azure"], help="Cloud provider.")
    ap.add_argument("--out-json", help="Write full JSON results to this path (stdout stays line-oriented).")
    ap.add_argument(
        "--unknown-default",
        default="high",
        choices=["low", "medium", "high", "critical"],
        help="Category for permissions that don't match any rule (default: high).",
    )
    ap.add_argument("permissions", nargs="*", help="Permissions to classify. If empty, read one-per-line from stdin.")
    args = ap.parse_args()

    perms = list(args.permissions)
    if not perms:
        perms = [line.strip() for line in sys.stdin.read().splitlines() if line.strip()]

    if args.out_json:
        out = classify_all(args.cloud, perms, unknown_default=args.unknown_default)
        atomic_write_json(args.out_json, out)

    for p in perms:
        lvl = classify_permission(args.cloud, p, unknown_default=args.unknown_default)
        print(f"{lvl}\\t{p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
