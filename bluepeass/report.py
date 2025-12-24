from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional


SCHEMA_VERSION = 1
TOOL_NAME = "Blue Cloud PEASS"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def atomic_write_json(path: str, obj: Any) -> None:
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=False, default=str)
        f.write("\n")
    os.replace(tmp_path, path)


@dataclass
class Target:
    target_type: str
    target_id: str
    label: Optional[str] = None
    data: Optional[dict] = None

    def to_dict(self) -> dict:
        out = {"target_type": self.target_type, "target_id": self.target_id}
        if self.label:
            out["label"] = self.label
        if self.data is not None:
            out["data"] = self.data
        return out


def _count_nested_errors(targets: list[dict]) -> int:
    total = 0
    for t in targets:
        data = t.get("data")
        if isinstance(data, dict):
            errs = data.get("errors")
            if isinstance(errs, list):
                total += len(errs)
    return total


def build_report(
    *,
    provider: str,
    targets: list[dict],
    errors: Optional[list[dict]] = None,
    extra_summary: Optional[dict] = None,
) -> dict:
    errors = errors or []
    summary = {
        "total_targets": len(targets),
        "top_level_errors": len(errors),
        "target_errors": _count_nested_errors(targets),
        "errors": len(errors) + _count_nested_errors(targets),
    }
    if extra_summary:
        summary.update(extra_summary)

    report = {
        "tool": TOOL_NAME,
        "schema_version": SCHEMA_VERSION,
        "provider": provider,
        "generated_at": utc_now_iso(),
        "targets": targets,
        "summary": summary,
    }
    if errors:
        report["errors"] = errors
    return report

