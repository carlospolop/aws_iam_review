from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional, Sequence
import threading


@dataclass(frozen=True)
class Stage:
    name: str


class StageProgress:
    """
    Thread-safe stage tracker for parallel tasks.

    - Maintains a single overall tqdm bar (if tqdm is available).
    - Tracks a per-task current stage and updates bar postfix with stage counts.
    """

    def __init__(
        self,
        *,
        total: int,
        desc: str,
        unit: str,
        tqdm_factory: Optional[Callable] = None,
        stages: Optional[Sequence[str]] = None,
    ) -> None:
        self._lock = threading.Lock()
        self._total = total
        self._desc = desc
        self._unit = unit
        self._tqdm = tqdm_factory(total=total, desc=desc, unit=unit, leave=False) if tqdm_factory else None
        self._task_stage: dict[int, str] = {}
        self._task_stage_index: dict[int, int] = {}
        self._stages = list(stages) if stages else []
        self._stage_to_index = {name: i for i, name in enumerate(self._stages)}
        self._stage_weight = 1.0 / max(1, len(self._stages)) if self._stages else 0.0

    def make_callback(self, task_id: int) -> Callable[[str], None]:
        def cb(stage: str) -> None:
            self.set_stage(task_id, stage)

        return cb

    def set_stage(self, task_id: int, stage: str) -> None:
        with self._lock:
            # Weighted progress: when a task advances to a new stage, increment the overall bar.
            if self._tqdm is not None and self._stages:
                prev_idx = self._task_stage_index.get(task_id, -1)
                new_idx = self._stage_to_index.get(stage, prev_idx)
                if new_idx > prev_idx:
                    self._task_stage_index[task_id] = new_idx
                    self._tqdm.update((new_idx - prev_idx) * self._stage_weight)
            self._task_stage[task_id] = stage
            self._render_locked()

    def finish(self, task_id: int) -> None:
        with self._lock:
            self._task_stage[task_id] = "done"
            # Ensure the task contributes a full "1.0" unit of progress, even if it errored.
            if self._tqdm is not None:
                if self._stages:
                    prev_idx = self._task_stage_index.get(task_id, -1)
                    remaining = max(0.0, 1.0 - ((prev_idx + 1) * self._stage_weight))
                    if remaining:
                        self._tqdm.update(remaining)
                else:
                    self._tqdm.update(1)
            self._render_locked()

    def close(self) -> None:
        with self._lock:
            if self._tqdm is not None:
                self._tqdm.close()
                self._tqdm = None

    def _render_locked(self) -> None:
        if self._tqdm is None:
            return
        counts: dict[str, int] = {}
        for st in self._task_stage.values():
            counts[st] = counts.get(st, 0) + 1

        # Keep the postfix short and stable.
        interesting = []
        for key in sorted(counts.keys()):
            if key == "done":
                continue
            interesting.append(f"{key}:{counts[key]}")
        if "done" in counts:
            interesting.append(f"done:{counts['done']}")
        postfix = " ".join(interesting[:8])
        self._tqdm.set_postfix_str(postfix, refresh=True)
