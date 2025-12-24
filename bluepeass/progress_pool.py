from __future__ import annotations

import threading
from typing import Callable, Optional, Sequence

try:
    from tqdm import tqdm
except Exception:  # pragma: no cover
    tqdm = None


class SlotStageProgress:
    """
    Multi-progress helper for parallel target scans.

    Creates N small per-slot tqdm bars and provides thread-safe stage updates.
    Intended usage:
      - slot = idx % max_slots
      - start(slot, label)
      - update(slot, stage)
      - finish(slot)

    This is deliberately lightweight: it only tracks the stage name, not inner work.
    """

    def __init__(
        self,
        *,
        max_slots: int,
        stages: Sequence[str],
        unit: str,
        enabled: bool = True,
        position_offset: int = 1,
    ) -> None:
        self._lock = threading.Lock()
        self._enabled = bool(enabled and tqdm is not None)
        self._stages = list(stages)
        self._stage_to_idx = {s: i for i, s in enumerate(self._stages)}
        self._bars: list = []
        self._slot_idx: list[int] = []
        self._slot_label: list[str] = []
        self._unit = unit
        self._pos_off = position_offset
        self._cv = threading.Condition(self._lock)
        self._available: list[int] = []

        n = max(0, int(max_slots))
        if not self._enabled or n <= 0:
            return
        for i in range(n):
            bar = tqdm(
                total=max(1, len(self._stages)),
                desc=f"{unit} #{i+1}",
                unit="stage",
                position=self._pos_off + i,
                leave=False,
            )
            self._bars.append(bar)
            self._slot_idx.append(-1)
            self._slot_label.append("")
            self._available.append(i)

    def make_callback(self, slot: int, *, forward: Optional[Callable[[str], None]] = None) -> Callable[[str], None]:
        def cb(stage: str) -> None:
            if forward:
                forward(stage)
            self.update(slot, stage)

        return cb

    def acquire(self, label: str) -> int:
        """
        Acquire a progress slot (blocking) and set its label.
        Returns the slot index.
        """
        if not self._enabled:
            return 0
        with self._cv:
            while not self._available:
                self._cv.wait(timeout=0.1)
            slot = self._available.pop(0)
            self._start_locked(slot, label)
            return slot

    def release(self, slot: int) -> None:
        if not self._enabled:
            return
        with self._cv:
            if slot < 0 or slot >= len(self._bars):
                return
            # Reset for reuse.
            bar = self._bars[slot]
            bar.reset()
            bar.set_description_str(f"{self._unit} #{slot+1}", refresh=True)
            bar.set_postfix_str("", refresh=True)
            self._slot_idx[slot] = -1
            self._slot_label[slot] = ""
            self._available.append(slot)
            self._cv.notify()

    def start(self, slot: int, label: str) -> None:
        if not self._enabled:
            return
        with self._lock:
            self._start_locked(slot, label)

    def _start_locked(self, slot: int, label: str) -> None:
        if slot < 0 or slot >= len(self._bars):
            return
        self._slot_idx[slot] = -1
        self._slot_label[slot] = label or ""
        bar = self._bars[slot]
        bar.reset()
        bar.set_description_str(label or f"{self._unit} #{slot+1}", refresh=True)

    def update(self, slot: int, stage: str) -> None:
        if not self._enabled:
            return
        with self._lock:
            if slot < 0 or slot >= len(self._bars):
                return
            idx = self._stage_to_idx.get(stage)
            if idx is None:
                return
            prev = self._slot_idx[slot]
            if idx <= prev:
                return
            self._slot_idx[slot] = idx
            bar = self._bars[slot]
            bar.update(idx - prev)
            bar.set_postfix_str(stage, refresh=True)

    def finish(self, slot: int) -> None:
        if not self._enabled:
            return
        with self._lock:
            if slot < 0 or slot >= len(self._bars):
                return
            bar = self._bars[slot]
            # Fill to total.
            remaining = max(0, bar.total - bar.n)
            if remaining:
                bar.update(remaining)
            bar.set_postfix_str("done", refresh=True)

    def close(self) -> None:
        if not self._enabled:
            return
        with self._lock:
            for b in self._bars:
                try:
                    b.close()
                except Exception:
                    pass
            self._bars = []
