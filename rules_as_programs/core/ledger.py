"""Per-conversation evidence ledger.

An append-only JSONL file per ``conversation_id`` holding every observed
:class:`Event`. Rule programs read from the ledger (never from the agent's
prompt), which is what makes them *independent* auditors of what the agent
actually thought and did.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from .. import config
from .events import Event


class Ledger:
    """Thread-safe append-only event log for one conversation."""

    def __init__(self, conversation_id: str, project_root: str = ""):
        self.conversation_id = conversation_id
        self.project_root = project_root
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in conversation_id)
        self.path: Path = config.ledger_dir() / f"{safe}.jsonl"
        self._lock = threading.Lock()

    def append(self, event: Event) -> None:
        line = json.dumps(event.to_dict(), ensure_ascii=False)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")

    def events(self, kinds: set[str] | None = None) -> list[Event]:
        if not self.path.exists():
            return []
        out: list[Event] = []
        with self.path.open("r", encoding="utf-8") as f:
            for raw in f:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    ev = Event.from_dict(json.loads(raw))
                except (json.JSONDecodeError, KeyError):
                    continue
                if kinds is None or ev.kind in kinds:
                    out.append(ev)
        return out

    def latest_text(self, kind: str) -> str:
        """Text of the most recent event of ``kind`` (empty if none)."""
        evs = self.events({kind})
        return evs[-1].text() if evs else ""

    def context_window(
        self,
        center_event_id: str = "",
        *,
        center_ts: float | None = None,
        before: int = 30,
        after: int = 30,
        start: int | None = None,
        limit: int = 60,
    ) -> dict[str, Any]:
        """Return a bounded, scrollable event slice around one trigger."""
        events = self.events()
        total = len(events)
        center_index = next(
            (index for index, event in enumerate(events)
             if center_event_id and event.id == center_event_id),
            -1,
        )
        if center_index < 0 and center_ts is not None and events:
            center_index = min(
                range(total), key=lambda index: abs(events[index].ts - center_ts))
        if center_index < 0:
            center_index = max(0, total - 1)
        if start is None:
            window_start = max(0, center_index - max(0, before))
            window_end = min(total, center_index + max(0, after) + 1)
        else:
            window_start = max(0, min(int(start), total))
            window_end = min(total, window_start + max(1, int(limit)))
        rows = []
        for index, event in enumerate(events[window_start:window_end], window_start):
            data = event.to_dict()
            data["text"] = event.text()
            data["index"] = index
            data["is_trigger"] = index == center_index
            rows.append(data)
        return {
            "events": rows,
            "start": window_start,
            "end": window_end,
            "total": total,
            "center_index": center_index,
            "has_earlier": window_start > 0,
            "has_later": window_end < total,
            "path": str(self.path),
        }


class LedgerStore:
    """Caches :class:`Ledger` instances by conversation id within a process."""

    def __init__(self) -> None:
        self._ledgers: dict[str, Ledger] = {}
        self._lock = threading.Lock()

    def get(self, conversation_id: str, project_root: str = "") -> Ledger:
        with self._lock:
            led = self._ledgers.get(conversation_id)
            if led is None:
                led = Ledger(conversation_id, project_root)
                self._ledgers[conversation_id] = led
            elif project_root and not led.project_root:
                led.project_root = project_root
            return led
