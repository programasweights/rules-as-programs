"""Per-conversation evidence ledger.

An append-only JSONL file per ``conversation_id`` holding every observed
:class:`Event`. Rule programs read from the ledger (never from the agent's
prompt), which is what makes them *independent* auditors of what the agent
actually thought and did.
"""

from __future__ import annotations

import json
import os
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Iterator

from .. import config
from .events import Event


@dataclass(frozen=True, slots=True)
class _Record:
    offset: int
    length: int
    event_id: str
    ts: float


def _signature(stat: os.stat_result) -> tuple[int, int, int, int, int]:
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)


class Ledger:
    """Thread-safe append-only event log for one conversation."""

    def __init__(self, conversation_id: str, project_root: str = ""):
        self.conversation_id = conversation_id
        self.project_root = project_root
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in conversation_id)
        self.path: Path = config.ledger_dir() / f"{safe}.jsonl"
        self._lock = threading.Lock()
        # Keep offsets and identifying metadata, never event payloads. Only our
        # own complete appends extend this cache; any other file change rebuilds
        # it, including same-size rewrites and truncation followed by regrowth.
        self._records: list[_Record] = []
        self._positions: dict[str, int] = {}
        self._signature: tuple[int, int, int, int, int] | None = None
        self._terminated = True

    def append(self, event: Event) -> None:
        data = event.to_dict()
        line = (json.dumps(data, ensure_ascii=False) + os.linesep).encode("utf-8")
        with self._lock:
            with self.path.open("ab") as f:
                before = _signature(os.fstat(f.fileno()))
                f.write(line)
                f.flush()
                after = _signature(os.fstat(f.fileno()))
            if (
                self._signature == before
                and self._terminated
                and before[:2] == after[:2]
                and after[2] == before[2] + len(line)
            ):
                self._add_record(_Record(before[2], len(line), data["id"], data["ts"]))
                self._signature = after
            else:
                self._signature = None

    @staticmethod
    def _decode_event(raw: bytes) -> Event | None:
        try:
            return Event.from_dict(json.loads(raw.decode("utf-8").strip()))
        except (ValueError, KeyError, TypeError):
            # A torn JSONL tail is retried after the next file change, as are
            # malformed lines repaired by an external writer.
            return None

    def _add_record(self, record: _Record) -> None:
        if isinstance(record.event_id, str):
            self._positions.setdefault(record.event_id, len(self._records))
        self._records.append(record)

    def _rebuild_index(
        self, f: BinaryIO, signature: tuple[int, int, int, int, int]
    ) -> None:
        self._records = []
        self._positions = {}
        self._signature = None
        self._terminated = True
        offset = 0
        # Bound the scan to the size observed on open. A concurrent external
        # change invalidates the signature on the next read.
        while offset < signature[2]:
            raw = f.readline(signature[2] - offset)
            if not raw:
                break
            self._terminated = raw.endswith(b"\n")
            event = self._decode_event(raw)
            if event is not None:
                self._add_record(_Record(offset, len(raw), event.id, event.ts))
            offset += len(raw)
        self._signature = signature

    @contextmanager
    def _snapshot(self) -> Iterator[BinaryIO | None]:
        with self._lock:
            try:
                f = self.path.open("rb")
            except FileNotFoundError:
                self._records = []
                self._positions = {}
                self._signature = None
                yield None
                return
            with f:
                signature = _signature(os.fstat(f.fileno()))
                if self._signature != signature:
                    self._rebuild_index(f, signature)
                yield f

    def event_position(self, event_id: str | None = None) -> tuple[int | None, int]:
        """Return the first matching one-based sequence and the snapshot count."""
        with self._snapshot():
            index = self._positions.get(event_id) if event_id is not None else None
            return (index + 1 if index is not None else None), len(self._records)

    def _read_event(self, f: BinaryIO, record: _Record) -> Event | None:
        f.seek(record.offset)
        event = self._decode_event(f.read(record.length))
        if event is not None:
            # Legacy records can omit defaults. Keep their generated identity
            # consistent with the metadata used to center this snapshot.
            event.id = record.event_id
            event.ts = record.ts
        return event

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
        through_seq: int | None = None,
    ) -> dict[str, Any]:
        """Return a bounded, scrollable event slice around one trigger."""
        with self._snapshot() as f:
            total = len(self._records)
            if through_seq is not None:
                total = min(total, max(0, int(through_seq)))
            center_index = (
                self._positions.get(center_event_id, -1) if center_event_id else -1)
            if center_index >= total:
                center_index = -1
            if center_index < 0 and center_ts is not None and total:
                center_index = min(
                    range(total),
                    key=lambda index: abs(self._records[index].ts - center_ts))
            if center_index < 0:
                center_index = max(0, total - 1)
            if start is None:
                window_start = max(0, center_index - max(0, before))
                window_end = min(total, center_index + max(0, after) + 1)
            else:
                window_start = max(0, min(int(start), total))
                window_end = min(total, window_start + max(1, int(limit)))
            rows = []
            if f is not None:
                for index in range(window_start, window_end):
                    event = self._read_event(f, self._records[index])
                    if event is None:
                        continue
                    data = event.to_dict()
                    data["text"] = event.text()
                    data["index"] = index
                    data["seq"] = index + 1
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
            "through_seq": total,
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
