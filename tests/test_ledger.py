from __future__ import annotations

import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from rules_as_programs.core.events import Event, MESSAGE
from rules_as_programs.core.ledger import Ledger


@pytest.fixture
def ledger(monkeypatch, tmp_path):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path / "state"))
    return Ledger("synthetic-session", str(tmp_path))


def _event(index, *, event_id=None):
    return Event(
        kind=MESSAGE,
        conversation_id="synthetic-session",
        project_root="/synthetic/project",
        id=str(index) if event_id is None else event_id,
        ts=float(index),
        payload={"text": f"synthetic message {index}: café 🌱"},
    )


def _line(event):
    return (json.dumps(event.to_dict(), ensure_ascii=False) + os.linesep).encode("utf-8")


def _expected_window(ledger, events, **options):
    through_seq = options.get("through_seq")
    if through_seq is not None:
        events = events[:max(0, int(through_seq))]
    total = len(events)
    center_id = options.get("center_event_id", "")
    center_index = next(
        (index for index, event in enumerate(events) if center_id and event.id == center_id),
        -1,
    )
    center_ts = options.get("center_ts")
    if center_index < 0 and center_ts is not None and events:
        center_index = min(range(total), key=lambda index: abs(events[index].ts - center_ts))
    if center_index < 0:
        center_index = max(0, total - 1)
    start = options.get("start")
    if start is None:
        start = max(0, center_index - max(0, options.get("before", 30)))
        end = min(total, center_index + max(0, options.get("after", 30)) + 1)
    else:
        start = max(0, min(int(start), total))
        end = min(total, start + max(1, int(options.get("limit", 60))))
    return {
        "events": [
            {**event.to_dict(), "text": event.text(), "index": index,
             "seq": index + 1, "is_trigger": index == center_index}
            for index, event in enumerate(events[start:end], start)
        ],
        "start": start,
        "end": end,
        "total": total,
        "center_index": center_index,
        "has_earlier": start > 0,
        "has_later": end < total,
        "path": str(ledger.path),
        "through_seq": total,
    }


@pytest.mark.parametrize("options", [
    {},
    {"center_event_id": "3", "before": 1, "after": 2},
    {"center_event_id": "duplicate", "before": 0, "after": 0},
    {"center_event_id": "missing", "center_ts": 4.5},
    {"center_event_id": "9", "through_seq": 4, "center_ts": 1.5},
    {"center_event_id": "9", "through_seq": 4},
    {"center_event_id": "3", "before": -1, "after": -2},
    {"center_event_id": "3", "start": 6, "limit": 2},
    {"start": -10, "limit": 0},
    {"start": 1000, "limit": 2},
    {"through_seq": 0},
    {"through_seq": -4},
    {"through_seq": 1000},
])
def test_indexed_window_matches_full_scan(ledger, options):
    events = [_event(index, event_id="duplicate" if index in (2, 7) else None)
              for index in range(10)]
    for event in events:
        ledger.append(event)
    expected = _expected_window(ledger, events, **options)
    assert ledger.context_window(**options) == expected
    assert ledger.context_window(**options) == expected
    assert ledger.event_position("duplicate") == (3, 10)
    assert ledger.event_position("missing") == (None, 10)
    assert ledger.event_position() == (None, 10)


def test_warm_reads_decode_only_window_and_append_keeps_index(ledger, monkeypatch):
    for index in range(200):
        ledger.append(_event(index))
    assert ledger.event_position("50") == (51, 200)
    decoded = []
    decode = Ledger._decode_event

    def counting_decode(raw):
        decoded.append(len(raw))
        return decode(raw)

    monkeypatch.setattr(ledger, "_decode_event", counting_decode)
    assert ledger.event_position("199") == (200, 200)
    assert decoded == []
    assert len(ledger.context_window("100", before=2, after=2)["events"]) == 5
    assert len(decoded) == 5
    decoded.clear()
    ledger.append(_event(200))
    assert ledger.event_position("200") == (201, 201)
    assert decoded == []
    window = ledger.context_window("199", before=0, after=10, through_seq=200)
    assert [row["id"] for row in window["events"]] == ["199"]
    assert len(decoded) == 1


@pytest.mark.parametrize("change", ["append", "replace", "truncate", "rewrite", "regrow"])
def test_external_file_changes_invalidate_index(ledger, change):
    original = [_event(index) for index in range(4)]
    for event in original:
        ledger.append(event)
    assert ledger.event_position("3") == (4, 4)
    if change == "append":
        expected = [*original, _event(4)]
        with ledger.path.open("ab") as f:
            f.write(_line(expected[-1]))
    else:
        expected = [_event(index + 4) for index in range(
            1 if change == "truncate" else 8 if change == "regrow" else 4)]
        raw = b"".join(_line(event) for event in expected)
        if change == "replace":
            replacement = ledger.path.with_suffix(".replacement")
            replacement.write_bytes(raw)
            replacement.replace(ledger.path)
        else:
            old_stat = ledger.path.stat()
            ledger.path.write_bytes(raw)
            if change == "rewrite":
                # Even a same-size rewrite must invalidate the prior offsets
                # and ID mapping; give it an explicit different timestamp.
                assert len(raw) == old_stat.st_size
                os.utime(ledger.path, ns=(old_stat.st_atime_ns, old_stat.st_mtime_ns + 1_000_000))
    assert ledger.context_window() == _expected_window(ledger, expected)
    assert ledger.event_position(expected[-1].id) == (len(expected), len(expected))


def test_external_change_before_local_append_does_not_extend_stale_index(ledger):
    ledger.append(_event(0))
    assert ledger.event_position("0") == (1, 1)
    ledger.path.write_bytes(_line(_event(1)))
    ledger.append(_event(2))
    assert ledger.event_position("0") == (None, 2)
    assert ledger.event_position("1") == (1, 2)
    assert ledger.event_position("2") == (2, 2)


def test_missing_deleted_and_recreated_ledger(ledger):
    assert ledger.event_position("0") == (None, 0)
    assert ledger.context_window() == _expected_window(ledger, [])
    ledger.append(_event(0))
    assert ledger.event_position("0") == (1, 1)
    ledger.path.unlink()
    assert ledger.context_window() == _expected_window(ledger, [])
    ledger.append(_event(1))
    assert ledger.event_position("1") == (1, 1)
    assert ledger.event_position("0") == (None, 1)


def test_malformed_records_and_incomplete_utf8_tail(ledger):
    first, second = _event(0), _event(1)
    line = _line(second)
    split = line.index("🌱".encode("utf-8")) + 1
    ledger.path.write_bytes(_line(first) + b'\nnot json\n{}\nnull\n[]\n' + line[:split])
    assert ledger.event_position(second.id) == (None, 1)
    assert ledger.context_window() == _expected_window(ledger, [first])
    with ledger.path.open("ab") as f:
        f.write(line[split:])
    assert ledger.context_window() == _expected_window(ledger, [first, second])
    assert ledger.event_position(second.id) == (2, 2)


@pytest.mark.parametrize("tail", [b'{"kind":', _line(_event(1)).rstrip(b"\r\n")])
def test_local_append_after_unterminated_tail_preserves_jsonl_behavior(ledger, tail):
    first = _event(0)
    ledger.path.write_bytes(_line(first) + tail)
    ledger.event_position()
    ledger.append(_event(2))
    # append() has always written exactly the event plus one newline. An old
    # unterminated tail therefore joins the next event into a malformed line.
    assert ledger.context_window() == _expected_window(ledger, [first])
    ledger.append(_event(3))
    assert ledger.context_window() == _expected_window(ledger, [first, _event(3)])


def test_complete_unterminated_record_and_legacy_defaults(ledger):
    event = _event(0)
    ledger.path.write_bytes(_line(event).rstrip(b"\r\n"))
    assert ledger.context_window() == _expected_window(ledger, [event])
    ledger.path.write_bytes(b'{"kind": "message", "payload": {"text": "legacy"}}\n')
    window = ledger.context_window()
    row = window["events"][0]
    assert row["id"]
    assert ledger.event_position(row["id"]) == (1, 1)
    assert ledger.context_window(row["id"])["events"][0] == row


def test_concurrent_appends_and_windows_share_consistent_index(ledger):
    ledger.append(_event(0))
    ledger.event_position()

    def append_and_read(index):
        event = _event(index)
        ledger.append(event)
        seq, total = ledger.event_position(event.id)
        assert seq is not None and seq <= total
        window = ledger.context_window(event.id, before=0, after=0, through_seq=seq)
        assert window["total"] == seq
        assert window["events"][0]["id"] == event.id
        assert window["events"][0]["seq"] == seq

    with ThreadPoolExecutor(max_workers=6) as executor:
        list(executor.map(append_and_read, range(1, 80)))
    events = ledger.events()
    assert len(events) == 80
    assert {event.id for event in events} == {str(index) for index in range(80)}
    assert ledger.context_window(start=0, limit=100) == _expected_window(
        ledger, events, start=0, limit=100)


@pytest.mark.parametrize("phase", ["cold_rebuild", "warm_window"])
def test_append_does_not_wait_for_index_read(ledger, monkeypatch, phase):
    first, second = _event(0), _event(1)
    ledger.append(first)
    if phase == "warm_window":
        ledger.event_position()
    method_name = "_rebuild_index" if phase == "cold_rebuild" else "_read_event"
    original = getattr(ledger, method_name)
    reader_paused = threading.Event()
    release_reader = threading.Event()

    def paused_read(*args):
        reader_paused.set()
        assert release_reader.wait(5), "test did not release the ledger reader"
        return original(*args)

    monkeypatch.setattr(ledger, method_name, paused_read)
    with ThreadPoolExecutor(max_workers=2) as executor:
        reader = executor.submit(ledger.context_window)
        try:
            assert reader_paused.wait(5), "ledger reader did not reach the pause"
            # The reader is still paused while append must finish. Using two
            # separate futures also lets a failing test release both workers.
            executor.submit(ledger.append, second).result(timeout=5)
        finally:
            release_reader.set()
        assert reader.result(timeout=5) == _expected_window(ledger, [first])

    assert ledger.event_position(second.id) == (2, 2)
    assert ledger.context_window() == _expected_window(ledger, [first, second])
    assert ledger.context_window(through_seq=1) == _expected_window(
        ledger, [first, second], through_seq=1)
