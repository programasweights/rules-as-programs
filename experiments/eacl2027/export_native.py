#!/usr/bin/env python3
"""Stream private RAP ledgers into a minimal native-Codex candidate pool.

The output contains only the exact mapped Stop or PreToolUse input plus hashed
identifiers.  Raw payloads, project roots, paths supplied by Codex, model names,
and surrounding events are never copied.  Output remains private until every
input receives manual privacy review.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parents[1]

SENSITIVE_PATTERNS = {
    "email": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "secret_marker": re.compile(
        r"(?i)(?:api[_-]?key|access[_-]?token|private[_-]?key|password|secret)"
    ),
}


def _require_git_ignored_private_output(
    output: Path, repo_root: Path = REPO_ROOT
) -> None:
    """Refuse private text at a normally stageable path inside this repo."""
    resolved_repo = repo_root.resolve()
    resolved_output = output.expanduser().resolve()
    try:
        relative = resolved_output.relative_to(resolved_repo)
    except ValueError:
        return
    if relative.parts and relative.parts[0] == ".git":
        raise SystemExit("refusing to write private native input under .git")
    try:
        tracked = (
            subprocess.run(
                ["git", "ls-files", "--error-unmatch", "--", str(relative)],
                cwd=resolved_repo,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            ).returncode
            == 0
        )
        ignored = (
            subprocess.run(
                ["git", "check-ignore", "--quiet", "--no-index", "--", str(relative)],
                cwd=resolved_repo,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            ).returncode
            == 0
        )
    except OSError as exc:
        raise SystemExit(
            "cannot verify that the private output is Git-ignored; refusing to write"
        ) from exc
    if tracked or not ignored:
        raise SystemExit(
            "private native output inside the repository must be untracked and "
            f"Git-ignored: {relative}"
        )


def _canonical(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _hash(salt: str, value: str, length: int = 24) -> str:
    digest = hashlib.sha256(f"{salt}\x00{value}".encode("utf-8")).hexdigest()
    return digest[:length]


def _candidate(event: dict[str, Any], salt: str) -> tuple[dict[str, Any], str] | None:
    hook = str(event.get("hook_name") or "")
    raw = event.get("raw_payload")
    if hook not in {"Stop", "PreToolUse"} or not isinstance(raw, dict):
        return None
    if str(raw.get("hook_event_name") or hook) != hook:
        return None
    session = str(raw.get("session_id") or event.get("conversation_id") or "")
    turn = str(raw.get("turn_id") or event.get("generation_id") or "")
    if hook == "Stop":
        value = raw.get("last_assistant_message")
        if not isinstance(value, str) or not value.strip():
            return None
        input_text = value
        identity = (session, turn, hook, hashlib.sha256(value.encode()).hexdigest())
        tool_name = ""
    else:
        if "tool_input" not in raw:
            return None
        input_text = _canonical(raw.get("tool_input"))
        if not input_text.strip():
            return None
        tool_name = str(raw.get("tool_name") or "")
        tool_use_id = str(raw.get("tool_use_id") or "")
        identity = (
            session,
            turn,
            hook,
            tool_use_id,
            tool_name,
            hashlib.sha256(input_text.encode()).hexdigest(),
        )
    identity_text = json.dumps(identity, separators=(",", ":"))
    case_id = _hash(salt, identity_text)
    row = {
        "case_id": case_id,
        "conversation_id": _hash(salt, session),
        "turn_id": _hash(salt, f"{session}\x00{turn}"),
        "hook": hook,
        "input": input_text,
        "input_sha256": hashlib.sha256(input_text.encode("utf-8")).hexdigest(),
        "input_bytes": len(input_text.encode("utf-8")),
        "provenance": "native_codex",
        "privacy_status": "UNREVIEWED_PRIVATE",
    }
    if tool_name:
        row["tool_name"] = tool_name
    return row, identity_text


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--salt", required=True)
    parser.add_argument("--max-input-bytes", type=int, default=65536)
    args = parser.parse_args()

    _require_git_ignored_private_output(args.output)

    paths = sorted(args.ledger_dir.glob("*.jsonl"))
    if not paths:
        raise SystemExit(f"no JSONL ledgers found under {args.ledger_dir}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.inventory.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")

    seen = set()
    counts = Counter()
    sensitivity = Counter()
    output_hash = hashlib.sha256()
    started = time.time()
    with temporary.open("w", encoding="utf-8") as target:
        for path in paths:
            counts["source_files"] += 1
            try:
                counts["source_bytes"] += path.stat().st_size
            except OSError:
                pass
            try:
                stream = path.open(encoding="utf-8")
            except OSError:
                counts["source_open_errors"] += 1
                continue
            with stream:
                for raw_line in stream:
                    counts["ledger_rows"] += 1
                    try:
                        event = json.loads(raw_line)
                    except json.JSONDecodeError:
                        counts["parse_errors"] += 1
                        continue
                    hook = str(event.get("hook_name") or "")
                    if hook in {"Stop", "PreToolUse"}:
                        counts[f"{hook}_raw"] += 1
                    value = _candidate(event, args.salt)
                    if value is None:
                        continue
                    row, identity = value
                    if identity in seen:
                        counts[f"{row['hook']}_duplicates"] += 1
                        continue
                    seen.add(identity)
                    if row["input_bytes"] > args.max_input_bytes:
                        counts[f"{row['hook']}_oversized"] += 1
                        continue
                    for name, pattern in SENSITIVE_PATTERNS.items():
                        if pattern.search(row["input"]):
                            sensitivity[name] += 1
                    encoded = (
                        json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
                    ).encode("utf-8")
                    target.write(encoded.decode("utf-8"))
                    output_hash.update(encoded)
                    counts[f"{row['hook']}_unique"] += 1
                    counts["retained"] += 1
    temporary.replace(args.output)

    inventory = {
        "schema_version": 1,
        "provenance": "private_native_codex",
        "generated_at_unix": time.time(),
        "elapsed_seconds": round(time.time() - started, 3),
        "counts": dict(sorted(counts.items())),
        "potentially_sensitive_retained_inputs": dict(sorted(sensitivity.items())),
        "output_sha256": output_hash.hexdigest(),
        "output_bytes": args.output.stat().st_size,
        "max_input_bytes": args.max_input_bytes,
        "privacy_notice": (
            "Output is private and unreviewed. Do not commit or release it. "
            "Every retained input requires manual privacy review."
        ),
    }
    args.inventory.write_text(
        json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(inventory, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
