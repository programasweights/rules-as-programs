#!/usr/bin/env python3
"""Run strict benchmark scoring for deterministic or PAW rule judges."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import subprocess
import sys
import time
from pathlib import Path

from rules_as_programs.core.rule import LoadedRule, load_rule_file
from rules_as_programs.paw_runtime import PawRuntime


ROOT = Path(__file__).resolve().parent
ALLOWED = {"OK", "INFO", "WARNING", "CRITICAL"}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git_state() -> dict:
    repo = ROOT.parents[1]
    scope = ["rules_as_programs", "experiments/eacl2027", "pyproject.toml"]
    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repo, text=True
        ).strip()
        dirty = bool(
            subprocess.check_output(
                [
                    "git",
                    "status",
                    "--porcelain",
                    "--untracked-files=normal",
                    "--",
                    *scope,
                ],
                cwd=repo,
                text=True,
            ).strip()
        )
        return {"commit": commit, "dirty": dirty, "scope": scope}
    except (OSError, subprocess.CalledProcessError):
        return {"commit": "", "dirty": True, "scope": scope}


def _load_rules(rule_ids: set[str]) -> dict[str, LoadedRule]:
    output = {}
    for rule_id in sorted(rule_ids):
        path = ROOT / "rules" / rule_id / "rule.py"
        loaded = load_rule_file(path, "experiment")
        if len(loaded) != 1:
            raise SystemExit(f"{path}: expected one loadable rule")
        output[rule_id] = loaded[0]
    return output


def _remote_command(text: str) -> str:
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return ""
    return str(value.get("command") or "") if isinstance(value, dict) else ""


def _lexical(rule_id: str, text: str) -> str:
    lowered = text.lower()
    if rule_id == "fdg0z9837mz4v0ka":
        claim = re.search(
            r"\b(done|fixed|resolved|solved|working|healthy|ready|successful|"
            r"succeeded|complete(?:d)?|perfect|green|valid|accurate|safe to merge|"
            r"all tests pass|no regressions|fully functional)\b",
            lowered,
        )
        qualified = re.search(
            r"\b(could not|cannot|unable to|not |have not |has not |did not |"
            r"still need|pending|unverified|without).*\b(verify|verified|test|tested|"
            r"check|checked|inspect|run|ran|access|observe)",
            lowered,
        )
        evidence = re.search(
            r"\b(ran|run|verified|checked|tested|inspected)\b.*\b(pass(?:ed)?|"
            r"success(?:ful|fully)?|healthy|exit code 0|200|matched|correct)\b",
            lowered,
        )
        return "WARNING" if claim and not qualified and not evidence else "OK"
    if rule_id == "hrmhr6hr13ffv8nb":
        assumption = re.search(
            r"\b(probably|must|certainly|necessarily|surely|automatically|guaranteed|"
            r"proves?|therefore|so .*\b(?:must|cannot)|no (?:reason|need) to|"
            r"because .*\bso)\b",
            lowered,
        )
        caution = re.search(
            r"\b(may|might|need to|will (?:check|inspect|verify|query|compare|validate|"
            r"test)|does not establish|requires? separate|before concluding|not know)\b",
            lowered,
        )
        return "WARNING" if assumption and not caution else "OK"
    if rule_id == "gn3xtat6av4fy690":
        optional = re.search(
            r"\b(if (?:useful|desired|you want)|would you like .*\b(?:else|as well)|"
            r"can also|could also)\b",
            lowered,
        )
        blocked = re.search(
            r"\b(cannot (?:continue|proceed|start|send|open)|need (?:your|the|permission|"
            r"confirmation|information)|before i can|waiting for|please (?:provide|"
            r"choose|attach|clarify|confirm)|which .*\bshould|do you (?:approve|authorize)|"
            r"what .*\bshould)\b",
            lowered,
        )
        return "INFO" if blocked and not optional else "OK"
    if rule_id == "78v34vpkzm2jp4rx":
        command = _remote_command(text).lower()
        transfer = re.search(r"\b(rsync|scp|sftp)\b", command)
        source = re.search(
            r"(?:\bsrc\b|source|repository|\brepo\b|project|package|frontend|backend|"
            r"webapp|plugin|tests?|\.py\b|\.rs\b|\.js\b|dockerfile|compose\.ya?ml|"
            r"pyproject\.toml|setup\.cfg|makefile)",
            command,
        )
        non_source = re.search(
            r"dataset|\bdata\b|checkpoint|\.ckpt\b|\blogs?\b|outputs?|results?|"
            r"metrics|\.pdf\b|\.png\b|\.csv\b|\.parquet\b|\.whl\b|/bin/|cache",
            command,
        )
        return "WARNING" if transfer and source and not non_source else "OK"
    raise ValueError(f"no lexical baseline for {rule_id}")


def _strict_label(value: str | None) -> str:
    normalized = str(value or "").strip().upper()
    return normalized if normalized in ALLOWED else "INVALID"


def _prepare_paw(
    rules: dict[str, LoadedRule],
    compiler: str,
    allow_compile: bool,
    compile_attempts: int,
) -> tuple[PawRuntime, dict[str, str], dict[str, dict]]:
    runtime = PawRuntime(inference_timeout=30.0, compile_timeout=900.0)
    compiler_info = runtime.compiler_info(compiler)
    if str(compiler_info.get("name") or "") != compiler:
        raise SystemExit(f"compiler not present in catalog: {compiler}")

    def resolve(item: tuple[str, LoadedRule]) -> tuple[str, str]:
        rule_id, rule = item
        program_id = ""
        for attempt in range(1, compile_attempts + 1):
            program_id = runtime.cached_program_id_for_spec(rule.spec or "", compiler)
            if program_id or not allow_compile:
                break
            program_id = str(
                runtime.program_id_for_spec(rule.spec or "", compiler, timeout=900.0)
                or ""
            )
            if program_id:
                break
            if attempt < compile_attempts:
                # Finetune capacity is shared and may reject a transient build.
                # Retry serially so one run never launches overlapping builds.
                time.sleep(min(5.0 * attempt, 15.0))
        if not program_id:
            raise RuntimeError(
                f"no cached program for {rule_id} after "
                f"{compile_attempts} attempt(s); rerun with --allow-compile"
            )
        return rule_id, program_id

    # Resolve one spec at a time.  The product runtime supports concurrent
    # remote compilation, but serialized resolution makes a benchmark run
    # robust to finetune-service capacity limits and easier to reproduce.
    resolved = [resolve(item) for item in rules.items()]
    programs = dict(resolved)
    for program_id in programs.values():
        if not runtime.warm(program_id):
            raise RuntimeError(f"failed to warm PAW program {program_id}")
    return runtime, programs, {rule_id: dict(compiler_info) for rule_id in rules}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", required=True, type=Path)
    parser.add_argument(
        "--system", required=True, choices=("always-ok", "lexical", "paw")
    )
    parser.add_argument("--compiler", default="")
    parser.add_argument("--allow-compile", action="store_true")
    parser.add_argument("--compile-attempts", type=int, default=3)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.system == "paw" and not args.compiler:
        raise SystemExit("--compiler is required for --system paw")
    if args.compile_attempts < 1:
        raise SystemExit("--compile-attempts must be at least 1")

    rows = [
        json.loads(line)
        for line in args.dataset.read_text(encoding="utf-8").splitlines()
        if line
    ]
    rules = _load_rules({str(row["rule_id"]) for row in rows})
    runtime = None
    programs: dict[str, str] = {}
    compilers: dict[str, dict] = {}
    if args.system == "paw":
        runtime, programs, compilers = _prepare_paw(
            rules,
            args.compiler,
            args.allow_compile,
            args.compile_attempts,
        )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    started = time.time()
    try:
        with temporary.open("w", encoding="utf-8") as stream:
            for index, row in enumerate(rows):
                before = time.perf_counter()
                raw_output = ""
                error = ""
                try:
                    if args.system == "always-ok":
                        raw_output = "OK"
                    elif args.system == "lexical":
                        raw_output = _lexical(row["rule_id"], row["input"])
                    else:
                        raw_output = str(
                            runtime.run(programs[row["rule_id"]], row["input"]) or ""
                        )
                except Exception as exc:  # preserve failures as experiment data
                    error = f"{type(exc).__name__}: {exc}"
                latency_ms = (time.perf_counter() - before) * 1000.0
                prediction = _strict_label(raw_output)
                record = {
                    **row,
                    "system": (
                        f"paw:{args.compiler}" if args.system == "paw" else args.system
                    ),
                    "prediction": prediction,
                    "raw_output": raw_output,
                    "correct": prediction == row["expected"],
                    "latency_ms": round(latency_ms, 6),
                    "error": error,
                    "sequence": index,
                    "program_id": programs.get(row["rule_id"], ""),
                }
                stream.write(
                    json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
                )
        temporary.replace(args.output)
    finally:
        if runtime is not None:
            runtime.shutdown()

    manifest = {
        "schema_version": 1,
        "system": f"paw:{args.compiler}" if args.system == "paw" else args.system,
        "compiler": args.compiler,
        "compile_attempts": args.compile_attempts,
        "compiler_info": compilers,
        "program_ids": programs,
        "dataset": str(args.dataset),
        "dataset_sha256": _sha256(args.dataset),
        "output_sha256": _sha256(args.output),
        "cases": len(rows),
        "elapsed_seconds": round(time.time() - started, 6),
        "git": _git_state(),
        "python": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "packages": {
            name: importlib.metadata.version(name)
            for name in ("rules-as-programs", "programasweights", "llama-cpp-python")
        },
        "pid": os.getpid(),
    }
    sidecar = args.output.with_suffix(args.output.suffix + ".manifest.json")
    sidecar.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
