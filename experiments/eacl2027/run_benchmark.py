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
    value = _json_object(text)
    return str(value.get("command") or "")


def _json_object(text: str) -> dict:
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def _is_generated_or_lock_path(value: str) -> bool:
    path = value.strip("'\" ").replace("\\", "/").lower()
    segments = [segment for segment in path.split("/") if segment not in {"", "."}]
    name = segments[-1] if segments else ""
    lock_names = {
        "bun.lock",
        "bun.lockb",
        "cargo.lock",
        "composer.lock",
        "gemfile.lock",
        "package-lock.json",
        "pnpm-lock.yaml",
        "poetry.lock",
        "uv.lock",
        "yarn.lock",
    }
    generated_directories = {
        ".next",
        ".nuxt",
        "build",
        "coverage",
        "dist",
        "generated",
        "out",
    }
    return (
        name in lock_names
        or name.endswith(".generated.json")
        or name.endswith(".generated.py")
        or any(segment in generated_directories for segment in segments[:-1])
    )


def _actions_run_fragments(payload: str) -> list[str]:
    """Return shell fragments located in YAML ``run`` values or blocks."""
    fragments: list[str] = []
    lines = payload.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        normalized = re.sub(r"^(\s*)[+-]\s?", r"\1", line)
        match = re.match(r"^(\s*)run\s*:\s*(.*)$", normalized)
        if not match:
            index += 1
            continue
        indentation = len(match.group(1))
        value = match.group(2)
        if value not in {"|", ">", "|-", ">-", "|+", ">+"}:
            fragments.append(value)
            index += 1
            continue
        block: list[str] = []
        index += 1
        while index < len(lines):
            candidate = re.sub(r"^(\s*)[+-]\s?", r"\1", lines[index])
            if (
                candidate.strip()
                and len(candidate) - len(candidate.lstrip()) <= indentation
            ):
                break
            block.append(candidate)
            index += 1
        fragments.append("\n".join(block))
    return fragments


def _contains_untrusted_actions_expression(value: str) -> bool:
    expression = re.compile(
        r"\$\{\{\s*(?:"
        r"inputs\.\w+|"
        r"steps\.\w+\.outputs\.\w+|"
        r"github\.head_ref|"
        r"github\.ref_name|"
        r"github\.event\.head_commit\.message|"
        r"github\.event\.(?:issue|pull_request)\.(?:body|title)|"
        r"github\.event\.pull_request\.head\.(?:ref|label)"
        r")\s*\}\}",
        re.IGNORECASE,
    )
    return bool(expression.search(value))


def _markdown_link_targets(value: str) -> list[str]:
    return re.findall(r"(?<!!)\[[^\]]+\]\(\s*<?([^\s)>]+)>?", value)


def _is_source_code_path(value: str) -> bool:
    return Path(value).suffix.lower() in {".c", ".cc", ".cpp", ".cs", ".cxx", ".h"}


def _has_license_header(value: str) -> bool:
    header = "\n".join(value.splitlines()[:20]).lower()
    return bool(
        re.search(r"\bcopyright\b|\blicensed under\b|spdx-license-identifier", header)
    )


def _is_destructive_git_command(command: str) -> bool:
    if not re.search(r"(?:^|[;&|()'\"]\s*)git\s+", command):
        return False

    clean = re.search(r"\bgit\s+clean\b([^;&|]*)", command)
    if clean:
        options = re.findall(r"(?:^|\s)(--[a-z-]+|-[a-z]+)", clean.group(1))
        forced = "--force" in options or any(
            option.startswith("-") and not option.startswith("--") and "f" in option
            for option in options
        )
        dry_run = "--dry-run" in options or any(
            option.startswith("-") and not option.startswith("--") and "n" in option
            for option in options
        )
        if forced and not dry_run:
            return True

    restore = re.search(r"\bgit\s+restore\b([^;&|]*)", command)
    if restore:
        arguments = restore.group(1)
        if "--worktree" in arguments or "--staged" not in arguments:
            return True

    return bool(
        re.search(
            r"\bgit\s+(?:"
            r"reset\b[^;&|]*--hard|"
            r"push\b[^;&|]*(?:--force(?:-with-lease)?\b|-f\b|"
            r"--delete\b|\s:[^\s]+)|"
            r"branch\b[^;&|]*(?:-d\b|--delete\b)|"
            r"checkout\b[^;&|]*(?:--force\b|-f\b|--\s+\S+)|"
            r"filter-(?:branch|repo)\b|"
            r"reflog\s+expire\b|"
            r"stash\s+(?:drop|clear)\b|"
            r"update-ref\s+-d\b"
            r")",
            command,
        )
    )


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
    if rule_id == "98z9wvr031840p4g":
        command = _remote_command(text).lower()
        disallowed = re.search(
            r"(?:^|[;&|()'\"]|\b(?:corepack|env|exec|sudo)\s+)\s*"
            r"(?:npm|yarn)(?=\s|$)",
            command,
        )
        return "WARNING" if disallowed else "OK"
    if rule_id == "g3b7damk0b5xgdj6":
        command = _remote_command(text).lower()
        commit = re.search(r"\bgit\s+commit\b", command)
        ai_name = r"(?:ai\b|chatgpt|claude(?:\s+code)?|copilot|gemini)"
        attribution = (
            rf"(?:assisted[- ]by|authored[- ]by|co-authored[- ]by|generated|"
            rf"produced|written|contribution)[^'\"\n]{{0,36}}{ai_name}|"
            rf"{ai_name}[^'\"\n]{{0,36}}(?:assisted|authored|generated|produced|"
            rf"written|contribution)"
        )
        return "WARNING" if commit and re.search(attribution, command) else "OK"
    if rule_id == "3pcxewp5hggr1vsn":
        command = _remote_command(text).lower()
        return "WARNING" if _is_destructive_git_command(command) else "OK"
    if rule_id == "xb24rc14cpcrsf4g":
        value = _json_object(text)
        file_path = str(value.get("file_path") or "")
        if file_path and _is_generated_or_lock_path(file_path):
            if "content" in value or "patch" in value:
                return "WARNING"
        command = str(value.get("command") or "")
        generated_target = any(
            _is_generated_or_lock_path(token)
            for token in re.findall(r"[^\s;&|]+", command)
        )
        mutation = re.search(
            r"(?:^|[;&|]\s*)(?:git\s+add|rm|mv|cp|install|touch|truncate|"
            r"sed\s+[^;&|]*-i\b|perl\s+[^;&|]*-i\b)",
            command,
            re.IGNORECASE,
        )
        return "WARNING" if generated_target and mutation else "OK"
    if rule_id == "q88xgdmftag16dq9":
        value = _json_object(text)
        file_path = str(value.get("file_path") or "").replace("\\", "/").lower()
        if ".github/workflows/" not in f"/{file_path.lstrip('/')}":
            return "OK"
        payload = str(value.get("patch") or value.get("content") or "")
        unsafe = any(
            _contains_untrusted_actions_expression(fragment)
            for fragment in _actions_run_fragments(payload)
        )
        return "WARNING" if unsafe else "OK"
    if rule_id == "qfh0h1cf4wt5aeg4":
        value = _json_object(text)
        file_path = str(value.get("file_path") or "")
        if Path(file_path).suffix.lower() not in {".md", ".mdx"}:
            return "OK"
        payload = str(value.get("content") or value.get("patch") or "")
        added_titles: list[str] = []
        for line in payload.splitlines():
            stripped = line.lstrip()
            if stripped.startswith("-") and not stripped.startswith("---"):
                continue
            normalized = stripped[1:].lstrip() if stripped.startswith("+") else stripped
            match = re.match(r"title\s*:\s*(.*?)\s*$", normalized, re.IGNORECASE)
            if match:
                added_titles.append(match.group(1).strip("'\" "))
        violates = any(
            not re.search(r"(?:^|\s)source$", title, re.IGNORECASE)
            for title in added_titles
        )
        return "WARNING" if violates else "OK"
    if rule_id == "e3m4bdwj6gqcwpnn":
        value = _json_object(text)
        payload = str(value.get("patch") or value.get("content") or "")
        for target in _markdown_link_targets(payload):
            lowered_target = target.lower()
            if re.match(r"(?:[a-z][a-z0-9+.-]*:|//|#)", lowered_target):
                continue
            page_path = re.split(r"[?#]", lowered_target, maxsplit=1)[0].rstrip("/")
            if page_path.endswith((".md", ".mdx", ".markdown")):
                return "WARNING"
        return "OK"
    if rule_id == "sr09vpkt60y74r0q":
        value = _json_object(text)
        file_path = str(value.get("file_path") or "")
        if not _is_source_code_path(file_path):
            return "OK"
        if "content" in value:
            return "OK" if _has_license_header(str(value["content"])) else "WARNING"
        patch = str(value.get("patch") or "")
        removed_header = any(
            line.lstrip().startswith("-")
            and re.search(
                r"\bcopyright\b|\blicensed under\b|spdx-license-identifier",
                line,
                re.IGNORECASE,
            )
            for line in patch.splitlines()
        )
        return "WARNING" if removed_header else "OK"
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
