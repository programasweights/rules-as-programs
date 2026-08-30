#!/usr/bin/env python3
"""Run the exact unadapted Qwen3-0.6B Q6_K interpreter used by PAW.

This is a matched-base diagnostic, not a PAW program: it loads the same
content-addressed GGUF interpreter but never loads a per-spec LoRA adapter.
The rule specification and observed input use the same message builder as the
independent Hugging Face judge. Generation follows PAW's llama.cpp path with
temperature zero and no truncation.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from experiments.eacl2027.run_benchmark import (  # noqa: E402
    _git_state,
    _load_rules,
    _sha256,
    _strict_label,
)
from experiments.eacl2027.run_open_judge import (  # noqa: E402
    SYSTEM_PROMPT,
    build_messages,
)


RUNTIME_ID = "qwen3-0.6b-q6_k"
INTERPRETER = "Qwen/Qwen3-0.6B"
MODEL_REPOSITORY = "programasweights/Qwen3-0.6B-GGUF-Q6_K"
MODEL_FILE = "qwen3-0.6b-q6_k.gguf"
MODEL_SIZE_BYTES = 622_733_120
MODEL_SHA256 = "9a16ed5cacba959e63b62e2b6840c3eca2b51c3c3e51d31367ef8e4aafeae33c"
N_CTX = 2048
SYSTEM_NAME = f"open-judge-matched-base:{INTERPRETER}:{RUNTIME_ID}"
QWEN3_MESSAGE_TEMPLATE = "<|im_start|>{role}\n{content}<|im_end|>\n"
QWEN3_NO_THINKING_PREFIX = (
    "<|im_start|>assistant\n<think>\n\n</think>\n\n"
)
GGUF_METADATA_KEYS = (
    "general.architecture",
    "general.name",
    "general.file_type",
    "general.quantization_version",
    "qwen3.context_length",
    "tokenizer.ggml.model",
)


@dataclass(frozen=True)
class RuntimeAssets:
    manifest: dict[str, Any]
    manifest_sha256: str
    manifest_source: str
    model_path: Path
    model_sha256: str
    model_size_bytes: int


def _canonical_json_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _default_paw_cache() -> Path:
    return Path(
        os.environ.get(
            "PAW_CACHE_DIR",
            str(Path.home() / ".cache" / "programasweights"),
        )
    )


def _read_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read JSON object {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{path}: expected a JSON object")
    return value


def _embedded_runtime_manifests(cache_dir: Path) -> list[tuple[Path, dict[str, Any]]]:
    candidates = []
    for meta_path in sorted((cache_dir / "programs").glob("*/meta.json")):
        meta = _read_json_object(meta_path)
        runtime = meta.get("runtime")
        if (
            meta.get("runtime_id") == RUNTIME_ID
            and isinstance(runtime, dict)
            and runtime.get("runtime_id") == RUNTIME_ID
        ):
            candidates.append((meta_path, runtime))
    return candidates


def _discover_runtime_manifest(
    cache_dir: Path,
    explicit_path: Path | None = None,
) -> tuple[dict[str, Any], str]:
    if explicit_path is not None:
        return _read_json_object(explicit_path), f"explicit:{explicit_path.name}"

    cached_path = cache_dir / "runtimes" / f"{RUNTIME_ID}.json"
    if cached_path.exists():
        return _read_json_object(cached_path), f"cache:runtimes/{cached_path.name}"

    embedded = _embedded_runtime_manifests(cache_dir)
    if not embedded:
        raise SystemExit(
            f"runtime manifest {RUNTIME_ID!r} is not cached under {cache_dir}; "
            "prepare one PAW program with this runtime first or pass "
            "--runtime-manifest"
        )
    canonical = {_canonical_json_sha256(value) for _path, value in embedded}
    if len(canonical) != 1:
        paths = ", ".join(str(path) for path, _value in embedded[:5])
        raise SystemExit(f"conflicting embedded runtime manifests: {paths}")
    meta_path, runtime = embedded[0]
    return runtime, f"embedded:programs/{meta_path.parent.name}/meta.json"


def _validate_runtime_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    local_sdk = manifest.get("local_sdk")
    base_model = local_sdk.get("base_model") if isinstance(local_sdk, dict) else None
    expected = {
        "runtime_id": RUNTIME_ID,
        "interpreter": INTERPRETER,
        "adapter_format": "gguf_lora",
    }
    mismatches = {
        key: {"expected": value, "observed": manifest.get(key)}
        for key, value in expected.items()
        if manifest.get(key) != value
    }
    if not isinstance(local_sdk, dict) or local_sdk.get("supported") is not True:
        mismatches["local_sdk.supported"] = {
            "expected": True,
            "observed": None if not isinstance(local_sdk, dict) else local_sdk.get("supported"),
        }
    if not isinstance(local_sdk, dict) or local_sdk.get("n_ctx") != N_CTX:
        mismatches["local_sdk.n_ctx"] = {
            "expected": N_CTX,
            "observed": None if not isinstance(local_sdk, dict) else local_sdk.get("n_ctx"),
        }
    expected_base = {
        "repo": MODEL_REPOSITORY,
        "file": MODEL_FILE,
        "size_bytes": MODEL_SIZE_BYTES,
        "sha256": MODEL_SHA256,
    }
    for key, value in expected_base.items():
        observed = base_model.get(key) if isinstance(base_model, dict) else None
        if observed != value:
            mismatches[f"local_sdk.base_model.{key}"] = {
                "expected": value,
                "observed": observed,
            }
    if mismatches:
        raise SystemExit(
            "runtime manifest is not the frozen matched PAW interpreter: "
            + json.dumps(mismatches, sort_keys=True)
        )
    return base_model


def _resolve_runtime_assets(
    cache_dir: Path,
    runtime_manifest_path: Path | None = None,
    model_path: Path | None = None,
) -> RuntimeAssets:
    manifest, source = _discover_runtime_manifest(cache_dir, runtime_manifest_path)
    _validate_runtime_manifest(manifest)
    resolved_model = model_path or cache_dir / "base_models" / MODEL_FILE
    if not resolved_model.is_file():
        raise SystemExit(
            f"exact matched base model is not present: {resolved_model}; "
            "this runner never downloads or substitutes model bytes"
        )
    observed_size = resolved_model.stat().st_size
    if observed_size != MODEL_SIZE_BYTES:
        raise SystemExit(
            f"matched model size differs: {observed_size} != {MODEL_SIZE_BYTES}"
        )
    observed_sha = _sha256(resolved_model)
    if observed_sha != MODEL_SHA256:
        raise SystemExit(
            f"matched model SHA-256 differs: {observed_sha} != {MODEL_SHA256}"
        )
    return RuntimeAssets(
        manifest=manifest,
        manifest_sha256=_canonical_json_sha256(manifest),
        manifest_source=source,
        model_path=resolved_model,
        model_sha256=observed_sha,
        model_size_bytes=observed_size,
    )


def render_qwen3_no_thinking(messages: list[dict[str, str]]) -> str:
    """Render Qwen3 chat messages exactly, with thinking disabled."""
    parts = []
    for message in messages:
        role = message.get("role")
        content = message.get("content")
        if role not in {"system", "user", "assistant"} or not isinstance(content, str):
            raise ValueError(f"unsupported chat message: {message!r}")
        parts.append(QWEN3_MESSAGE_TEMPLATE.format(role=role, content=content))
    parts.append(QWEN3_NO_THINKING_PREFIX)
    return "".join(parts)


class MatchedBaseJudge:
    """Unadapted llama.cpp judge over the frozen PAW base interpreter."""

    def __init__(
        self,
        assets: RuntimeAssets,
        *,
        n_gpu_layers: int = 0,
        n_threads: int | None = None,
        seed: int = 0,
        verbose: bool = False,
        llama_factory: Callable[..., Any] | None = None,
    ) -> None:
        if llama_factory is None:
            from llama_cpp import Llama

            llama_factory = Llama
        kwargs: dict[str, Any] = {
            "model_path": str(assets.model_path),
            "n_ctx": N_CTX,
            "n_gpu_layers": n_gpu_layers,
            "seed": seed,
            "verbose": verbose,
        }
        if n_threads is not None:
            kwargs["n_threads"] = n_threads
            kwargs["n_threads_batch"] = n_threads
        self.llm = llama_factory(**kwargs)
        self.load_parameters = {
            **{key: value for key, value in kwargs.items() if key != "model_path"},
            "model_file": assets.model_path.name,
        }

    def prompt_token_count(self, prompt: str) -> int:
        return len(
            self.llm.tokenize(
                prompt.encode("utf-8"),
                add_bos=False,
                special=True,
            )
        )

    def generate(self, prompt: str, max_new_tokens: int) -> tuple[str, int]:
        self.llm.reset()
        prompt_tokens = self.llm.tokenize(
            prompt.encode("utf-8"),
            add_bos=False,
            special=True,
        )
        if len(prompt_tokens) + max_new_tokens > N_CTX:
            raise ValueError(
                f"full prompt uses {len(prompt_tokens)} tokens and leaves fewer than "
                f"{max_new_tokens} generation tokens in the {N_CTX}-token context; "
                "refusing to truncate"
            )
        self.llm.eval(prompt_tokens)
        output_tokens = []
        for _ in range(max_new_tokens):
            token = self.llm.sample(temp=0)
            if token == self.llm.token_eos():
                break
            output_tokens.append(token)
            self.llm.eval([token])
        raw = self.llm.detokenize(output_tokens).decode(
            "utf-8", errors="replace"
        ).strip()
        return raw, len(prompt_tokens)

    def selected_metadata(self) -> dict[str, Any]:
        metadata = getattr(self.llm, "metadata", {})
        if not isinstance(metadata, dict):
            return {}
        return {key: metadata[key] for key in GGUF_METADATA_KEYS if key in metadata}


def _run_repeated(
    judge: MatchedBaseJudge,
    prompt: str,
    *,
    repeat_count: int,
    max_new_tokens: int,
) -> tuple[str, list[float], int]:
    outputs = []
    latencies = []
    prompt_tokens = None
    for _ in range(repeat_count):
        before = time.perf_counter()
        raw, observed_prompt_tokens = judge.generate(prompt, max_new_tokens)
        latencies.append((time.perf_counter() - before) * 1000.0)
        outputs.append(raw)
        if prompt_tokens is None:
            prompt_tokens = observed_prompt_tokens
        elif prompt_tokens != observed_prompt_tokens:
            raise RuntimeError("token count changed across deterministic repeats")
    if len(set(outputs)) != 1:
        hashes = [_text_sha256(value) for value in outputs]
        raise RuntimeError(f"raw output changed across deterministic repeats: {hashes}")
    return outputs[0], latencies, int(prompt_tokens or 0)


def _repeat_signatures(rows: list[dict[str, Any]]) -> list[tuple[Any, ...]]:
    return [
        (
            row.get("sequence"),
            row.get("case_id"),
            row.get("raw_output"),
            row.get("prediction"),
            row.get("repeat_raw_output_sha256"),
        )
        for row in rows
    ]


def _verify_against(
    rows: list[dict[str, Any]],
    prior_path: Path,
) -> dict[str, Any]:
    prior = [
        json.loads(line)
        for line in prior_path.read_text(encoding="utf-8").splitlines()
        if line
    ]
    if _repeat_signatures(rows) != _repeat_signatures(prior):
        current_by_id = {str(row.get("case_id")): row for row in rows}
        prior_by_id = {str(row.get("case_id")): row for row in prior}
        changed = sorted(
            case_id
            for case_id in set(current_by_id) | set(prior_by_id)
            if _repeat_signatures([current_by_id.get(case_id, {})])
            != _repeat_signatures([prior_by_id.get(case_id, {})])
        )[:5]
        raise RuntimeError(
            f"deterministic repeat differs from {prior_path}: changed={changed}"
        )
    return {
        "path": str(prior_path),
        "sha256": _sha256(prior_path),
        "exact_raw_outputs_match": True,
    }


def _package_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return "not-installed"


def _write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _build_manifest(
    *,
    args: argparse.Namespace,
    assets: RuntimeAssets,
    dataset_sha256: str,
    output_sha256: str,
    cases: int,
    elapsed_seconds: float,
    prompt_token_counts: list[int],
    judge: MatchedBaseJudge,
    rule_spec_sha256: dict[str, str],
    against: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "system": SYSTEM_NAME,
        "cases": cases,
        "dataset": str(args.dataset),
        "dataset_sha256": dataset_sha256,
        "output_sha256": output_sha256,
        "elapsed_seconds": round(elapsed_seconds, 6),
        "matched_base": {
            "adapter_applied": False,
            "runtime_id": RUNTIME_ID,
            "runtime_manifest_sha256": assets.manifest_sha256,
            "runtime_manifest_source": assets.manifest_source,
            "runtime_manifest_version": assets.manifest.get("manifest_version"),
            "display_name": assets.manifest.get("display_name"),
            "interpreter": INTERPRETER,
            "repository": MODEL_REPOSITORY,
            "file": MODEL_FILE,
            "content_sha256": assets.model_sha256,
            "size_bytes": assets.model_size_bytes,
            "identity": "exact GGUF content SHA-256",
            "gguf_metadata": judge.selected_metadata(),
        },
        "prompt": {
            "system": SYSTEM_PROMPT,
            "system_sha256": _text_sha256(SYSTEM_PROMPT),
            "message_builder": "experiments.eacl2027.run_open_judge.build_messages",
            "rule_specification_and_observed_input_framing": "identical to run_open_judge",
            "qwen3_rendering": QWEN3_MESSAGE_TEMPLATE
            + QWEN3_NO_THINKING_PREFIX,
            "qwen3_rendering_sha256": _text_sha256(
                QWEN3_MESSAGE_TEMPLATE + QWEN3_NO_THINKING_PREFIX
            ),
            "thinking": "disabled",
            "observed_input_delimited_as_untrusted_data": True,
            "rule_spec_sha256": rule_spec_sha256,
        },
        "decoding": {
            "backend": "llama.cpp low-level token loop used by PAW",
            "temperature": 0,
            "greedy": True,
            "max_new_tokens": args.max_new_tokens,
            "n_ctx": N_CTX,
            "input_truncation": False,
            "add_bos": False,
            "minimum_prompt_tokens_observed": min(prompt_token_counts),
            "maximum_prompt_tokens_observed": max(prompt_token_counts),
            "seed": args.seed,
            "repeat_count_per_case": args.repeat_count,
            "all_within_run_raw_outputs_identical": True,
        },
        "repeat_verification": {
            "within_run_exact_raw_output_repeats": args.repeat_count,
            "against_prior_output": against,
        },
        "runtime": {
            "n_gpu_layers": args.n_gpu_layers,
            "n_threads": args.n_threads,
            "load_parameters": judge.load_parameters,
            "latency_definition": (
                "first sequential prompt-to-raw-output generation wall time; "
                "verification-repeat times are stored per row"
            ),
        },
        "git": _git_state(),
        "python": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "packages": {
            "llama-cpp-python": _package_version("llama-cpp-python"),
            "programasweights": _package_version("programasweights"),
            "rules-as-programs": _package_version("rules-as-programs"),
        },
        "pid": os.getpid(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--paw-cache", type=Path, default=_default_paw_cache())
    parser.add_argument("--runtime-manifest", type=Path)
    parser.add_argument("--model-path", type=Path)
    parser.add_argument("--max-new-tokens", type=int, default=8)
    parser.add_argument("--repeat-count", type=int, default=2)
    parser.add_argument("--verify-against", type=Path)
    parser.add_argument("--n-gpu-layers", type=int, default=0)
    parser.add_argument("--n-threads", type=int)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    if args.max_new_tokens < 1:
        raise SystemExit("--max-new-tokens must be at least 1")
    if args.repeat_count < 2:
        raise SystemExit("--repeat-count must be at least 2")
    if args.verify_against is not None and not args.verify_against.is_file():
        raise SystemExit(f"--verify-against does not exist: {args.verify_against}")

    assets = _resolve_runtime_assets(
        args.paw_cache,
        args.runtime_manifest,
        args.model_path,
    )
    rows = [
        json.loads(line)
        for line in args.dataset.read_text(encoding="utf-8").splitlines()
        if line
    ]
    if not rows:
        raise SystemExit("dataset is empty")
    rules = _load_rules({str(row["rule_id"]) for row in rows})
    judge = MatchedBaseJudge(
        assets,
        n_gpu_layers=args.n_gpu_layers,
        n_threads=args.n_threads,
        seed=args.seed,
        verbose=args.verbose,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    started = time.time()
    output_rows = []
    prompt_token_counts = []
    try:
        with temporary.open("w", encoding="utf-8") as stream:
            for sequence, row in enumerate(rows):
                rule = rules[str(row["rule_id"])]
                prompt = render_qwen3_no_thinking(
                    build_messages(rule.spec or "", str(row["input"]))
                )
                raw_output, latencies, prompt_tokens = _run_repeated(
                    judge,
                    prompt,
                    repeat_count=args.repeat_count,
                    max_new_tokens=args.max_new_tokens,
                )
                prompt_token_counts.append(prompt_tokens)
                prediction = _strict_label(raw_output)
                record = {
                    **row,
                    "system": SYSTEM_NAME,
                    "prediction": prediction,
                    "raw_output": raw_output,
                    "correct": prediction == row["expected"],
                    "latency_ms": round(latencies[0], 6),
                    "latency_definition": (
                        "first sequential matched-base generation wall time"
                    ),
                    "verification_repeat_latency_ms": [
                        round(value, 6) for value in latencies[1:]
                    ],
                    "error": "",
                    "sequence": sequence,
                    "program_id": "",
                    "adapter_applied": False,
                    "repeat_count": args.repeat_count,
                    "repeat_verified": True,
                    "repeat_raw_output_sha256": _text_sha256(raw_output),
                    "prompt_tokens": prompt_tokens,
                }
                output_rows.append(record)
                stream.write(
                    json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
                )

        against = (
            _verify_against(output_rows, args.verify_against)
            if args.verify_against is not None
            else None
        )
        os.replace(temporary, args.output)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise

    manifest = _build_manifest(
        args=args,
        assets=assets,
        dataset_sha256=_sha256(args.dataset),
        output_sha256=_sha256(args.output),
        cases=len(rows),
        elapsed_seconds=time.time() - started,
        prompt_token_counts=prompt_token_counts,
        judge=judge,
        rule_spec_sha256={
            rule_id: _text_sha256(rule.spec or "")
            for rule_id, rule in sorted(rules.items())
        },
        against=against,
    )
    sidecar = args.output.with_suffix(args.output.suffix + ".manifest.json")
    _write_json_atomic(sidecar, manifest)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
