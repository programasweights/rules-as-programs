from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments.eacl2027 import run_matched_base_judge as matched


def _runtime_manifest() -> dict:
    return {
        "runtime_id": matched.RUNTIME_ID,
        "manifest_version": 1,
        "display_name": "Qwen3 0.6B (Q6_K)",
        "interpreter": matched.INTERPRETER,
        "adapter_format": "gguf_lora",
        "prompt_template": {
            "format": "rendered_text",
            "placeholder": "{INPUT_PLACEHOLDER}",
        },
        "local_sdk": {
            "supported": True,
            "n_ctx": matched.N_CTX,
            "base_model": {
                "provider": "huggingface",
                "repo": matched.MODEL_REPOSITORY,
                "file": matched.MODEL_FILE,
                "size_bytes": matched.MODEL_SIZE_BYTES,
                "sha256": matched.MODEL_SHA256,
            },
        },
    }


def _assets(model_path: Path) -> matched.RuntimeAssets:
    manifest = _runtime_manifest()
    return matched.RuntimeAssets(
        manifest=manifest,
        manifest_sha256=matched._canonical_json_sha256(manifest),
        manifest_source="cache:runtimes/qwen3-0.6b-q6_k.json",
        model_path=model_path,
        model_sha256=matched.MODEL_SHA256,
        model_size_bytes=matched.MODEL_SIZE_BYTES,
    )


def test_prompt_reuses_open_judge_framing_and_disables_qwen_thinking():
    messages = matched.build_messages("  Return labels.  ", "untrusted\ninput")

    prompt = matched.render_qwen3_no_thinking(messages)

    assert prompt == (
        f"<|im_start|>system\n{matched.SYSTEM_PROMPT}<|im_end|>\n"
        "<|im_start|>user\n"
        "<RULE_SPECIFICATION>\n"
        "Return labels.\n"
        "</RULE_SPECIFICATION>\n\n"
        "<OBSERVED_INPUT>\n"
        "untrusted\ninput\n"
        "</OBSERVED_INPUT>\n\n"
        "Classification:<|im_end|>\n"
        "<|im_start|>assistant\n<think>\n\n</think>\n\n"
    )
    assert messages == matched.build_messages(
        "  Return labels.  ", "untrusted\ninput"
    )


def test_prompt_renderer_rejects_unknown_roles():
    with pytest.raises(ValueError, match="unsupported chat message"):
        matched.render_qwen3_no_thinking(
            [{"role": "tool", "content": "not supported"}]
        )


def test_strict_parser_rejects_anything_beyond_one_whole_label():
    assert matched._strict_label(" warning\n") == "WARNING"
    assert matched._strict_label("WARNING because the rule applies") == "INVALID"
    assert matched._strict_label("<think></think> WARNING") == "INVALID"


def test_runtime_discovery_verifies_manifest_and_model_content(
    tmp_path, monkeypatch
):
    model_bytes = b"exact-model-content"
    model_sha = hashlib.sha256(model_bytes).hexdigest()
    monkeypatch.setattr(matched, "MODEL_SIZE_BYTES", len(model_bytes))
    monkeypatch.setattr(matched, "MODEL_SHA256", model_sha)
    cache = tmp_path / "paw-cache"
    runtime_path = cache / "runtimes" / f"{matched.RUNTIME_ID}.json"
    runtime_path.parent.mkdir(parents=True)
    manifest = _runtime_manifest()
    runtime_path.write_text(json.dumps(manifest), encoding="utf-8")
    model_path = cache / "base_models" / matched.MODEL_FILE
    model_path.parent.mkdir()
    model_path.write_bytes(model_bytes)

    assets = matched._resolve_runtime_assets(cache)

    assert assets.model_path == model_path
    assert assets.model_size_bytes == len(model_bytes)
    assert assets.model_sha256 == model_sha
    assert assets.manifest_sha256 == matched._canonical_json_sha256(manifest)
    assert assets.manifest_source == (
        "cache:runtimes/qwen3-0.6b-q6_k.json"
    )


@pytest.mark.parametrize("tampered", [b"short", b"exact-model-contenX"])
def test_runtime_discovery_rejects_tampered_model_bytes(
    tmp_path, monkeypatch, tampered
):
    expected = b"exact-model-content"
    monkeypatch.setattr(matched, "MODEL_SIZE_BYTES", len(expected))
    monkeypatch.setattr(
        matched, "MODEL_SHA256", hashlib.sha256(expected).hexdigest()
    )
    cache = tmp_path / "paw-cache"
    runtime_path = cache / "runtimes" / f"{matched.RUNTIME_ID}.json"
    runtime_path.parent.mkdir(parents=True)
    runtime_path.write_text(json.dumps(_runtime_manifest()), encoding="utf-8")
    model_path = cache / "base_models" / matched.MODEL_FILE
    model_path.parent.mkdir()
    model_path.write_bytes(tampered)

    with pytest.raises(SystemExit, match="model (size|SHA-256) differs"):
        matched._resolve_runtime_assets(cache)


def test_runtime_manifest_must_name_the_frozen_interpreter():
    manifest = _runtime_manifest()
    manifest["interpreter"] = "Qwen/other"

    with pytest.raises(SystemExit, match="not the frozen matched PAW interpreter"):
        matched._validate_runtime_manifest(manifest)


def test_runtime_discovery_can_use_identical_embedded_program_manifests(tmp_path):
    cache = tmp_path / "paw-cache"
    manifest = _runtime_manifest()
    for program_id in ("program-a", "program-b"):
        meta_path = cache / "programs" / program_id / "meta.json"
        meta_path.parent.mkdir(parents=True)
        meta_path.write_text(
            json.dumps(
                {
                    "runtime_id": matched.RUNTIME_ID,
                    "runtime": manifest,
                }
            ),
            encoding="utf-8",
        )

    discovered, source = matched._discover_runtime_manifest(cache)

    assert discovered == manifest
    assert source == "embedded:programs/program-a/meta.json"


class _FakeLlama:
    def __init__(self, outputs: list[int], prompt_tokens: list[int] | None = None):
        self.outputs = iter(outputs)
        self.prompt_tokens = prompt_tokens or [1, 2, 3]
        self.calls = []
        self.metadata = {
            "general.name": "frozen-qwen",
            "ignored": "not recorded",
        }

    def reset(self):
        self.calls.append(("reset",))

    def tokenize(self, value, *, add_bos, special):
        self.calls.append(("tokenize", value, add_bos, special))
        return list(self.prompt_tokens)

    def eval(self, tokens):
        self.calls.append(("eval", list(tokens)))

    def sample(self, *, temp):
        self.calls.append(("sample", temp))
        return next(self.outputs)

    def token_eos(self):
        return 0

    def detokenize(self, tokens):
        self.calls.append(("detokenize", list(tokens)))
        return b"WARNING"


def test_judge_loads_unadapted_model_and_uses_paw_greedy_token_loop(tmp_path):
    model_path = tmp_path / matched.MODEL_FILE
    fake = _FakeLlama([10, 0])
    load_calls = []

    def factory(**kwargs):
        load_calls.append(kwargs)
        return fake

    judge = matched.MatchedBaseJudge(
        _assets(model_path),
        n_gpu_layers=7,
        n_threads=3,
        seed=11,
        llama_factory=factory,
    )

    raw, prompt_tokens = judge.generate("prompt", max_new_tokens=4)

    assert raw == "WARNING"
    assert prompt_tokens == 3
    assert load_calls == [
        {
            "model_path": str(model_path),
            "n_ctx": matched.N_CTX,
            "n_gpu_layers": 7,
            "seed": 11,
            "verbose": False,
            "n_threads": 3,
            "n_threads_batch": 3,
        }
    ]
    assert "lora_path" not in load_calls[0]
    assert fake.calls == [
        ("reset",),
        ("tokenize", b"prompt", False, True),
        ("eval", [1, 2, 3]),
        ("sample", 0),
        ("eval", [10]),
        ("sample", 0),
        ("detokenize", [10]),
    ]
    assert judge.load_parameters == {
        "model_file": matched.MODEL_FILE,
        "n_ctx": matched.N_CTX,
        "n_gpu_layers": 7,
        "seed": 11,
        "verbose": False,
        "n_threads": 3,
        "n_threads_batch": 3,
    }
    assert judge.selected_metadata() == {"general.name": "frozen-qwen"}


def test_judge_refuses_to_truncate_an_oversized_prompt(tmp_path):
    fake = _FakeLlama([0], prompt_tokens=[1] * matched.N_CTX)
    judge = matched.MatchedBaseJudge(
        _assets(tmp_path / matched.MODEL_FILE),
        llama_factory=lambda **_kwargs: fake,
    )

    with pytest.raises(ValueError, match="refusing to truncate"):
        judge.generate("too long", max_new_tokens=1)

    assert not any(call[0] in {"eval", "sample"} for call in fake.calls)


class _RepeatJudge:
    def __init__(self, outputs):
        self.outputs = iter(outputs)

    def generate(self, _prompt, _max_new_tokens):
        return next(self.outputs), 17


def test_within_run_repeat_requires_exact_raw_output_identity():
    raw, latencies, prompt_tokens = matched._run_repeated(
        _RepeatJudge(["OK", "OK"]),
        "prompt",
        repeat_count=2,
        max_new_tokens=8,
    )

    assert raw == "OK"
    assert len(latencies) == 2
    assert prompt_tokens == 17

    with pytest.raises(RuntimeError, match="raw output changed"):
        matched._run_repeated(
            _RepeatJudge(["OK", "INFO"]),
            "prompt",
            repeat_count=2,
            max_new_tokens=8,
        )


def test_cross_run_repeat_ignores_latency_but_requires_exact_raw_output(tmp_path):
    row = {
        "sequence": 0,
        "case_id": "case-1",
        "raw_output": "CRITICAL",
        "prediction": "CRITICAL",
        "repeat_raw_output_sha256": matched._text_sha256("CRITICAL"),
        "latency_ms": 12.0,
    }
    prior_path = tmp_path / "prior.jsonl"
    prior_path.write_text(
        json.dumps({**row, "latency_ms": 99.0}) + "\n",
        encoding="utf-8",
    )

    result = matched._verify_against([row], prior_path)

    assert result["exact_raw_outputs_match"] is True
    changed = [{**row, "raw_output": "WARNING", "prediction": "WARNING"}]
    with pytest.raises(RuntimeError, match=r"changed=\['case-1'\]"):
        matched._verify_against(changed, prior_path)


def test_manifest_records_immutable_identity_prompt_and_repeat_protocol(
    tmp_path, monkeypatch
):
    model_path = tmp_path / matched.MODEL_FILE
    assets = _assets(model_path)
    args = SimpleNamespace(
        dataset=Path("external.jsonl"),
        max_new_tokens=8,
        seed=0,
        repeat_count=2,
        n_gpu_layers=0,
        n_threads=4,
    )
    judge = SimpleNamespace(
        load_parameters={
            "model_file": matched.MODEL_FILE,
            "n_ctx": matched.N_CTX,
        },
        selected_metadata=lambda: {"general.name": "frozen-qwen"},
    )
    monkeypatch.setattr(matched, "_git_state", lambda: {"commit": "abc"})
    monkeypatch.setattr(matched, "_package_version", lambda _name: "test")

    manifest = matched._build_manifest(
        args=args,
        assets=assets,
        dataset_sha256="1" * 64,
        output_sha256="2" * 64,
        cases=160,
        elapsed_seconds=1.25,
        prompt_token_counts=[101, 202],
        judge=judge,
        rule_spec_sha256={"rule": "3" * 64},
        against=None,
    )

    assert manifest["matched_base"] == {
        "adapter_applied": False,
        "runtime_id": matched.RUNTIME_ID,
        "runtime_manifest_sha256": assets.manifest_sha256,
        "runtime_manifest_source": assets.manifest_source,
        "runtime_manifest_version": 1,
        "display_name": "Qwen3 0.6B (Q6_K)",
        "interpreter": matched.INTERPRETER,
        "repository": matched.MODEL_REPOSITORY,
        "file": matched.MODEL_FILE,
        "content_sha256": matched.MODEL_SHA256,
        "size_bytes": matched.MODEL_SIZE_BYTES,
        "identity": "exact GGUF content SHA-256",
        "gguf_metadata": {"general.name": "frozen-qwen"},
    }
    assert manifest["prompt"]["system"] == matched.SYSTEM_PROMPT
    assert manifest["prompt"]["rule_spec_sha256"] == {"rule": "3" * 64}
    assert manifest["decoding"]["temperature"] == 0
    assert manifest["decoding"]["greedy"] is True
    assert manifest["decoding"]["input_truncation"] is False
    assert manifest["decoding"]["repeat_count_per_case"] == 2
    assert manifest["repeat_verification"] == {
        "within_run_exact_raw_output_repeats": 2,
        "against_prior_output": None,
    }
    assert str(tmp_path) not in json.dumps(manifest)
