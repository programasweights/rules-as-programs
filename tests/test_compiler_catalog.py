import threading
import time

from rules_as_programs import paw_runtime


class FakePaw:
    def __init__(self):
        self.calls = 0
        self.compile_calls = 0
        self.compile_kwargs = []
        self.standard_snapshot = "standard-2027"
        self.active_inferences = 0
        self.max_active_inferences = 0
        self.inference_lock = threading.Lock()

    def list_compilers(self):
        self.calls += 1
        return [
            {
                "name": "future-standard",
                "description": "Future Standard",
                "default": True,
                "compiler_kind": "mapper_lora",
                "runtime_id": "runtime-v2",
                "supports_local_sdk": True,
                "latest_snapshot": self.standard_snapshot,
            },
            {
                "name": "future-finetune",
                "description": "Future Finetuned",
                "default": False,
                "compiler_kind": "finetune_lora",
                "runtime_id": "runtime-v2",
                "supports_local_sdk": True,
                "latest_snapshot": "finetune-2027",
            },
        ]

    def compile(self, _spec, **_kwargs):
        self.compile_calls += 1
        self.compile_kwargs.append(dict(_kwargs))
        return type("Program", (), {"id": f"program-{self.compile_calls}"})()

    def function(self, _program_id):
        def run(text):
            with self.inference_lock:
                self.active_inferences += 1
                self.max_active_inferences = max(
                    self.max_active_inferences, self.active_inferences)
            time.sleep(0.02)
            with self.inference_lock:
                self.active_inferences -= 1
            return text
        return run


class FakeInferenceWorker:
    def __init__(self, fake):
        self.fake = fake
        self.generation = 1
        self.lock = threading.Lock()
        self.calls = 0

    def call(self, program_id, text, _timeout):
        with self.lock:
            self.calls += 1
            return self.fake.function(program_id)(text)

    def shutdown(self):
        return None


def test_compiler_catalog_is_discovered_and_cached(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path))
    fake = FakePaw()
    monkeypatch.setattr(paw_runtime, "paw", fake)
    runtime = paw_runtime.PawRuntime()

    first = runtime.list_compilers(refresh=True)
    second = runtime.list_compilers()

    assert fake.calls == 1
    assert not first["cached"]
    assert second["cached"]
    assert runtime.compiler_info()["name"] == "future-standard"
    assert runtime.automatic_base_compiler()["name"] == "future-standard"
    assert runtime.compatible_finetune_compiler()["name"] == (
        "future-finetune")
    runtime.shutdown()


def test_compiler_catalog_uses_offline_cache(monkeypatch, tmp_path):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path))
    fake = FakePaw()
    monkeypatch.setattr(paw_runtime, "paw", fake)
    runtime = paw_runtime.PawRuntime()
    runtime.list_compilers(refresh=True)
    monkeypatch.setattr(paw_runtime, "paw", None)
    runtime.available = False

    cached = runtime.list_compilers(refresh=True)

    assert cached["offline"]
    assert cached["compilers"][0]["name"] == "future-standard"
    runtime.shutdown()


def test_program_cache_is_scoped_to_compiler_snapshot(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path))
    fake = FakePaw()
    monkeypatch.setattr(paw_runtime, "paw", fake)
    runtime = paw_runtime.PawRuntime()
    runtime.list_compilers(refresh=True)

    first = runtime.program_id_for_spec("spec")
    assert runtime.cached_program_id_for_spec("spec") == first
    fake.standard_snapshot = "standard-2028"
    runtime.list_compilers(refresh=True)
    second = runtime.program_id_for_spec("spec")

    assert first == "program-1"
    assert second == "program-2"
    assert fake.compile_calls == 2
    assert all(
        call["public"] is True and call["ephemeral"] is False
        for call in fake.compile_kwargs
    )
    runtime.shutdown()


def test_concurrent_compile_requests_share_one_build(monkeypatch, tmp_path):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path))
    fake = FakePaw()
    original_compile = fake.compile

    def slow_compile(spec, **kwargs):
        time.sleep(0.05)
        return original_compile(spec, **kwargs)

    fake.compile = slow_compile
    monkeypatch.setattr(paw_runtime, "paw", fake)
    runtime = paw_runtime.PawRuntime()
    runtime.list_compilers(refresh=True)
    results = []
    workers = [
        threading.Thread(
            target=lambda: results.append(
                runtime.program_id_for_spec("same spec")))
        for _ in range(4)
    ]

    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()

    assert results == ["program-1"] * 4
    assert fake.compile_calls == 1
    runtime.shutdown()


def test_local_inference_is_strictly_single_threaded(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path))
    fake = FakePaw()
    monkeypatch.setattr(paw_runtime, "paw", fake)
    runtime = paw_runtime.PawRuntime(
        inference_worker=FakeInferenceWorker(fake))
    workers = [
        threading.Thread(
            target=lambda value=value: runtime.run("program", value))
        for value in ("one", "two", "three")
    ]

    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()

    assert fake.max_active_inferences == 1
    assert runtime._inference_worker.generation == 1
    calls = runtime._inference_worker.calls
    assert runtime.warm("program")
    assert runtime.warm("program")
    assert runtime._inference_worker.calls == calls + 1
    runtime._inference_worker.generation += 1
    assert runtime.warm("program")
    assert runtime._inference_worker.calls == calls + 2
    runtime.shutdown()
