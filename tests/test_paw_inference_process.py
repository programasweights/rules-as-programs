from types import SimpleNamespace

import pytest

from rules_as_programs.paw_inference_process import (
    PawInferenceProcess,
    _configure_llama_threads,
    _llama_thread_kwargs,
)


class FakeConnection:
    def __init__(self):
        self.closed = False
        self.sent = []

    def send(self, value):
        self.sent.append(value)

    def poll(self, _timeout):
        return False

    def close(self):
        self.closed = True


class FakeProcess:
    def __init__(self):
        self.pid = None
        self.alive = False
        self.terminated = False

    def start(self):
        self.pid = 123
        self.alive = True

    def is_alive(self):
        return self.alive

    def terminate(self):
        self.terminated = True
        self.alive = False

    def join(self, timeout=None):
        return None

    def kill(self):
        self.alive = False


class FakeContext:
    def __init__(self):
        self.parent = FakeConnection()
        self.child = FakeConnection()
        self.process = FakeProcess()

    def Pipe(self, duplex=True):
        return self.parent, self.child

    def Process(self, **_kwargs):
        return self.process


class ScriptedConnection(FakeConnection):
    def __init__(self, response=None):
        super().__init__()
        self.response = response

    def poll(self, _timeout):
        return self.response is not None

    def recv(self):
        return self.response


class ScriptedContext:
    def __init__(self, responses):
        self.responses = list(responses)
        self.parents = []
        self.processes = []

    def Pipe(self, duplex=True):
        parent = ScriptedConnection(self.responses.pop(0))
        child = FakeConnection()
        self.parents.append(parent)
        return parent, child

    def Process(self, **_kwargs):
        process = FakeProcess()
        self.processes.append(process)
        return process


def test_timeout_kills_poisoned_native_worker():
    worker = PawInferenceProcess()
    context = FakeContext()
    worker._context = context

    result = worker.call("program", "input", timeout=0.01)

    assert result is None
    assert "timed out" in worker.last_error
    assert context.process.terminated
    assert context.parent.closed
    assert worker.pid is None


def test_timeout_retries_once_in_a_fresh_worker():
    worker = PawInferenceProcess()
    context = ScriptedContext([None, {"id": "2", "ok": True, "output": " WARNING \n"}])
    worker._context = context

    assert worker.call("program", "input", timeout=0.01) == "WARNING"
    assert len(context.processes) == 2
    assert context.processes[0].terminated
    assert worker.generation == 2
    assert worker.last_error == ""


def test_llama_thread_settings_are_explicit_and_positive():
    assert _llama_thread_kwargs({}) == {}
    assert _llama_thread_kwargs(
        {"RAP_PAW_N_THREADS": "8", "RAP_PAW_N_THREADS_BATCH": "8"}
    ) == {"n_threads": 8, "n_threads_batch": 8}
    with pytest.raises(ValueError, match="positive integer"):
        _llama_thread_kwargs({"RAP_PAW_N_THREADS": "0"})
    with pytest.raises(ValueError, match="positive integer"):
        _llama_thread_kwargs({"RAP_PAW_N_THREADS_BATCH": "many"})


def test_configure_llama_threads_pins_both_constructor_arguments():
    calls = []

    def llama(*args, **kwargs):
        calls.append((args, kwargs))
        return "loaded"

    runtime = SimpleNamespace(Llama=llama)
    _configure_llama_threads(
        runtime,
        {"RAP_PAW_N_THREADS": "8", "RAP_PAW_N_THREADS_BATCH": "8"},
    )

    assert runtime.Llama(model_path="model.gguf") == "loaded"
    assert calls == [
        ((), {"model_path": "model.gguf", "n_threads": 8, "n_threads_batch": 8})
    ]


def test_configure_llama_threads_rejects_conflicting_runtime_value():
    runtime = SimpleNamespace(Llama=lambda **_kwargs: None)
    _configure_llama_threads(runtime, {"RAP_PAW_N_THREADS": "8"})

    with pytest.raises(RuntimeError, match="conflicting"):
        runtime.Llama(n_threads=4)
