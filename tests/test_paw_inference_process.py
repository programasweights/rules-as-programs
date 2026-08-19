from rules_as_programs.paw_inference_process import PawInferenceProcess


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
