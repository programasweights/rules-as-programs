"""Supervised single-process executor for local PAW/llama.cpp inference."""

from __future__ import annotations

import faulthandler
import multiprocessing
import os
import threading
from multiprocessing.connection import Connection
from typing import Any


def _worker_main(connection: Connection) -> None:
    faulthandler.enable()
    os.environ.setdefault("OMP_NUM_THREADS", "1")
    os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
    import programasweights as paw

    functions: dict[str, Any] = {}
    while True:
        try:
            request = connection.recv()
        except EOFError:
            break
        if request.get("type") == "shutdown":
            break
        request_id = str(request.get("id", ""))
        program_id = str(request.get("program_id", ""))
        try:
            function = functions.get(program_id)
            if function is None:
                function = paw.function(program_id)
                functions[program_id] = function
            output = function(str(request.get("text", "")))
            connection.send({
                "id": request_id,
                "ok": True,
                "output": output,
            })
        except BaseException as exc:
            connection.send({
                "id": request_id,
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
            })
    connection.close()


class PawInferenceProcess:
    """One serialized worker process; kill and replace it after any timeout."""

    def __init__(self):
        self._context = multiprocessing.get_context("spawn")
        self._lock = threading.Lock()
        self._process = None
        self._connection = None
        self._request_id = 0
        self.generation = 0
        self.last_error = ""

    @property
    def pid(self) -> int | None:
        process = self._process
        return int(process.pid) if process and process.pid else None

    def _start_locked(self) -> None:
        if self._process is not None and self._process.is_alive():
            return
        self._stop_locked()
        parent, child = self._context.Pipe(duplex=True)
        process = self._context.Process(
            target=_worker_main,
            args=(child,),
            name="rap-paw-inference",
            daemon=True,
        )
        process.start()
        child.close()
        self._connection = parent
        self._process = process
        self.generation += 1
        self.last_error = ""

    def call(
        self, program_id: str, text: str, timeout: float
    ) -> str | None:
        # The lock starts the timeout only after this caller reaches the single
        # worker. Calls never overlap and queued callers do not time out early.
        with self._lock:
            self._start_locked()
            self._request_id += 1
            request_id = str(self._request_id)
            connection = self._connection
            try:
                connection.send({
                    "type": "run",
                    "id": request_id,
                    "program_id": program_id,
                    "text": text,
                })
                if not connection.poll(timeout):
                    self.last_error = (
                        f"local inference timed out after {timeout:.1f}s")
                    self._stop_locked()
                    return None
                response = connection.recv()
            except (BrokenPipeError, EOFError, OSError) as exc:
                self.last_error = f"worker exited: {exc}"
                self._stop_locked()
                return None
            if (
                str(response.get("id", "")) != request_id
                or not response.get("ok")
            ):
                self.last_error = str(
                    response.get("error", "invalid worker response"))
                return None
            output = response.get("output")
            return output.strip() if isinstance(output, str) else str(output)

    def _stop_locked(self) -> None:
        connection = self._connection
        process = self._process
        self._connection = None
        self._process = None
        if connection is not None:
            try:
                connection.close()
            except OSError:
                pass
        if process is None:
            return
        if process.is_alive():
            process.terminate()
            process.join(timeout=1)
        if process.is_alive():
            process.kill()
            process.join(timeout=1)

    def shutdown(self) -> None:
        with self._lock:
            connection = self._connection
            if connection is not None:
                try:
                    connection.send({"type": "shutdown"})
                except (BrokenPipeError, OSError):
                    pass
            self._stop_locked()
