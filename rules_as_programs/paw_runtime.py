"""Thin wrapper over the ProgramAsWeights SDK.

Follows the PAW docs/AGENTS.md guidance:

* Compile a spec with the server default or a compiler discovered through
  ``paw.list_compilers()``.
* Run local inference in one supervised subprocess. A native timeout kills the
  entire worker, so a stuck llama.cpp call cannot poison the daemon.
* First inference loads the base model (~1-5s); each program is warmed at most
  once per worker generation.
* Compiled program ids are cached on disk keyed by a hash of the spec, so we
  never recompile the same spec (and inference works offline afterwards).

Everything degrades gracefully: if PAW is unavailable, slow, or a compile
fails, judgment simply returns ``None`` and the caller keeps the deterministic
evidence it already has.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from typing import Any

from . import config
from .paw_inference_process import PawInferenceProcess

try:  # PAW is a hard dependency, but never let an import blow up the daemon.
    import programasweights as paw  # type: ignore
except Exception:  # pragma: no cover - defensive
    paw = None  # type: ignore


def spec_hash(spec: str, compiler: str | None) -> str:
    h = hashlib.sha256()
    h.update((compiler or "default").encode())
    h.update(b"\x00")
    h.update(spec.strip().encode())
    return h.hexdigest()[:20]


class PawRuntime:
    """Compiles + caches + runs PAW functions, keeping them warm."""

    def __init__(
        self,
        inference_timeout: float = 8.0,
        compile_timeout: float = 90.0,
        inference_worker: Any | None = None,
    ):
        self.inference_timeout = inference_timeout
        self.compile_timeout = compile_timeout
        self._id_by_hash: dict[str, str] = self._load_cache()
        self._lock = threading.Lock()
        self._compile_futures: dict[str, Any] = {}
        self._catalog_lock = threading.Lock()
        self._inference_worker = (
            inference_worker or PawInferenceProcess())
        self._warm_lock = threading.Lock()
        self._warmed_programs: set[tuple[int, str]] = set()
        # Compilation is remote and independent from the one local worker.
        self._compile_pool = ThreadPoolExecutor(
            max_workers=2, thread_name_prefix="paw-compile")
        self.available = paw is not None

    def list_compilers(
        self, *, refresh: bool = False, max_age: float = 24 * 3600
    ) -> dict:
        with self._catalog_lock:
            return self._list_compilers(refresh=refresh, max_age=max_age)

    def _list_compilers(
        self, *, refresh: bool, max_age: float
    ) -> dict:
        path = config.compiler_catalog_path()
        cached = {}
        if path.exists():
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(value, dict):
                    cached = value
            except (json.JSONDecodeError, OSError):
                cached = {}
        age = time.time() - float(cached.get("fetched_at", 0) or 0)
        if (
            not refresh
            and cached.get("compilers")
            and age <= max_age
        ):
            return {**cached, "cached": True}
        if self.available and hasattr(paw, "list_compilers"):
            try:
                response = paw.list_compilers()
                compilers = (
                    response.get("compilers", [])
                    if isinstance(response, dict)
                    else getattr(response, "compilers", response)
                )
                normalized = []
                for item in compilers or []:
                    if isinstance(item, dict):
                        normalized.append(dict(item))
                    elif hasattr(item, "model_dump"):
                        normalized.append(dict(item.model_dump()))
                    elif hasattr(item, "__dict__"):
                        normalized.append(dict(vars(item)))
                catalog = {
                    "fetched_at": time.time(),
                    "compilers": normalized,
                }
                path.write_text(
                    json.dumps(catalog, indent=2, default=str),
                    encoding="utf-8")
                return {**catalog, "cached": False}
            except Exception:
                pass
        return {
            "fetched_at": cached.get("fetched_at"),
            "compilers": list(cached.get("compilers") or []),
            "cached": True,
            "offline": True,
        }

    def compiler_info(self, name: str = "") -> dict:
        compilers = self.list_compilers().get("compilers") or []
        if name:
            return next(
                (
                    dict(item) for item in compilers
                    if str(item.get("name", "")) == name
                ),
                {"name": name, "description": name},
            )
        return next(
            (dict(item) for item in compilers if item.get("default")),
            {"name": "", "description": "Server default", "default": True},
        )

    def compatible_finetune_compiler(
        self, active_compiler: str = ""
    ) -> dict:
        compilers = self.list_compilers().get("compilers") or []
        active = self.compiler_info(active_compiler)
        runtime_id = str(active.get("runtime_id", ""))
        return next(
            (
                dict(item) for item in compilers
                if item.get("compiler_kind") == "finetune_lora"
                and item.get("supports_local_sdk")
                and (
                    not runtime_id
                    or str(item.get("runtime_id", "")) == runtime_id
                )
            ),
            {},
        )

    def automatic_base_compiler(self) -> dict:
        """Return the fast local compiler used by Automatic mode."""
        compilers = self.list_compilers().get("compilers") or []
        default = next(
            (dict(item) for item in compilers if item.get("default")),
            {},
        )
        if (
            default
            and default.get("compiler_kind") != "finetune_lora"
            and default.get("supports_local_sdk", True)
        ):
            return default
        return next(
            (
                dict(item) for item in compilers
                if item.get("compiler_kind") == "mapper_lora"
                and item.get("supports_local_sdk", True)
            ),
            next(
                (
                    dict(item) for item in compilers
                    if item.get("compiler_kind") != "finetune_lora"
                    and item.get("supports_local_sdk", True)
                ),
                default,
            ),
        )

    # --- disk cache of spec-hash -> program id ---------------------------
    def _load_cache(self) -> dict[str, str]:
        p = config.paw_cache_path()
        if p.exists():
            try:
                return json.loads(p.read_text())
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def _save_cache(self) -> None:
        try:
            config.paw_cache_path().write_text(json.dumps(self._id_by_hash, indent=2))
        except OSError:
            pass

    # --- compile ---------------------------------------------------------
    def _cache_key_for_spec(
        self, spec: str, compiler: str | None
    ) -> str:
        compiler_info = self.compiler_info(compiler or "")
        compiler_identity = (
            str(compiler or compiler_info.get("name") or "default")
            + "@"
            + str(compiler_info.get("latest_snapshot") or "unknown")
        )
        return spec_hash(spec, compiler_identity)

    def cached_program_id_for_spec(
        self, spec: str, compiler: str | None = None
    ) -> str:
        key = self._cache_key_for_spec(spec, compiler)
        with self._lock:
            return str(self._id_by_hash.get(key, ""))

    def program_id_for_spec(
        self,
        spec: str,
        compiler: str | None = None,
        *,
        timeout: float | None = None,
    ) -> str | None:
        """Return a compiled program id for ``spec``, compiling+caching if new."""
        if not self.available:
            return None
        key = self._cache_key_for_spec(spec, compiler)
        created = False
        with self._lock:
            cached = self._id_by_hash.get(key)
            if cached:
                return cached
            fut = self._compile_futures.get(key)
            if fut is None:
                fut = self._compile_pool.submit(self._compile, spec, compiler)
                self._compile_futures[key] = fut
                created = True
        if created:
            fut.add_done_callback(
                lambda completed, cache_key=key: (
                    self._finish_compile(cache_key, completed)
                )
            )
        try:
            program = fut.result(timeout=(
                self.compile_timeout if timeout is None else timeout))
        except (FuturesTimeout, Exception):
            return None
        pid = getattr(program, "id", None)
        if not pid:
            return None
        with self._lock:
            self._id_by_hash[key] = pid
            self._save_cache()
        return pid

    def _finish_compile(self, key: str, future: Any) -> None:
        try:
            program = future.result()
            pid = getattr(program, "id", None)
        except Exception:
            pid = None
        with self._lock:
            if self._compile_futures.get(key) is future:
                self._compile_futures.pop(key, None)
            if pid:
                self._id_by_hash[key] = str(pid)
                self._save_cache()

    def _compile(self, spec: str, compiler: str | None):
        if compiler:
            return paw.compile(spec, compiler=compiler)
        return paw.compile(spec)

    # --- supervised warm + run -------------------------------------------
    def warm(self, program_id: str) -> bool:
        """Force base-model load for ``program_id`` (best-effort)."""
        if not self.available:
            return False
        with self._warm_lock:
            generation = int(self._inference_worker.generation)
            key = (generation, program_id)
            if generation and key in self._warmed_programs:
                return True
            output = self._inference_worker.call(
                program_id, "warmup", self.inference_timeout)
            if output is None:
                return False
            current_generation = int(self._inference_worker.generation)
            self._warmed_programs.add((current_generation, program_id))
            self._warmed_programs = {
                value for value in self._warmed_programs
                if value[0] == current_generation
            }
            return True

    def run(self, program_id: str, text: str) -> str | None:
        """Run one serialized local inference in a killable subprocess."""
        if not self.available:
            return None
        return self._inference_worker.call(
            program_id, text, self.inference_timeout)

    def shutdown(self) -> None:
        self._inference_worker.shutdown()
        self._compile_pool.shutdown(wait=False, cancel_futures=True)


# --- process-global shared runtime -----------------------------------------
# So `sdk.paw_function` / `ctx.paw` and the daemon share one warm, cached
# instance (compiled programs and loaded models are reused across all rules).

_SHARED: PawRuntime | None = None
_SHARED_LOCK = threading.Lock()


def shared() -> PawRuntime:
    global _SHARED
    with _SHARED_LOCK:
        if _SHARED is None:
            _SHARED = PawRuntime()
        return _SHARED
