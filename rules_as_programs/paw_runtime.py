"""Thin wrapper over the ProgramAsWeights SDK.

Follows the PAW docs/AGENTS.md guidance:

* Compile a spec into a tiny neural program with ``paw.compile(spec)`` (fast
  Standard compiler for iteration; optional ``paw-ft-bs48`` finalize pass).
* Run inference locally and forever with ``paw.function(program_id)(text)``.
* First inference call loads the base model (~1-5s), so we *warm* every active
  program once on daemon start and keep the callables cached.
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
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from typing import Callable

from . import config

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

    def __init__(self, inference_timeout: float = 8.0, compile_timeout: float = 90.0):
        self.inference_timeout = inference_timeout
        self.compile_timeout = compile_timeout
        self._fns: dict[str, Callable[[str], str]] = {}
        self._id_by_hash: dict[str, str] = self._load_cache()
        self._lock = threading.Lock()
        # A dedicated pool so a slow/hung inference can't wedge the daemon.
        self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="paw")
        self.available = paw is not None

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
    def program_id_for_spec(self, spec: str, compiler: str | None = None) -> str | None:
        """Return a compiled program id for ``spec``, compiling+caching if new."""
        if not self.available:
            return None
        key = spec_hash(spec, compiler)
        with self._lock:
            cached = self._id_by_hash.get(key)
        if cached:
            return cached
        try:
            fut = self._pool.submit(self._compile, spec, compiler)
            program = fut.result(timeout=self.compile_timeout)
        except (FuturesTimeout, Exception):
            return None
        pid = getattr(program, "id", None)
        if not pid:
            return None
        with self._lock:
            self._id_by_hash[key] = pid
            self._save_cache()
        return pid

    def _compile(self, spec: str, compiler: str | None):
        if compiler:
            return paw.compile(spec, compiler=compiler)
        return paw.compile(spec)

    # --- warm + run ------------------------------------------------------
    def _get_fn(self, program_id: str) -> Callable[[str], str] | None:
        with self._lock:
            fn = self._fns.get(program_id)
        if fn is not None:
            return fn
        if not self.available:
            return None
        try:
            fn = paw.function(program_id)
        except Exception:
            return None
        with self._lock:
            self._fns[program_id] = fn
        return fn

    def warm(self, program_id: str) -> bool:
        """Force base-model load for ``program_id`` (best-effort)."""
        fn = self._get_fn(program_id)
        if fn is None:
            return False
        try:
            self._pool.submit(fn, "warmup").result(timeout=self.inference_timeout)
            return True
        except Exception:
            return False

    def run(self, program_id: str, text: str) -> str | None:
        """Run inference with a hard timeout. Returns ``None`` on any failure."""
        fn = self._get_fn(program_id)
        if fn is None:
            return None
        try:
            fut = self._pool.submit(fn, text)
            out = fut.result(timeout=self.inference_timeout)
            return out.strip() if isinstance(out, str) else str(out)
        except (FuturesTimeout, Exception):
            return None

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)


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
