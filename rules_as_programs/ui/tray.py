"""Platform entry point for the Rules as Programs status item.

macOS uses the native AppKit popover.  Linux and Windows retain a deliberately
smaller pystray menu backed by the same daemon snapshot/action model.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import Any

from .. import config, ipc

_LOCK_HANDLE = None


def _log(message: str) -> None:
    try:
        with config.tray_log_path().open("a", encoding="utf-8") as handle:
            handle.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}\n")
    except OSError:
        pass


def _acquire_single_instance() -> bool:
    """Keep init, login autostart, and manual launches from duplicating the UI."""
    global _LOCK_HANDLE
    path = config.tray_lock_path()
    handle = path.open("a+")
    try:
        if sys.platform == "darwin" or not sys.platform.startswith("win"):
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        else:  # pragma: no cover - Windows fallback
            import msvcrt
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
    except (OSError, IOError):
        handle.close()
        return False
    handle.seek(0)
    handle.truncate()
    handle.write(str(os.getpid()))
    handle.flush()
    _LOCK_HANDLE = handle
    return True


def _open_path(path: str) -> None:
    if not path:
        return
    try:
        if sys.platform == "darwin":
            subprocess.Popen(["open", path])
        elif sys.platform.startswith("win"):
            os.startfile(path)  # type: ignore[attr-defined]
        else:
            subprocess.Popen(["xdg-open", path])
    except OSError:
        pass


def _icon_image(open_count: int = 0, unavailable: bool = False):
    from PIL import Image, ImageDraw
    try:
        base = Image.open(config.icon_png()).convert("RGBA").resize((64, 64))
    except Exception:
        base = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    if open_count or unavailable:
        draw = ImageDraw.Draw(base)
        draw.ellipse((42, 42, 63, 63), fill=(190, 50, 45, 255))
    return base


def _run_pystray() -> int:
    import pystray

    state: dict[str, Any] = {"snapshot": None}
    icon_ref: dict[str, Any] = {}

    def snapshot() -> dict[str, Any]:
        value = state.get("snapshot")
        return value if isinstance(value, dict) else {}

    def review(ids: list[int]) -> None:
        ipc.send_request({"type": "review", "ids": ids})

    def build_menu():
        data = snapshot()
        if not data:
            return pystray.Menu(
                pystray.MenuItem("Daemon unavailable", lambda _icon, _item: None,
                                 enabled=False),
                pystray.MenuItem("Retry", lambda _icon, _item: None),
                pystray.MenuItem("Quit", lambda icon, _item: icon.stop()),
            )
        items: list[Any] = []
        findings = data.get("findings_by_project", {})
        if not findings:
            items.append(pystray.MenuItem(
                "All reviewed — monitoring continues", None, enabled=False))
        for project, groups in findings.items():
            sub: list[Any] = []
            for group in groups[:12]:
                title = group.get("rule_title") or group.get("rule_id", "Rule")
                message = str(group.get("message", "")).replace("\n", " ")
                label = f"{title}: {message[:80]}"
                ids = [int(value) for value in group.get("ids", [group.get("id")]) if value]
                sub.append(pystray.MenuItem(
                    label,
                    lambda _icon, _item, values=ids: review(values),
                ))
            sub.append(pystray.Menu.SEPARATOR)
            sub.append(pystray.MenuItem(
                "Open audit log",
                lambda _icon, _item, path=project: _open_path(
                    str(config.project_log_file(path))),
            ))
            items.append(pystray.MenuItem(
                f"{Path(project).name or project} ({len(groups)})",
                pystray.Menu(*sub)))
        items.extend([
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", lambda icon, _item: icon.stop()),
        ])
        return pystray.Menu(*items)

    icon = pystray.Icon(
        "rules-as-programs",
        _icon_image(),
        "Rules as Programs",
        menu=build_menu,
    )
    icon_ref["icon"] = icon

    def poll() -> None:
        icon.visible = True
        while icon.visible:
            compatible = ipc.ensure_daemon(
                required_protocol=ipc.PROTOCOL_VERSION, restart_stale=True)
            data = ipc.send_request({"type": "snapshot"}, timeout=3) if compatible else None
            state["snapshot"] = data
            count = int((data or {}).get("open_count", 0) or 0)
            icon.icon = _icon_image(count, unavailable=not bool(data))
            icon.title = (
                f"Rules as Programs — {count} open"
                if data else "Rules as Programs — daemon unavailable")
            try:
                icon.update_menu()
            except Exception:
                pass
            time.sleep(4)

    icon.run(setup=lambda _icon: threading.Thread(target=poll, daemon=True).start())
    return 0


def run(backend: str = "auto") -> int:
    if not _acquire_single_instance():
        return 0
    if backend in ("auto", "appkit") and sys.platform == "darwin":
        try:
            from .macos_app import run_macos
            _log("starting native AppKit inbox")
            return run_macos(demo=os.environ.get("RAP_UI_DEMO") == "1")
        except ImportError as exc:
            if backend == "appkit":
                print(f"AppKit UI unavailable: {exc}", file=sys.stderr)
                return 1
        except Exception:
            _log("AppKit inbox crashed:\n" + traceback.format_exc())
            raise
    try:
        _log("starting pystray fallback")
        return _run_pystray()
    except ImportError:
        print("No tray backend. Install pystray and pillow.", file=sys.stderr)
        return 1
    except Exception:
        _log("pystray fallback crashed:\n" + traceback.format_exc())
        raise


if __name__ == "__main__":
    raise SystemExit(run())
