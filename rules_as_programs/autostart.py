"""Login autostart for the tray menu item, so it's always present.

macOS: a LaunchAgent plist in ``~/Library/LaunchAgents``.
Linux:  an XDG autostart ``.desktop`` file in ``~/.config/autostart``.
Other:  no-op (returns a note).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from xml.sax.saxutils import escape

from . import config

LABEL = "com.programasweights.rules-as-programs"


def _macos_plist() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def _linux_desktop() -> Path:
    return Path.home() / ".config" / "autostart" / "rules-as-programs.desktop"


def install(python: str | None = None) -> str:
    python = python or sys.executable
    if sys.platform == "darwin":
        path = _macos_plist()
        path.parent.mkdir(parents=True, exist_ok=True)
        python_xml = escape(python)
        tray_log_xml = escape(str(config.tray_log_path()))
        path.write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
            '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            '<plist version="1.0"><dict>\n'
            f'  <key>Label</key><string>{LABEL}</string>\n'
            '  <key>ProgramArguments</key>\n'
            f'  <array><string>{python_xml}</string><string>-m</string>'
            '<string>rules_as_programs.ui.tray</string></array>\n'
            '  <key>RunAtLoad</key><true/>\n'
            '  <key>KeepAlive</key><dict>\n'
            '    <key>SuccessfulExit</key><false/>\n'
            '  </dict>\n'
            '  <key>ProcessType</key><string>Interactive</string>\n'
            f'  <key>StandardErrorPath</key><string>{tray_log_xml}</string>\n'
            '</dict></plist>\n'
        )
        try:
            subprocess.run(["launchctl", "unload", str(path)],
                           capture_output=True, timeout=5)
            subprocess.run(["launchctl", "load", "-w", str(path)],
                           capture_output=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            pass
        return f"installed LaunchAgent: {path}"

    if sys.platform.startswith("linux"):
        path = _linux_desktop()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "[Desktop Entry]\n"
            "Type=Application\n"
            "Name=Rules as Programs\n"
            f"Exec={python} -m rules_as_programs.ui.tray\n"
            "X-GNOME-Autostart-enabled=true\n"
        )
        return f"installed autostart entry: {path}"

    return "autostart not supported on this platform (start the tray with `rap tray`)"


def uninstall() -> str:
    if sys.platform == "darwin":
        path = _macos_plist()
        if path.exists():
            try:
                subprocess.run(["launchctl", "unload", str(path)],
                               capture_output=True, timeout=5)
            except (OSError, subprocess.SubprocessError):
                pass
            path.unlink(missing_ok=True)
            return f"removed LaunchAgent: {path}"
        return "no LaunchAgent installed"
    if sys.platform.startswith("linux"):
        path = _linux_desktop()
        if path.exists():
            path.unlink(missing_ok=True)
            return f"removed autostart entry: {path}"
        return "no autostart entry installed"
    return "nothing to remove"
