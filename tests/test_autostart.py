from __future__ import annotations

from rules_as_programs import autostart


def test_macos_autostart_restarts_crashes_but_logs_errors(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path / "state"))
    plist = tmp_path / "agent.plist"
    monkeypatch.setattr(autostart, "_macos_plist", lambda: plist)
    monkeypatch.setattr(autostart.sys, "platform", "darwin")
    monkeypatch.setattr(
        autostart.subprocess, "run",
        lambda *args, **kwargs: None,
    )

    autostart.install("/tmp/python&current")
    text = plist.read_text()
    assert "<key>SuccessfulExit</key><false/>" in text
    assert "<key>StandardErrorPath</key>" in text
    assert "tray.log" in text
    assert "/tmp/python&amp;current" in text
