"""``rap`` command-line interface.

The important one is ``rap init`` -- the single-command onboarding that installs
Cursor hooks, scaffolds rule programs, optionally converts existing prose rules,
and launches the daemon + tray. Everything else (status, rules management,
daemon/tray control) supports that workflow.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

from . import config, ipc, autostart, paw_runtime, rules_api
from .adapters.cursor import CursorAdapter
from .core.rule import load_rules, load_rule_file
from . import scaffold

SEV_EMOJI = {"info": "*", "warn": "!", "critical": "X"}
ICON_URLS = ["https://programasweights.com/paw-192.png"]


def _refresh_icon() -> bool:
    """Download the latest PAW icon into the state dir (best-effort, offline-ok)."""
    import urllib.request
    for url in ICON_URLS:
        try:
            with urllib.request.urlopen(url, timeout=4) as resp:
                data = resp.read()
            if data[:8] == b"\x89PNG\r\n\x1a\n":
                (config.state_dir() / "paw-192.png").write_bytes(data)
                return True
        except Exception:
            continue
    return False


def _scope_from_args(args) -> str:
    return "global" if getattr(args, "global_scope", False) else "project"


# --- init ------------------------------------------------------------------

def cmd_init(args) -> int:
    project_root = os.path.abspath(args.path or os.getcwd())
    scope = _scope_from_args(args)
    print(f"Rules as Programs: setting up ({scope} scope)")
    print(f"  project: {project_root}")

    # 1. Cursor hooks
    adapter = CursorAdapter()
    for note in adapter.install(scope, project_root):
        print(f"  hooks: {note}")

    # 2. Scaffold built-in rule programs
    for note in scaffold.install_builtins(scope, project_root):
        print(f"  rules: {note}")

    # 3. Optionally convert existing prose rules
    if args.scan:
        for note in scaffold.convert_prose_rules(project_root, scope):
            print(f"  scan: {note}")

    # 4. Refresh the menu-bar icon from programasweights.com (falls back to bundled)
    print(f"  icon: {'refreshed from programasweights.com' if _refresh_icon() else 'using bundled asset'}")

    # 5. Login autostart so the menu item is always there
    if not args.no_autostart:
        print(f"  autostart: {autostart.install(sys.executable)}")

    # 6. Launch daemon + tray
    if not args.no_launch:
        ok = ipc.ensure_daemon()
        print(f"  daemon: {'running' if ok else 'could not start (will autostart on first hook)'}")
        if ok:
            ipc.send_request({"type": "warm", "project_root": project_root})
        if not args.no_tray:
            _spawn_tray()
            print("  tray: launched (top-right status item)")

    print(
        "\nDone. Rule programs will now audit this project's agent runs.\n"
        "Reload Cursor (or restart) so it picks up .cursor/hooks.json.\n"
        "Findings appear in the top-right menu item; per-project logs live in\n"
        ".cursor/rules-as-programs/log/. You can also run `rap status`."
    )
    if args.scan:
        print(
            "\nTip: to convert your existing rules with high quality, ask the Cursor\n"
            "agent to follow the 'Convert existing rules' section of AGENTS.md."
        )
    return 0


def _spawn_tray() -> None:
    try:
        subprocess.Popen(
            [sys.executable, "-m", "rules_as_programs.ui.tray"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        pass


# --- daemon / tray control -------------------------------------------------

def cmd_daemon(args) -> int:
    from . import daemon
    daemon.run()
    return 0


def cmd_tray(args) -> int:
    from .ui import tray
    ipc.ensure_daemon()
    return tray.run(backend=args.backend)


def cmd_stop(args) -> int:
    resp = ipc.send_request({"type": "shutdown"})
    print("daemon stopped" if resp and resp.get("ok") else "daemon not running")
    return 0


def cmd_uninstall(args) -> int:
    print("Rules as Programs: uninstalling")
    print(f"  autostart: {autostart.uninstall()}")
    # Remove our hook entries from hooks.json (both scopes).
    from .adapters.cursor.adapter import SUBSCRIBED_HOOKS, _WRAPPER_NAME
    import json
    proj = os.path.abspath(args.path or os.getcwd())
    for scope in ("project", "global"):
        hooks_json = config.cursor_hooks_path(scope, proj)
        if not hooks_json.exists():
            continue
        try:
            data = json.loads(hooks_json.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        hooks = data.get("hooks", {})
        for event in SUBSCRIBED_HOOKS:
            arr = hooks.get(event)
            if isinstance(arr, list):
                hooks[event] = [h for h in arr
                                if not (isinstance(h, dict) and _WRAPPER_NAME in str(h.get("command", "")))]
                if not hooks[event]:
                    hooks.pop(event, None)
        hooks_json.write_text(json.dumps(data, indent=2) + "\n")
        print(f"  hooks: cleaned {hooks_json}")
    ipc.send_request({"type": "shutdown"})
    print("  daemon: stopped")
    print("\nNote: rule files and cached state were left in place.\n"
          f"Remove manually if desired: {config.state_dir()} and .cursor/rules-as-programs/")
    return 0


# --- status ----------------------------------------------------------------

def cmd_status(args) -> int:
    if not ipc.ping():
        print("daemon not running (start it with `rap daemon` or just run the agent)")
        return 1
    project = os.path.abspath(args.path) if args.path else None
    resp = ipc.send_request({"type": "verdicts", "project_root": project, "limit": args.limit})
    verdicts = (resp or {}).get("verdicts", [])
    if not verdicts:
        print("no violations recorded")
        return 0
    for v in verdicts:
        marker = SEV_EMOJI.get(v["severity"], "-")
        ago = int(time.time() - v["ts"])
        proj = os.path.basename(v["project_root"].rstrip("/")) or "?"
        print(f"[{marker}] {v['severity']:<8} {proj:<16} {v['rule_id']:<22} "
              f"{v['message']}  ({ago}s ago)")
    return 0


# --- rules -----------------------------------------------------------------

def cmd_rules(args) -> int:
    if args.rules_cmd == "list":
        return _rules_list(args)
    if args.rules_cmd == "add":
        return _rules_add(args)
    if args.rules_cmd == "test":
        return _rules_test(args)
    if args.rules_cmd == "convert":
        return _rules_convert(args)
    if args.rules_cmd in ("enable", "disable"):
        project = None if getattr(args, "global_scope", False) else os.path.abspath(
            getattr(args, "path", None) or os.getcwd())
        lookup_root = project or os.path.abspath(
            getattr(args, "path", None) or os.getcwd())
        rule = _load_rule_by_id(args.rule_id, lookup_root)
        if rule is None:
            print(f"rule {args.rule_id!r} not found", file=sys.stderr)
            return 1
        rules_api.set_enabled(
            rule.id, args.rules_cmd == "enable", project, rule.title)
        ipc.send_request({"type": "reload"})
        print(f"{args.rule_id}: {args.rules_cmd}d")
        return 0
    print("unknown rules subcommand", file=sys.stderr)
    return 2


def _rules_list(args) -> int:
    project_root = os.path.abspath(args.path or os.getcwd())
    rules = load_rules(project_root)
    print(f"Built-in templates: {', '.join(scaffold.builtin_ids())}\n")
    if not rules:
        print("No active rules. Run `rap init` to install the built-in set.")
        return 0
    print(f"Rules for {project_root}:")
    for r in rules:
        state = "on " if rules_api.is_enabled(r.id, project_root) else "off"
        kind = "paw" if r.spec else "py "
        print(
            f"  [{state}] {r.title:<34} ({r.scope:<7}) {kind} "
            f"trigger={r.trigger or 'unset'} id={r.id[:8]}…"
        )
    return 0


def _rules_add(args) -> int:
    scope = _scope_from_args(args)
    project_root = os.path.abspath(args.path or os.getcwd())
    target = scaffold.rules_dir_for(scope, project_root) / f"{args.rule_id}.py"
    if target.exists():
        print(f"{target} already exists; it was not overwritten", file=sys.stderr)
        return 1
    target = scaffold.add_builtin(args.rule_id, scope, project_root)
    if target is None:
        print(f"no built-in rule named {args.rule_id!r}. "
              f"Available: {', '.join(scaffold.builtin_ids())}", file=sys.stderr)
        return 1
    print(f"installed {target}")
    ipc.send_request({"type": "reload"})
    return 0


def _load_rule_by_id(rule_id: str, project_root: str):
    for r in load_rules(project_root):
        if rule_id == r.id or rule_id.lower() == r.title.lower():
            return r
    src = scaffold.BUILTIN_DIR / f"{rule_id}.py"
    if src.exists():
        loaded = load_rule_file(src, "builtin")
        return loaded[0] if loaded else None
    return None


def _rules_test(args) -> int:
    project_root = os.path.abspath(args.path or os.getcwd())
    rule = _load_rule_by_id(args.rule_id, project_root)
    if rule is None:
        print(f"rule {args.rule_id!r} not found", file=sys.stderr)
        return 1
    cases = list(rule.examples) or rules_api.spec_examples(rule.spec)
    if not rule.spec or not cases:
        print(f"rule {rule.id!r} has no PAW spec Input/Output cases to test")
        return 0

    runtime = paw_runtime.shared()
    if not runtime.available:
        print("PAW SDK not available; cannot compile/run", file=sys.stderr)
        return 1
    print(f"compiling {rule.id} ...")
    pid = runtime.program_id_for_spec(rule.spec, args.compiler)
    if not pid:
        print("compile failed", file=sys.stderr)
        return 1
    runtime.warm(pid)

    passed = 0
    for i, (inp, want) in enumerate(cases, 1):
        want_u = str(want).strip().upper()
        got_raw = runtime.run(pid, str(inp))
        got = (got_raw or "").strip().upper()
        ok = bool(want_u and got) and (want_u in got or got in want_u)
        passed += 1 if ok else 0
        print(f"  [{'PASS' if ok else 'FAIL'}] example {i}: want={want_u!r} got={got_raw!r}")
    total = len(cases)
    print(f"{passed}/{total} passed")
    if passed < total:
        print("Tip: iterate on the SPEC wording/examples (PAW docs), then re-test. "
              "Use `paw.list_compilers()` to discover higher-accuracy options.")
    return 0 if passed == total else 1


def _rules_convert(args) -> int:
    scope = _scope_from_args(args)
    project_root = os.path.abspath(args.path or os.getcwd())
    for note in scaffold.convert_prose_rules(project_root, scope):
        print(note)
    ipc.send_request({"type": "reload"})
    return 0


# --- doctor ----------------------------------------------------------------

def cmd_doctor(args) -> int:
    print("Rules as Programs -- doctor")
    print(f"  python:        {sys.executable}")
    try:
        import programasweights  # noqa: F401
        print("  PAW SDK:       installed")
    except Exception:
        print("  PAW SDK:       MISSING (pip install programasweights "
              "--extra-index-url https://pypi.programasweights.com/simple/)")
    details = ipc.ping_details()
    compatible = bool(
        details and details.get("protocol") == ipc.PROTOCOL_VERSION)
    if compatible:
        snapshot = ipc.send_request({"type": "snapshot"}, timeout=4) or {}
        daemon_text = (
            f"running (protocol {details.get('protocol')}, "
            f"health {snapshot.get('daemon', {}).get('health', 'unknown')})")
    elif details:
        daemon_text = (
            f"stale (protocol {details.get('protocol', 'legacy')}; "
            "restart with `rap tray`)")
    else:
        daemon_text = "stopped"
    print(f"  daemon:        {daemon_text}")
    print(f"  state dir:     {config.state_dir()}")
    print(f"  socket:        {config.socket_path()}")
    print(f"  icon:          {config.icon_png()}")
    print(f"  global rules:  {config.global_rules_dir()}")
    proj = os.getcwd()
    print(f"  project rules: {config.project_rules_dir(proj)}")
    for scope, path in (("global", config.cursor_hooks_path('global')),
                        ("project", config.cursor_hooks_path('project', proj))):
        print(f"  hooks ({scope}): {path} {'[present]' if Path(path).exists() else '[absent]'}")
    return 0


# --- arg parsing -----------------------------------------------------------

def _add_scope_flag(p: argparse.ArgumentParser) -> None:
    p.add_argument("--global", dest="global_scope", action="store_true",
                   help="apply to all projects (~/.cursor) instead of this repo")
    p.add_argument("--path", default=None, help="project root (default: cwd)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="rap", description="Rules as Programs")
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("init", help="install hooks + rules and launch (one command)")
    _add_scope_flag(pi)
    pi.add_argument("--scan", action="store_true",
                    help="discover existing project rules and draft rule programs")
    pi.add_argument("--no-launch", action="store_true", help="do not start daemon/tray")
    pi.add_argument("--no-tray", action="store_true", help="start daemon but not the tray")
    pi.add_argument("--no-autostart", action="store_true",
                    help="do not install a login autostart for the tray")
    pi.set_defaults(func=cmd_init)

    pd = sub.add_parser("daemon", help="run the daemon in the foreground")
    pd.set_defaults(func=cmd_daemon)

    pt = sub.add_parser("tray", help="run the menu-bar findings inbox")
    pt.add_argument("--backend", choices=["auto", "appkit", "pystray"], default="auto")
    pt.set_defaults(func=cmd_tray)

    ps = sub.add_parser("stop", help="stop the daemon")
    ps.set_defaults(func=cmd_stop)

    pun = sub.add_parser("uninstall", help="remove hooks + autostart and stop the daemon")
    pun.add_argument("--path", default=None, help="project root (default: cwd)")
    pun.set_defaults(func=cmd_uninstall)

    pst = sub.add_parser("status", help="show recent violations")
    pst.add_argument("--path", default=None, help="filter by project root")
    pst.add_argument("--limit", type=int, default=50)
    pst.set_defaults(func=cmd_status)

    pr = sub.add_parser("rules", help="manage rule programs")
    rsub = pr.add_subparsers(dest="rules_cmd", required=True)
    rl = rsub.add_parser("list"); _add_scope_flag(rl)
    ra = rsub.add_parser("add"); ra.add_argument("rule_id"); _add_scope_flag(ra)
    rt = rsub.add_parser("test"); rt.add_argument("rule_id")
    rt.add_argument("--compiler", default=None); _add_scope_flag(rt)
    rc = rsub.add_parser("convert"); _add_scope_flag(rc)
    re_ = rsub.add_parser("enable"); re_.add_argument("rule_id"); _add_scope_flag(re_)
    rd = rsub.add_parser("disable"); rd.add_argument("rule_id"); _add_scope_flag(rd)
    pr.set_defaults(func=cmd_rules)

    pdoc = sub.add_parser("doctor", help="diagnose the installation")
    pdoc.set_defaults(func=cmd_doctor)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
