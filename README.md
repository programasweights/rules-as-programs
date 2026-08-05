# Rules as Programs

**Give your agent's constraints a life of their own.**

Agent rules are usually passive text: an AI may forget them, reinterpret them, or
silently ignore them. Rules as Programs turns each rule into an **independent,
executable fuzzy program** that runs *alongside* your coding agent, observes its
reasoning and actions, gathers evidence about whether the rule's requirements
were met, and tells you when they weren't.

Each rule is one small **Python function**. For fuzzy judgment it calls a tiny
neural program compiled with [ProgramAsWeights (PAW)](https://programasweights.com)
— you describe the check in natural language and it runs **locally** — but a rule
can equally be plain Python (git, regex, any library). Judging is local-only and
private; the only remote step is the one-time compile.

The first integration targets **Cursor**, via its
[Agent Hooks](https://cursor.com/docs/hooks). The core is agent-agnostic so other
coding agents can be added later.

> **v1 is non-blocking by design.** It's an *agent reasoning audit* / LM
> observability layer: it only informs you (a PAW-branded status item and native
> findings inbox in the top-right menu bar), on top of whatever you already do.
> It never
> blocks or edits your agent's work. Enforcement (correcting/blocking the agent)
> is a designed-for later phase.

---

## Install in one command

From the root of an existing Cursor project:

```bash
pip install rules-as-programs --extra-index-url https://pypi.programasweights.com/simple/
rap init --scan
```

That single `rap init` will:

1. install a Cursor hook that feeds agent events to the local daemon
   (`.cursor/hooks.json` + `.cursor/hooks/rap-hook.sh`),
2. scaffold the built-in rule programs (`.py`) into `.cursor/rules-as-programs/rules/`,
3. (`--scan`) discover your existing prose rules (`.cursor/rules/*.mdc`,
   `AGENTS.md`, `.cursorrules`) and draft rule-program versions of them,
4. refresh the PAW menu-bar icon and install a login autostart for it,
5. start the daemon and the top-right menu item.

Then **reload Cursor** so it picks up the new hooks. That's it.

### Even easier: one prompt

Paste this to the Cursor agent in your repo:

> Set up Rules as Programs in this project by following the instructions in the
> Rules as Programs `AGENTS.md`.

See [`AGENTS.md`](AGENTS.md) for the agent-facing setup guide.

---

## What you get

### A native findings inbox in the menu bar

A large PAW item lives in the top-right (macOS menu bar; system tray on other
platforms) and starts automatically at login. A number beside it is the
actionable finding-group count, colored by highest severity: blue Info, yellow
Warning, or red Critical. The count remains visible when a rule check has an
operational problem; a secondary marker and tooltip describe that issue. A
separate purple `?` means an agent likely needs your reply.

Click it to open the native macOS popover:

- **Findings** is the home surface: choose a project, add a rule immediately,
  and switch between **Needs Review** and **Reviewed**.
- **Needs reply** appears above findings with the agent’s question and clears
  automatically when you submit the next prompt (or manually with Not waiting).
- Clicking a finding opens an evidence-first **Finding Inspector** showing the
  recorded rule name, exact evaluated input, raw rule output, surfaced severity,
  and a clearly separate expandable context window. Structured and Exact Text
  modes never change what Copy Input returns. Legacy/truncated records are
  labelled incomplete rather than presented as exact.
- **Edit Rule…** keeps the finding available as tuning context and can add the
  exact recorded input as an explicit test case without auto-deploying it.
- Findings record immutable compact rule ID, Name at the time, and active source hash.
  After a different source revision is activated, older open findings remain
  visible as **Rule changed — needs recheck** and stop contributing to severity
  badges until manually reviewed.
- **Rule Editor** is organized around intent: Name, Rule spec, Runs in,
  Runs when, and Reads. Every trigger/input has an information tip with an
  example. **View Python…** exposes the generated function without competing
  with the normal spec editor.
- **Deploy** is the single primary lifecycle action. New rules choose All
  projects or Selected projects; existing rules deploy directly. A clean rule
  shows a disabled **Deployed** button.
- Project headers expose **+ Rule** and **Manage Rules**; Projects remains the
  setup/monitoring-health view.
- **Rules for Project** is a labelled checklist of Project, Shared, and Built-in
  rules. Selections are stored in `.cursor/rules-as-programs/config.json` so
  they follow the repository; personal hidden-finding choices stay local.
- Interactive rows and flat actions visibly highlight on hover/press. The
  footer keeps the current Findings / Rules / Projects destination selected,
  and rule/project overflow controls are labelled **Actions…**.
- The native popover keeps one persistent table hierarchy across refreshes, so
  search, selection, keyboard focus, and scroll position remain stable. Native
  table selection and SF Symbols replace custom row overlays and text glyphs.
- The Rule Editor supports native Undo/Cut/Copy/Paste and Select All
  (`Command-A`, plus `Control-A`), preserves selection when its layout changes,
  and exposes the appropriate remove action directly in the window.

Action names are deliberately precise:

- **Mark Reviewed** hides this finding; a new occurrence can reappear.
- **Hide future findings in this project** suppresses future surfacing only in
  that repo; the rule still evaluates and logs, while the current finding stays
  open until reviewed.
- **Runs here** changes only the project assignment and is reversible.
- **Use shared version** removes a project customization while preserving that
  project assignment.
- **Delete project rule**, **Delete shared rule**, and **Remove installed
  built-in copy** remove exactly the named source definition after showing its
  path and impact. Open findings with no surviving definition move to
  **Reviewed** with a **Rule deleted** marker; their recorded source and audit
  history remain available. Shared-rule assignment and hidden-finding choices
  remain dormant under the immutable ID so surviving project overrides and a
  later reinstall keep the same behavior.
- **Pause monitoring** stops all evaluation for its project or globally and
  requires confirmation.

**Deploy** validates, tests, compiles, activates, and applies project coverage.
A failed deployment leaves the previous active revision and coverage running.
`Command-S` can still save a local draft without deploying it.

Warming is short-lived inline progress. Repeated runtime failures, model
preparation failures, rule import errors, and missing hooks become concrete,
project-scoped issues with Retry/Test/Details actions. A successful check clears
its runtime incident automatically.

### Per-project audit log

Every evaluated violation is appended to
`<project>/.cursor/rules-as-programs/log/audit.jsonl` with a stable finding ID,
timestamp, rule, severity, suppression state, typed evidence/probes, and rule
output. The log folder is auto-`.gitignore`d. Open it from the popover, or use
`rap status` in the terminal.

Operational diagnostics are local too:
`~/.cache/rules-as-programs/daemon.log` and `tray.log`.

### Built-in rule programs

| Rule | What its program watches for |
| --- | --- |
| `github-sync` | Meaningful local changes left uncommitted / unpushed to GitHub |
| `unverifiable-claim` | Claiming a check succeeded (e.g. "SSH works") when the evidence shows it couldn't actually be performed |
| `deployment-checklist` | Deploying without tests / migrations / GitHub sync / rollback addressed |
| `evidence-vs-assumption` | Stating a conclusion as fact when it depends on a prerequisite that was never obtained |
| `agent-needs-reply` | A completed response directly requires a user choice, confirmation, or missing information (purple attention, not a violation) |

Each is a small `.py` file: a `@rule` function that gathers evidence and calls a
**PAW fuzzy judge**.

---

## How it works

```
Cursor hooks ──stdin JSON──▶ rap-hook (thin, instant, fail-open)
                                   │ unix socket
                                   ▼
                         rap daemon (long-lived)
     normalize → evidence ledger → rule engine → PAW judge → verdict store
                                   │
                                   ▼
        menu-bar item + per-project audit log + `rap status`
```

- **Rules run independently.** Judgment happens in the daemon, over an
  append-only *evidence ledger* of what the agent actually thought and did —
  never by injecting more text into the agent's prompt.
- **It inspects reasoning and actions.** Cursor's `afterAgentThought`,
  `afterAgentResponse`, `afterShellExecution`, `afterFileEdit`, and tool hooks
  are normalized into one event schema.
- **It surfaces missing evidence.** Rules cross-reference a claim against the
  ledger; PAW decides `SUPPORTED` vs `UNVERIFIED_CLAIM` vs `HONEST_LIMITATION`.
- **It never stalls the agent.** Hooks return in milliseconds; PAW inference runs
  in the background with warm models; if PAW is slow or offline, the rule simply
  produces no verdict (graceful degrade).
- **Needs reply is an inference.** Cursor Hooks expose completed responses and
  the next submitted prompt, but no universal pending-input/approval state. A
  bundled local PAW rule detects direct blocking questions; purple attention can
  be dismissed and is never counted as a violation.

---

## Writing and customizing rules

The normal UI requires no Python: edit Name, Rule spec, Runs in, Runs when, and
Reads, then Deploy. Python remains canonical underneath at `rules/<id>/rule.py`;
**View Python…** opens the underlying program and advanced diagnostics.

Every rule has:

- immutable 16-character `id`, used by projects, findings, state, and history;
- mutable `name`, recorded with each finding;
- one editable working source and one last successfully checked active source
  hash.

The generated Python remains a single `@rule` function:

```python
from rules_as_programs import rule

SPEC = """Decide whether rsync or scp was used to synchronize project source code instead of Git. Directly copying source is a violation; transferring assets or release artifacts is allowed.
Return ONLY one of: OK, INFO, WARNING, CRITICAL

Input: ## Recent activity
- (shell_exec) $ rsync -av src/ host:/srv/app/src/
Output: WARNING

Input: ## Recent activity
- (shell_exec) $ scp public/logo.png host:/srv/assets/
Output: OK"""

@rule(id="7km3v9c2xq4t8n1p",
      name="Use Git for source synchronization",
      on=["shell_exec", "session_stop"], inputs=["shell_exec", "message"],
      spec=SPEC)
def use_git_for_source_sync(ctx):
    """Use Git—not direct source copying—to synchronize code."""
    decision = ctx.paw(SPEC)(ctx.input())
    return ctx.finding(decision, "Use Git for source synchronization")
```

`ctx` gives you `ctx.input()`, `ctx.evidence(probes=, include=, latest=)`,
`ctx.events(*kinds)`, `ctx.run(cmd)`, and `ctx.paw(spec)`. Existing explicit
`ctx.evidence(...)` rules remain supported. A plain-Python rule simply returns a
message when violated. Custom Python may return `("critical", "msg")`.

Canonical editable rules live in My Rule Library at
`~/.cursor/rules-as-programs/rules/<id>/rule.py`. Existing project-owned
definitions are moved there on their next successful deployment, preserving
their immutable ID, active revision, and project coverage. The project checklist
remains at `<repo>/.cursor/rules-as-programs/config.json`.

### Converting your existing prose rules

- **Agent-driven (best quality).** Run the one-prompt install (or ask the agent
  to follow [`AGENTS.md`](AGENTS.md)). The Cursor agent reads each plain-text
  rule, writes a managed fuzzy rule with realistic cases, runs
  `rap rules test`, and enables it.
- **`rap rules convert`** drafts a disabled fuzzy rule from each prose rule for
  you to refine.

### CLI

```bash
rap rules list                     # rules for this project (on/off, scope, paw/py)
rap rules add github-sync [--global]
rap rules test unverifiable-claim  # compile the SPEC and run its examples
rap rules enable|disable <id>
rap rules convert                  # draft .py rules from existing prose rules
```

**Writing good specs** (per the PAW docs): put realistic `Input:`/`Output:`
cases directly in `SPEC`, run `rap rules test <id>`, and iterate. The test
command parses those cases automatically; a duplicate Python `EXAMPLES` list is
not needed. Once stable, finalize with
`rap rules test <id> --compiler paw-ft-bs48`, or use **Deploy** in Rule
Editor.

---

## Commands

```bash
rap init [--global] [--scan] [--no-tray] [--no-launch] [--no-autostart]
rap status [--limit N] [--path DIR]
rap rules list|add|test|convert|enable|disable
rap tray [--backend auto|appkit|pystray]
rap daemon        # run the daemon in the foreground (normally auto-started)
rap stop          # stop the daemon
rap uninstall     # remove hooks + login autostart and stop the daemon
rap doctor        # diagnose the installation
```

Runtime state (socket, verdict DB, ledgers, active revision cache, personal
mutes, and monitoring state) lives in `~/.cache/rules-as-programs/` (override
with `RAP_STATE_DIR`). Shareable project rule assignments live in
`.cursor/rules-as-programs/config.json`; audit logs live under
`.cursor/rules-as-programs/log/`.

---

## Adding another agent integration

Only the Cursor adapter is Cursor-specific. To support another agent, implement
an `Adapter` (see
[`rules_as_programs/adapters/base.py`](rules_as_programs/adapters/base.py)) that
maps its raw hook payloads into the shared
[`Event`](rules_as_programs/core/events.py) schema and installs its hooks. The
daemon, engine, PAW runtime, verdict store, audit log, and tray are reused
unchanged.

## License

MIT.
