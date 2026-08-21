# Rules as Programs

**Give your agent's constraints a life of their own.**

Agent rules are usually passive text: an AI can forget, reinterpret, or ignore
them. Rules as Programs turns each rule into an independent Python function
that observes a coding agent's reasoning and actions and reports when the
evidence appears to violate that rule.

Managed fuzzy rules use
[ProgramAsWeights (PAW)](https://programasweights.com): write the judgment in
natural language, compile it into a small neural program, and run that program
locally alongside the agent. Advanced rules can use ordinary Python instead.

> **v1 is observability-only.** Rules report findings; they do not block, edit,
> or correct the agent's work.

The first integration uses
[Cursor Agent Hooks](https://cursor.com/docs/hooks). The engine and event model
are designed so other agent adapters can be added later.

## Requirements and platform support

- Python 3.10 or newer.
- Cursor with Agent Hooks.
- Internet access when installing dependencies and creating or refreshing PAW
  artifacts. Inference runs locally after the required assets are downloaded.
- macOS provides the full native menu-bar inbox, Inspector, Rule Editor, and
  login autostart.
- Linux and Windows use a reduced system-tray menu. Linux supports XDG
  autostart; on Windows, start `rap tray` manually.

Rule and hook processes use the Python executable selected during installation.
Install into an environment you intend to keep.

## Install from GitHub

From the root of an existing Cursor project:

```bash
python -m pip install "git+https://github.com/programasweights/rules-as-programs.git" \
  --extra-index-url https://pypi.programasweights.com/simple/
rap init --scan
```

Rules as Programs itself is installed from GitHub. The ProgramAsWeights index
contains prebuilt `llama-cpp-python` wheels for PAW's local inference runtime,
avoiding a local llama.cpp build; it does not host Rules as Programs.

`rap init --scan`:

1. merges the RAP hook into `.cursor/hooks.json` and writes its wrapper script;
2. installs the built-in rules;
3. creates disabled drafts from existing prose-rule documents;
4. starts the daemon and tray, and configures supported login autostart.

The scanner is intentionally rough. It reads top-level `.cursor/rules/*.mdc`,
`.cursor/rules/*.md`, `AGENTS.md`, and `.cursorrules`, then creates one disabled
draft per document from a short excerpt. It does not split a document into
individual rules, and rerunning it can create duplicate drafts. Run it once,
then review each draft before making it active.

If `.cursor/hooks.json` contains custom configuration, keep a backup. RAP merges
valid JSON, but malformed hook JSON may be replaced.

Reload Cursor so it reads the new hook configuration, then verify:

```bash
rap doctor
rap rules list
```

`rap doctor` verifies the installation and hook file; it cannot prove that the
currently running Cursor process has reloaded the hook. Run one agent turn after
reloading, then inspect the tray's project activity or
`.cursor/rules-as-programs/log/evaluations.jsonl`. `rap status` reports
findings, so a healthy turn may legitimately show none.

### Let a Cursor agent finish setup

Paste this into the agent chat in the project:

> Set up Rules as Programs in this project by following the repository's
> `AGENTS.md`. Review and improve every disabled scan draft before making it
> active.

See [`AGENTS.md`](AGENTS.md) for the complete agent-facing setup guide.

## How it works

```text
Cursor hook ──stdin JSON──▶ rap-hook ──local socket──▶ long-lived daemon
                                                          │
                                    exact trigger field ──┤
                                                          ▼
                                               Python rule / PAW judge
                                                          │
                                  evaluation log + finding store + tray
```

- Each managed rule has one Cursor trigger and one predefined input field.
  The Inspector shows the same mapped string that PAW evaluates.
- Surrounding Session Activity is retained for inspection but is not silently
  included in a Basic rule's input.
- The hook has a short IPC timeout and never waits for model inference. If the
  daemon is unavailable, an event can be dropped while the client starts the
  daemon for subsequent events.
- Local PAW loading, warmup, and inference are serialized through one
  supervised subprocess. A native timeout replaces a stuck worker.
- Remote compilation uses a separate executor and can overlap local inference.

## Create, test, and deploy a rule

On macOS, open **+ Rule** from the tray. A managed fuzzy rule has:

- a mutable display name;
- one Cursor trigger;
- a derived input field, optionally overridden with an advanced JSON Pointer;
- the exact PAW specification;
- All Projects or Selected Projects coverage.

RAP does not append to or rewrite the specification. It warns when the spec
does not mention `OK` plus at least one finding level, but the author controls
the output contract.

The normal workflow is:

1. Describe the judgment and choose its trigger.
2. Optionally add Validation Cases and click **Run Tests**.
3. Click **Deploy**. RAP checks the source, prepares the selected compiler
   artifact, activates the exact draft, and applies its project coverage.
4. If preparation takes time, **Deploy When Ready** stores an immutable intent
   and closes the editor while the tray tracks completion.

A failed deployment leaves the last successful active revision running.
`Command-S` saves a draft without deploying it.

Linux and Windows currently have no Rule Editor or Deploy action. Review the
source, run `rap rules test <id>`, then use `rap rules enable <id>` (with
`--global` for an explicitly global setup). This assigns the working source
directly and bypasses the managed revision, compiler-pinning, and deployment
queue lifecycle.

### Compilers and Validation Cases

**Automatic (Recommended)** deploys first with a compatible fast compiler. Once
that behavior is active, RAP builds and warms a compatible finetuned artifact,
when one is available, in a durable background job and promotes it only if the
deployed behavior is still current. **Explicit compiler** pins a compiler from
PAW's live catalog. Previously built artifacts for the same behavior revision
are retained so switching back does not require rebuilding them.

Validation Cases are stored in `tests.json` beside the rule. Only **Run Tests**
executes them. They never run implicitly and never gate deployment or automatic
compiler promotion. Results persist locally by exact spec, compiler snapshot,
and case content.

The CLI has a separate test mechanism: `rap rules test <id>` parses
`Input:`/`Output:` examples embedded in the specification. It does not run the
Rule Editor's `tests.json` cases.

### Rule source

The managed editor generates an ordinary `@rule`-decorated function:

```python
from rules_as_programs import rule

SPEC = """Decide whether this shell command uses rsync to synchronize source.
Return ONLY one of: OK, WARNING

Input: rsync -av src/ host:/srv/app/src/
Output: WARNING

Input: cp public/logo.png dist/assets/
Output: OK"""

@rule(
    id="7km3v9c2xq4t8n1p",
    name="Do not use rsync",
    trigger="afterShellExecution",
    spec=SPEC,
)
def do_not_use_rsync(ctx):
    decision = ctx.paw(SPEC)(ctx.input)
    return ctx.result(decision)
```

`ctx.input` is the exact mapped trigger field. `ctx.paw(spec)` invokes the local
fuzzy program, and `ctx.result(...)` maps `OK`, `INFO`, `WARNING`, or `CRITICAL`
to the rule outcome.

Every rule has an immutable 16-character ID. Its name is display metadata:
renaming a rule does not change its behavior identity, invalidate compiler
artifacts, or make existing findings stale.

Plain Python rules can use regexes, git, local files, or other libraries. The
engine can run them, but the current Rule Editor deployment pipeline supports
PAW-backed managed rules. Install and enable advanced plain-Python rules
manually.

Rules can be project-owned:

```text
<project>/.cursor/rules-as-programs/rules/<id>/rule.py
```

or shared through My Rule Library:

```text
~/.cursor/rules-as-programs/rules/<id>/rule.py
```

Per-project assignment is stored in `.cursor/rules-as-programs/config.json`.
Deploying a standalone project-owned rule moves it into My Rule Library. A
project override that shares an ID with an existing library rule cannot
currently Deploy until the conflicting sources are resolved.

## Findings and attention

The full macOS interface provides:

- a severity-colored actionable group count beside the PAW menu-bar icon;
- a separate purple `?` when an agent response likely requires a reply;
- project filtering and Needs Review / Reviewed views;
- exact rule input and output in the finding Inspector;
- Evaluation History for every invocation, including `OK` and runtime errors.

Repeated findings from one rule are grouped without making review implicitly
bulk. A single occurrence has no redundant count. Multiple occurrences can be
expanded and reviewed individually with **Review This Occurrence**; **Review
All N Occurrences…** is a separate confirmed action.

Muting is project-specific and suppresses future surfacing while the rule keeps
evaluating and logging. Older-revision findings remain reviewable as **Older
revision · Needs recheck**, but do not contribute to the current severity
badge. Editing a finding's rule can copy its exact observed input into a
Validation Case without deploying anything.

The purple needs-reply indicator comes from either an explicit Cursor
Ask Question event or the bundled local fuzzy rule; it is not a violation or a
universal native approval state. It clears after the next submitted prompt in
that conversation or through **Mark no reply needed**.

## Built-in rules

- `unverifiable-claim` flags unqualified success claims without the required
  evidence.
- `evidence-vs-assumption` flags reasoning that relies on an unsupported
  assumption.
- `agent-needs-reply` drives the purple attention indicator for direct blocking
  questions; it is not a violation.

Built-ins are normal Python rule programs and can be inspected like any other
rule.

## Data, privacy, and cleanup

Managed PAW rules evaluate observed inputs locally. Creating or refreshing a
PAW artifact sends the rule specification—not observed trigger inputs—to the
PAW compile service. Compilation is not necessarily one-time: changing the
spec, compiler, or compiler snapshot and Automatic background optimization can
compile again. Do not place secrets in a specification or its examples.

Advanced Python rules are unsandboxed and can access files, use the network, or
transmit their inputs. Only install rules you trust.

RAP stores local operational data in plaintext. Depending on the event and
outcome, this can include normalized events, raw Cursor hook payloads, mapped
inputs, outputs, findings, and diagnostics:

- `~/.cache/rules-as-programs/` — ledgers, databases, active revisions, compiler
  state, validation results, daemon logs, and personal UI state;
- `<project>/.cursor/rules-as-programs/log/audit.jsonl` — non-deduplicated
  finding occurrences;
- `<project>/.cursor/rules-as-programs/log/evaluations.jsonl` — every rule
  invocation, including `OK`, input failures, and runtime errors;
- `<project>/.cursor/rules-as-programs/config.json` — shareable project rule
  assignments.

Pause stops rule evaluation; it does not stop event collection. Evaluation logs
rotate, but ledgers and audit logs currently have no automatic retention
policy. RAP creates ignore protection for a new project log directory, but
verify your repository's ignore rules before committing. Validation Cases can
contain copied observed inputs, so inspect `tests.json` before sharing it.

This development version may reset verdicts, ledgers, audit logs, and evaluation
logs when its finding schema changes. Do not treat local history as a durable
archive.

`rap uninstall` removes the hook registration and login autostart and stops the
daemon for the current project and global scope. Other projects' hook entries
and generated wrapper scripts remain. It deliberately leaves rule and test
sources, project configuration, logs, and cached state for manual review or
deletion.

Set `RAP_STATE_DIR` to move the user-level cache and databases. The same value
must reach Cursor, the hook, daemon, and tray; generated login-autostart entries
do not persist that environment variable for you.

## CLI reference

```bash
rap init [--global] [--scan] [--no-tray] [--no-launch] [--no-autostart]
rap doctor
rap status [--limit N] [--path DIR]
rap rules list
rap rules add <built-in-name> [--global]
rap rules convert
rap rules test <id> [--compiler NAME]
rap rules enable|disable <id>
rap tray [--backend auto|appkit|pystray]
rap daemon
rap stop
rap uninstall
```

`rap rules enable` and `disable` change assignment only; they do not compile,
test, or activate a revision. `rap rules convert` uses the same rough,
disabled-draft conversion as `rap init --scan`.

## Adding another agent integration

Only the Cursor adapter is Cursor-specific. To support another agent, implement
an [`Adapter`](rules_as_programs/adapters/base.py) that maps raw payloads into
the shared [`Event`](rules_as_programs/core/events.py) schema and installs the
agent's hooks. The daemon, engine, PAW runtime, stores, and UI model can be
reused.

## License

MIT.
