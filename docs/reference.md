# Reference

Use [Getting started](getting-started.md) for installation,
[Writing rules](writing-rules.md) for authoring, and
[Working with findings](findings.md) for reviewing observations. This page
covers the current CLI, supported platforms, file locations, and diagnostics.

## Requirements and platforms

RAP requires Python 3.10 or newer and Codex lifecycle hooks. Installation and
PAW artifact creation or refresh require internet access. Managed inference
runs locally after the required assets are available.

- **macOS:** native menu-bar inbox, finding Inspector, Rule Editor, managed
  Deploy workflow, Validation Cases, and login autostart.
- **Linux:** reduced `pystray` menu and XDG login autostart. No native Rule
  Editor or managed Deploy action.
- **Windows:** reduced `pystray` menu. Start `rap tray` manually; RAP does not
  install login autostart on Windows.

The reduced menu shows finding groups, allows review, opens project audit
logs, and provides monitoring issue information. Its review action applies to
the selected group. Use source files and the CLI to author, test, and assign
rules on these platforms.

Hook wrappers and autostart entries retain the installing Python executable's
path. Keep that environment available, or rerun setup from its replacement.

### Install with pipx

For an isolated CLI environment, install from GitHub with pipx, then initialize
from the root of the project you want to monitor:

```bash
pipx install "git+https://github.com/programasweights/rules-as-programs.git" \
  --pip-args="--extra-index-url https://pypi.programasweights.com/simple/"
rap init
```

The ProgramAsWeights index supplies prebuilt local-inference dependencies; RAP
itself is installed from GitHub. Keep the pipx environment available because
the hook and login entry refer to its Python executable.

## CLI

Run `rap --help` or append `--help` to a command for its parser help. `DIR`
below is a project root; where supported, it defaults to the current directory
unless stated otherwise.

### Initialize

```bash
rap init [--global] [--path DIR] [--scan] [--no-launch] [--no-tray] [--no-autostart]
```

Installs Codex hooks and built-in rule sources, migrates missing legacy RAP
state, refreshes the menu icon when reachable, configures supported autostart,
and starts the daemon and tray.

- `--global` installs hooks and rule sources under `CODEX_HOME` rather than
  the selected project's `.codex/` directory.
- `--scan` creates disabled rough drafts from existing prose-rule documents.
  It uses short excerpts and creates one draft per document; rerunning it can
  create duplicates. Review and split drafts into useful individual rules.
- `--no-launch` skips launching the daemon and tray. It does not skip autostart
  installation; add `--no-autostart` when that is also unwanted.
- `--no-tray` skips the tray launch while allowing daemon startup.
- `--no-autostart` skips installing a login entry.

Valid existing hook JSON is merged. Malformed hook JSON may be replaced, so
back up custom configuration before setup. After installation or a hook
change, restart Codex and use `/hooks` to review and trust the current RAP hook
definitions. Project-local hooks also require trust in the project's
`.codex/` configuration layer.

### Inspect installation and findings

```bash
rap doctor
rap status [--path DIR] [--limit N]
```

`doctor` reports the Python executable, PAW SDK availability, daemon protocol
and health, state paths, rule paths, and global/project hook-file presence.
Its project is the current directory; it has no `--path` option. These checks
do not establish that Codex trusts the current hook hash or that an event has
been evaluated successfully.

`status` prints recent recorded findings, with a default limit of 50. Without
`--path`, it queries across projects. It requires a running daemon and does
not show all successful evaluations or establish monitoring health.

### Manage rule sources and assignments

```bash
rap rules list [--path DIR] [--global]
rap rules add <built-in-name> [--global] [--path DIR]
rap rules convert [--global] [--path DIR]
rap rules test <id> [--compiler NAME] [--path DIR] [--global]
rap rules enable <id> [--global] [--path DIR]
rap rules disable <id> [--global] [--path DIR]
```

`list` shows loadable shared and project rule sources, assignment state,
trigger, kind, and a shortened ID. A project source takes precedence when it
shares an ID with a library source. Although accepted by the parser,
`--global` does not change the lookup behavior of `list` or `test`; those
commands use `--path` or the current project.

`add` installs a bundled template. Available template names are
`unverifiable-claim`, `evidence-vs-assumption`, and `agent-needs-reply`.
`convert` performs the same disabled-draft conversion as `init --scan`.

`test` compiles and runs the rule's specification examples and returns a
nonzero exit status for failed examples or a compilation/runtime availability
failure. It uses explicit rule examples when present, otherwise `Input:` and
`Output:` cases parsed from the spec. It does not run the editor's
`tests.json` cases. `--compiler NAME` selects a compiler for this invocation;
it does not persist a deployment choice. A rule without a PAW spec or cases
prints that there is nothing to test and exits successfully.

Use a full rule ID for `test`, `enable`, and `disable`. The current lookup also
accepts an exact display name, ignoring case, or a bundled template name; a
shortened ID printed by `list` is not a supported prefix lookup.

`enable` and `disable` change assignment for the selected project, or the
global default with `--global`. They do not compile, run tests, create a
deployed revision, or persist a compiler choice. Testing and enabling a
working source is the CLI workflow on Linux and Windows. On macOS, **Deploy**
provides the managed revision and compiler lifecycle.

### Run and stop processes

```bash
rap daemon
rap tray [--backend auto|appkit|pystray]
rap stop
```

`daemon` runs the daemon in the foreground. `tray` ensures a daemon is
available and runs the tray; `auto` chooses the native AppKit interface on
macOS when available, otherwise the reduced `pystray` backend. `stop` requests
daemon shutdown. It does not remove hooks or autostart, so a later hook or
tray action can start the daemon again.

### Remove the integration

```bash
rap uninstall [--path DIR]
```

Removes RAP's hook registrations from the selected project and global
`hooks.json`, removes supported login autostart, and requests daemon shutdown.
Other projects' hook registrations and generated wrapper scripts remain.
This command does not uninstall the Python package or remove rule sources,
Validation Cases, project configuration, logs, or cached state. Review those
files separately before deleting any history or rule work you want to keep.

## Triggers and inputs

Each managed rule selects one Codex trigger and receives one field from that
hook's raw JSON payload. These are the complete current default mappings:

- `Stop` → `/last_assistant_message`: assistant response.
- `PreToolUse` → `/tool_input`: tool invocation input.
- `PostToolUse` → `/tool_response`: tool result.
- `UserPromptSubmit` → `/prompt`: user prompt.
- `SubagentStop` → `/last_assistant_message`: subagent response.
- `PermissionRequest` → `/tool_name`: name of the tool requesting approval.
- `SubagentStart` → `/agent_type`: subagent type.
- `PreCompact` → `/trigger`: trigger for the upcoming context compaction.
- `PostCompact` → `/trigger`: trigger for the completed context compaction.
- `SessionStart` → `/source`: session start source.
- `SessionEnd` → `/reason`: session end reason.

Text fields pass through unchanged. Objects and arrays become indented JSON
with sorted object keys; numbers, booleans, and null become their JSON text
representations. The resulting string is `ctx.input` and is recorded with the
evaluation. A missing field produces an input failure rather than an empty
string or an `OK` result.

An advanced `input_pointer` can select another field using JSON Pointer
syntax, such as `/tool_input/command`. It still selects from the one trigger
payload; it does not aggregate Session Activity. The definitions and
serialization behavior are in
[`core/triggers.py`](../rules_as_programs/core/triggers.py).

## Sources, coverage, and local state

The default source and configuration locations are:

```text
<project>/.codex/hooks.json
<project>/.codex/hooks/rap-hook.sh
<project>/.codex/rules-as-programs/config.json
<project>/.codex/rules-as-programs/rules/<id>/rule.py
<project>/.codex/rules-as-programs/rules/<id>/tests.json

~/.codex/hooks.json
~/.codex/hooks/rap-hook.sh
~/.codex/rules-as-programs/rules/<id>/rule.py
~/.codex/rules-as-programs/rules/<id>/tests.json
```

`CODEX_HOME` replaces `~/.codex` for global hooks and My Rule Library. It does
not relocate project-local configuration or RAP's cache.

Every rule has an immutable 16-character ID and a mutable display name.
Project sources override library sources with the same ID. Source ownership
and project coverage are distinct: a library rule can cover All Projects or
Selected Projects. Project assignment overrides live in the shareable
`config.json`; global defaults and personal settings live in local cache
state.

Deploying a standalone project-owned rule moves it into My Rule Library and
applies the selected coverage. A project override with the same ID as an
existing library rule cannot currently Deploy until the source conflict is
resolved. **Rules for Project** edits assignments; it does not make personal
hidden-finding choices part of the shared project configuration.

The default user-level state directory is `~/.cache/rules-as-programs/`.
It contains:

- `verdicts.db`, conversation `ledgers/`, and personal monitoring/mute state;
- `active_revisions.json`, `revisions/`, and `deployment-queue.json`;
- compiler metadata, `paw_programs.json`, and `validation-results.db`;
- `daemon.log`, `daemon-stderr.log`, `tray.log`, and process/socket files.

Project logs are separate:

- `.codex/rules-as-programs/log/audit.jsonl` records individual finding
  occurrences, including suppressed findings.
- `.codex/rules-as-programs/log/evaluations.jsonl` records invocation starts,
  completions, and failures, including `OK` outcomes.

Set `RAP_STATE_DIR` to relocate the user-level cache and databases. Give Codex,
the hook, daemon, and tray the same value so they use the same state and socket.
It does not move project logs, project configuration, or rule sources.
Generated autostart entries do not persist this environment variable.

On macOS, autostart uses
`~/Library/LaunchAgents/com.programasweights.rules-as-programs.plist`. On Linux,
it uses `~/.config/autostart/rules-as-programs.desktop`.

## Data and privacy

Managed PAW rules evaluate observed inputs locally. Artifact creation sends
the rule specification to the PAW compile service, including examples
embedded in that specification. RAP requests **public, persistent programs**
(`public=True`, `ephemeral=False`), so do not put secrets, private source, or
private observed text into a spec or its embedded examples. Compilation can
happen again after spec/compiler changes or during Automatic background
optimization. Observed trigger inputs and separate Validation Cases are not
added to the managed compile request.

Advanced Python rules are unsandboxed Python. They can read files, access the
network, and transmit their inputs. Install only sources you trust; local
managed inference does not restrict what custom Python can do.

RAP's operational data is stored locally in plaintext, including SQLite
databases. Depending on the event and outcome, records can contain normalized
events, raw Codex payloads, mapped inputs, outputs, rule sources, findings, and
diagnostics. Saved Validation Cases can contain copied observed inputs.

**Pause stops evaluation, not event collection.** Muting changes surfacing,
not evaluation or logging. Neither control is a privacy switch.

Evaluation logs rotate at 10 MiB with up to five backups. Ledgers and audit
logs have no automatic retention policy. This development version can reset
verdicts, ledgers, audit logs, and evaluation logs when its finding schema
changes; do not rely on local history as a durable archive.

RAP writes a `.gitignore` in a new project log directory. Verify repository
ignore rules before sharing, and inspect rule sources and `tests.json` for
sensitive content. An ignore entry does not protect a file already tracked by
Git.

## Diagnostics

For an apparently inactive installation:

1. Run `rap doctor` from the project root and check the interpreter, SDK,
   daemon health, and hook paths. `rap tray` can reconnect to or restart an
   incompatible daemon.
2. Restart Codex after hook installation or changes, open `/hooks`, and trust
   the exact current definitions and project configuration layer.
3. Run an agent turn. Check project activity, then Evaluation History or
   `evaluations.jsonl` for the expected trigger and rule outcome.
4. Check assignments, pause state, project monitoring state, and muted
   findings. For a load or input failure, inspect the rule source and selected
   trigger field. For compilation/inference failures, inspect the displayed
   monitoring issue and daemon logs.

`daemon-stderr.log` retains daemon stdout/stderr and worker tracebacks;
`daemon.log` contains daemon diagnostics, and `tray.log` helps with tray
startup problems. Review and redact logs before attaching them to a report.

The hook uses a short IPC timeout and never waits for model inference. A
missing event may reflect unavailable delivery, not an `OK` result. The
supervised local inference worker is serialized; a native timeout replaces
the worker. Compilation uses a separate executor and may continue while
local inference is running.
