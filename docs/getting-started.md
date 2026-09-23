# Getting started

Rules as Programs gives your rules their own check on the agent. Install it in
a Codex project, trust its hooks, and use the findings to see where an observed
response or tool action may have broken a rule. v1 reports findings; it does
not block or correct the agent's work.

## Before you start

You need Python 3.10 or newer and Codex with lifecycle hooks. Keep the Python
environment you install into: the hooks and login-autostart entry retain its
interpreter path. Installation and PAW compilation need internet access;
managed rules evaluate inputs locally once the required assets are available.

macOS has the full menu-bar inbox, finding Inspector, and Rule Editor. Linux
and Windows have a reduced system-tray menu and use the CLI to author and
enable rules. macOS and Linux support login autostart; on Windows, start the
tray with `rap tray`.

## 1. Install and initialize one project

Run these commands from the root of your Codex project:

```bash
python -m pip install "git+https://github.com/programasweights/rules-as-programs.git" \
  --extra-index-url https://pypi.programasweights.com/simple/
rap init
```

Rules as Programs is installed from GitHub. The extra package index supplies
prebuilt `llama-cpp-python` wheels for ProgramAsWeights (PAW), the runtime that
turns a natural-language rule specification into a local neural program.

`rap init` installs the Codex hook and built-in rules, starts the daemon and
tray, and configures login autostart where supported. It writes the project's
hook definitions to `.codex/hooks.json`, the wrapper to
`.codex/hooks/rap-hook.sh`, and rule sources under
`.codex/rules-as-programs/rules/`.

Existing rule sources are preserved. Valid hook JSON is merged; back up
malformed hook configuration before initialization because it may be replaced.

Project-local setup is a good starting point. Use `rap init --global` only
when you want hooks and rules for all your projects; it writes to
`$CODEX_HOME`, normally `~/.codex/`. See the [reference](reference.md) for
installation flags and the pipx alternative.

## 2. Restart Codex and trust the hooks

Restart Codex, open `/hooks`, and review and trust the RAP hook definitions.
For project-local hooks, also trust the project's `.codex/` configuration
layer. Codex skips new or changed non-managed hooks until their exact hash is
trusted, so an installed hook file alone is not enough.

## 3. Check the first agent turn

From the project root, run:

```bash
rap doctor
rap rules list
```

Look for the PAW SDK, a running daemon, and the project hook file in
`rap doctor`. `rap rules list` shows the installed rules and their on/off
state. Neither command verifies Codex's hook trust.

Run one normal agent turn after trusting the hooks. On macOS, open the paw
menu-bar item and inspect the project's activity and Evaluation History. On
any platform, check `.codex/rules-as-programs/log/evaluations.jsonl` for rule
invocations. This includes successful `OK` outcomes as well as findings and
errors.

An empty findings list can be healthy: a rule that returns `OK` creates no
finding. `rap status` shows recorded findings, so “no violations recorded”
does not by itself show whether hooks ran. Use activity or the evaluation log
to distinguish a quiet turn from missing events.

## 4. Read a finding, then add your own rule

On macOS, the number beside the paw shows the actionable finding groups.
Open a finding to inspect the exact input evaluated and the rule's output.
A separate purple `?` indicates that an agent likely needs a reply. The
[findings guide](findings.md) explains review, grouping, and operational
errors.

To create a rule, select your project in the menu-bar inbox and click
**+ Rule**. Give it a name, choose one trigger, describe what should count as
a finding, then use **Deploy** to activate it for the intended projects.
**Command-S** saves a draft without deploying it.

The [writing rules guide](writing-rules.md) walks through a complete example,
testing, compiler choices, and the CLI workflow for Linux and Windows.

## Optional: start from existing prose rules

If you already keep instructions in `AGENTS.md`, `AGENTS.override.md`,
`.cursor/rules/*.mdc`, `.cursor/rules/*.md`, or `.cursorrules`, you can use
`rap init --scan` instead of `rap init`. If setup is already complete, run
`rap rules convert` once from the project root.

Both use the same rough scanner: one disabled draft per source document,
based on a short excerpt. They do not turn every instruction into a separate
rule. Do not run both or repeatedly scan the same documents; new scans can
create duplicate drafts.

Review the drafts, split independent instructions into separate rules, and
choose a trigger whose input actually contains the evidence you need. Test
each rule before relying on it. On macOS, finish with **Deploy**; on Linux
and Windows, test and enable the source through the CLI. Follow the
[authoring workflow](writing-rules.md), including its guidance on keeping
private material out of specifications.

## If something is missing

- **No menu-bar or tray item:** run `rap tray`, then `rap doctor`. Linux and
  Windows show the reduced interface; they do not have the native Rule Editor.
- **No activity after an agent turn:** check `/hooks` trust and project
  configuration trust, then check that the daemon is running. A hook changed
  by setup or an upgrade needs trust for its new hash.
- **Activity appears but a rule does not run:** check its trigger, on/off
  state, and project coverage. A tool rule only runs on its selected tool
  event; a disabled scan draft does not run.
- **A build or evaluation fails:** inspect the error's Details on macOS and
  the evaluation log. Check network access for compilation and asset
  downloads; daemon diagnostics are in
  `~/.cache/rules-as-programs/daemon-stderr.log` by default.

Managed PAW compilation sends the specification, including embedded examples,
to the compile service as a public, persistent program. Observed inputs are
evaluated locally. Logs and saved test cases can contain those inputs in
plaintext; review them before sharing. The [reference](reference.md) covers
data storage, pause behavior, and removal.
