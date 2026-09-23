# Contributing

Rules as Programs turns agent rules into independently evaluated Python
programs. Contributions can improve the Codex adapter, rule authoring,
evaluation, findings interface, or documentation. The current product reports
observations without blocking or modifying the agent's work.

## Development setup

Use Python 3.10 or newer. From a checkout, create an environment and install
the package with its test dependency:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]" \
  --extra-index-url https://pypi.programasweights.com/simple/
```

On Windows, activate the environment with `.venv\Scripts\Activate.ps1` in
PowerShell. The extra index supplies prebuilt local-inference dependencies;
RAP itself comes from the checkout. macOS installs the native PyObjC UI
dependency, while the reduced tray uses `pystray` and Pillow.

Run tests from the repository root using the same Python environment:

```bash
python -m pytest tests
```

To inspect collection without running tests:

```bash
python -m pytest --collect-only -q tests
```

Native AppKit tests are macOS-only, and some need a graphical session. Use a
focused test file while iterating, such as
`python -m pytest tests/test_triggers.py`, then run the tests relevant to
the full change. A manual installation or native UI check is useful for
changes that depend on hook trust, login startup, or window behavior.

## Code map

- `rules_as_programs/cli.py`, `config.py`, `scaffold.py`, and `autostart.py`
  implement setup, paths, source scaffolding, and process entry points.
- `rules_as_programs/adapters/` defines the integration interface.
  `adapters/codex/` installs hooks and normalizes Codex payloads.
- `rules_as_programs/core/` contains events, exact trigger/input mappings,
  rule loading and evaluation, ledgers, findings, revisions, deployment
  queues, and validation-result storage.
- `rules_as_programs/daemon.py` coordinates event intake, evaluation, local
  state, and UI requests; `ipc.py` connects clients to it.
- `rules_as_programs/sdk.py` defines the author-facing `@rule` and context
  API. `rules_api.py` handles source editing, assignments, coverage, and rule
  management.
- `rules_as_programs/paw_runtime.py` manages compiler discovery and PAW
  artifacts. `paw_inference_process.py` supervises local inference.
- `rules_as_programs/ui/` contains the native macOS inbox, Inspector, Rule
  Editor, presentation models, and reduced tray backend.
- `rules_as_programs/builtin_rules/` contains the bundled rule templates.
  `tests/` contains the regression suite.

Local PAW function creation, warmup, and inference share one supervised
subprocess and must remain serialized. Compilation uses a separate executor.
Changes to the runtime should preserve this separation and the worker's
timeout/replacement behavior.

## Proposing a change

Describe the user-visible problem and intended behavior, with a small
reproduction where possible. For rule or findings changes, identify the
trigger, exact mapped input, and expected outcome. Synthetic examples are
usually enough; remove private conversation text, source, paths, and secrets
from reports and fixtures.

Keep tests focused on observable behavior. Relevant checks may cover payload
normalization, project/library precedence, recorded evaluation provenance,
deployment failure recovery, or native UI interactions. Explain what you
verified and any platform-specific checks you could not run.

Update the corresponding product documentation when behavior changes:

- [Getting started](docs/getting-started.md) for installation and hook trust.
- [Writing rules](docs/writing-rules.md) for authoring, testing, and deployment.
- [Working with findings](docs/findings.md) for inspection and review.
- [Reference](docs/reference.md) for CLI, platforms, storage, and diagnostics.

For another agent integration, implement the interface in
[`adapters/base.py`](rules_as_programs/adapters/base.py) and map its payloads
into the shared [`Event`](rules_as_programs/core/events.py) schema. Keep
agent-specific hook installation and normalization in the adapter so the
engine, runtime, stores, and UI model remain reusable.
