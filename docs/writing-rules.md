# Writing rules

A useful rule answers one question about one observable input. Start with a
small judgment you can explain and test, such as whether an assistant labels
a time estimate as uncertain. Rules as Programs runs that check independently
and records a finding when it returns `INFO`, `WARNING`, or `CRITICAL`.
`OK` creates no finding. None of these outcomes blocks the agent.

## Choose what the rule can observe

Choose a trigger before writing the specification. Each trigger supplies one
predefined field:

- **Assistant response** (`Stop`) supplies `/last_assistant_message`.
- **Tool invocation** (`PreToolUse`) supplies `/tool_input`.
- **Tool result** (`PostToolUse`) supplies `/tool_response`.
- **User prompt** (`UserPromptSubmit`) supplies `/prompt`.

See the [reference](reference.md) for the complete trigger list. Text fields
are passed as text; structured fields such as tool input are serialized as
JSON. The Inspector shows the same mapped string the managed rule evaluates.

Write examples of that field alone. A response rule can judge what a response
says, but cannot establish what happened in an earlier tool call. Session
Activity remains separate and is not silently added to the rule's input.
If an instruction contains several independent requirements, give each its
own rule and suitable trigger.

## Describe the judgment

For this example, choose **Assistant response** and name the rule **Label
time estimates**. The rule should flag definite promises about how long
future work will take, allow clearly qualified estimates, and leave reports
of completed work alone.

Use plain language to state the decision, the relevant exception, and the
allowed outputs. Add three to five synthetic `Input:` / `Output:` examples
that cover both findings and allowed behavior. End with a clear output
instruction. Here is a complete specification:

```text
Decide whether the assistant presents the duration of future work as certain.
Return WARNING for a definite duration or completion-time promise without
uncertainty. Return OK for a duration explicitly described as an estimate,
for reports of time already spent, or when no future duration is claimed.

Input: The migration will take exactly two hours.
Output: WARNING

Input: I estimate the migration will take about two hours.
Output: OK

Input: The migration took two hours.
Output: OK

Input: The migration will definitely be finished in 15 minutes.
Output: WARNING

Return ONLY one of: OK, WARNING
```

Run these cases, then add examples that reflect your own work. Adjust the
wording when the rule's decisions differ from your intent. Include close
contrasts, such as “will take” and “took,” so the rule's boundary is clear.

The editor compiles the specification exactly as written. It warns if `OK`
and at least one finding level are missing; it does not add or rewrite the
output instructions.

Keep specifications and inline examples free of private material. PAW
compilation sends the specification to its compile service with
`public=True` and `ephemeral=False`: compiled programs are public and
persistent. Managed evaluation uses observed inputs locally. Compilation may
happen again after specification or compiler changes and during Automatic
optimization.

## Create and test in the macOS Rule Editor

Open the menu-bar inbox, select a project, and click **+ Rule**. Starting
from **All Projects → + Rule** creates an all-project draft; starting with one
project selected creates a draft scoped to that project. You can also use a
project header's **… → Add Rule…**.

Enter the name, trigger, and specification. Check the displayed Input so the
rule judges the field you intended. **View Python…** shows its source, and
**Command-S** saves a local draft.

Under **Validation cases**, use **+ Add case** to enter an input and expected
level, then click **Run Tests**. These cases live in `tests.json` beside the
rule, separately from the specification. In Evaluation History, choose the
expected level and use **Save as test** to preserve an observed input as a
case. Check that expectation before using the case to judge a revised rule.

Saved validation cases are not added to the PAW specification. Run them
explicitly: saving a case or deploying a rule does not run them. They never
gate deployment or automatic compiler promotion. Results are retained
locally for the exact specification, compiler snapshot, and case content.
Review cases copied from activity before sharing the file.

The CLI uses a different test source: `rap rules test <id>` reads the
`Input:` / `Output:` examples embedded in the specification, not the editor's
`tests.json`. Keep inline examples in the specification instead of duplicating
them in a separate Python `EXAMPLES` list.

## Deploy the draft

Check the intended project coverage and click **Deploy**. RAP validates the
source, prepares its compiler artifact, activates that draft, and applies its
coverage. A failed deployment leaves the previous active revision running.
Saving a draft alone does not replace the deployed rule.

**Compilation…** offers two modes:

- **Automatic (Recommended)** starts with a compatible fast artifact. When a
  compatible finetune compiler is available, a durable background job builds
  and warms its artifact, then promotes it if the deployed behavior is still
  current.
- **Explicit compiler** pins a compiler from PAW's catalog. A missing artifact
  must be built for the current draft. **Build & Run Tests** prepares it and
  runs the requested validation cases without deploying it.

If the compiler needs time, **Deploy When Ready** saves the exact draft,
compiler, and scope for background deployment. An accepted queue closes the
editor. Editing the draft cancels the queued deployment, so an older draft
does not unexpectedly replace your next edit.

After deployment, use the rule on normal agent turns and inspect its
[findings](findings.md). If a judgment is wrong, preserve a useful test case,
refine the specification, and explicitly test and deploy the change.

## Project rules and My Rule Library

Coverage chooses where a shared rule runs: **All Projects** includes current
and future projects, while **Selected Projects** limits it to the projects
you choose. The **Rules for Project** checklist records assignments in
`.codex/rules-as-programs/config.json`.

Project-owned sources live at
`<project>/.codex/rules-as-programs/rules/<id>/rule.py`. Shared sources in
**My Rule Library** live at
`~/.codex/rules-as-programs/rules/<id>/rule.py` by default. Deploying a
standalone project-owned rule moves it into the library; its coverage
determines which projects use it.

A project override with the same ID as an existing library rule cannot
currently Deploy until the source conflict is resolved. Each rule's
16-character ID is its stable identity. Its name is display metadata, so
renaming it does not invalidate compiler artifacts or make earlier findings
stale.

## Authoring the Python source

Every rule is an ordinary decorated Python function. To create the example
manually, save this as
`.codex/rules-as-programs/rules/7km3v9c2xq4t8n1p/rule.py` in your project:

```python
from rules_as_programs import rule

SPEC = """Decide whether the assistant presents the duration of future work as certain.
Return WARNING for a definite duration or completion-time promise without
uncertainty. Return OK for a duration explicitly described as an estimate,
for reports of time already spent, or when no future duration is claimed.

Input: The migration will take exactly two hours.
Output: WARNING

Input: I estimate the migration will take about two hours.
Output: OK

Input: The migration took two hours.
Output: OK

Input: The migration will definitely be finished in 15 minutes.
Output: WARNING

Return ONLY one of: OK, WARNING"""


@rule(
    id="7km3v9c2xq4t8n1p",
    name="Label time estimates",
    trigger="Stop",
    spec=SPEC,
)
def label_time_estimates(ctx):
    """Label time estimates."""
    decision = ctx.paw(SPEC)(ctx.input)
    return ctx.result(decision)
```

`ctx.input` is the exact mapped field. `ctx.paw(SPEC)` supplies the local
judge, and `ctx.result(...)` converts its allowed label into the rule outcome.
Use a different immutable ID for each new rule; the Rule Editor generates
one for you.

From the project root, test the inline examples and enable the rule:

```bash
rap rules test 7km3v9c2xq4t8n1p
rap rules enable 7km3v9c2xq4t8n1p
```

If a case fails, edit the specification and test again. You can pass
`--compiler NAME` to a test run; use `paw.list_compilers()` from the
ProgramAsWeights SDK to discover available names. That selection applies
only to the test run.

`enable` changes assignment; it does not create a deployed revision or pin a
compiler. For a new, undeployed rule, it allows the working source to run in
the project. On macOS, finish in Rule Editor with **Deploy** to use managed
revisions and compiler deployment. Linux and Windows have no managed Deploy
action; their workflow ends at test and enable. Add `--global` only for an
intentionally global assignment.

For deterministic checks, an advanced rule can use ordinary Python instead
of PAW. Such rules run unsandboxed and can access files or the network, so
only install code you trust. The managed deployment pipeline currently
supports PAW-backed rules; install and enable plain-Python rules manually.
See the [reference](reference.md) for source locations, commands, and input
mapping details.
