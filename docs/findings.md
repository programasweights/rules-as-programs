# Working with findings

Open a finding to see what the rule checked, decide whether it needs
attention, and save useful examples for improving the rule.

This guide describes the full macOS menu-bar interface. Linux and Windows have
a reduced tray menu; use the logs and CLI described in the
[reference](reference.md) for details there. For initial setup, see
[Getting started](getting-started.md).

## Read the inbox

The PAW menu-bar item shows a severity-colored count of actionable finding
groups. Open it to select a project and switch between **Needs Review** and
**Reviewed**. Repeated occurrences can appear together, so the number of groups
is not the number of individual events.

Monitoring problems appear separately from findings. A rule that cannot load,
an unavailable compiler, or an inference failure needs operational attention;
it is not an `OK` judgment. Use the available Retry, Test, or Details action to
inspect the problem. A quiet inbox alone does not establish that monitoring is
working.

## Inspect the exact input

Click a finding to open its separate Inspector. The main input view shows the
exact mapped string recorded for that evaluation. For a managed rule, that is
the input passed to PAW. For example, a `Stop` rule normally receives the last
assistant response; a `PreToolUse` rule receives the serialized `tool_input`
field. The rule's trigger and any advanced input-pointer override determine
this selection.

**Session Activity** shows surrounding recorded events for your investigation.
Those events are not silently added to a Basic rule's input. If the context
explains why a finding seems wrong, check whether the rule's selected field
can support the judgment you want. A rule cannot reliably judge evidence that
is absent from its input.

The Inspector's **…** menu provides **Evaluation Details**, **Evaluation
History…**, and copy actions for the audit record and surrounding context.
Evaluation History also includes invocations that returned `OK`, input
failures, and runtime errors; the findings inbox contains only findings.

Prose wraps by default; structured commands, code, and JSON remain unwrapped.
Use **… → Line Wrapping** to choose Auto, Always, or Never. This changes the
display, not the copied raw input.

## Review an occurrence

Reviewing means you have handled an observation. It preserves the recorded
history and does not change the rule or the agent's work.

- A single-occurrence row has a direct review control.
- Expand a group with multiple occurrences to inspect and review each event.
  **Review This Occurrence** affects that event only.
- **Review All N Occurrences…** is a separate action with confirmation. It
  moves the currently open occurrences in that group to Reviewed; later
  occurrences can still appear.
- The review menu also offers **False Positive** and **Acceptable Risk** as
  reasons for reviewing an occurrence.

Use the Reviewed view to revisit past findings. Removing a rule moves its
orphaned open findings there with the reason **Rule deleted**, retaining the
recorded source and audit history.

## Mute, disable, or pause

**Mute This Rule in [Project]…** hides future findings from that rule in that
project. The rule continues evaluating and logging. The current open finding
remains until reviewed, and muted findings remain available in history. Mutes
are personal local settings, separate from the project's shared rule
assignments.

Disabling a rule removes its active assignment for the selected scope. Pausing
monitoring stops evaluation more broadly. Neither muting nor pausing is a way
to stop event collection: paused monitoring still records incoming events.
See [Data and privacy](reference.md#data-and-privacy) before using RAP with
sensitive inputs.

## Revisit an older revision

After a rule's behavior changes, its previous findings remain under the
matching project and rule as **Older revision · Needs recheck**. They remain
individually reviewable but do not contribute to the current severity badge.
The historical finding still describes the input and rule revision used at
the time; deploying a new revision does not rerun or rewrite that observation.

A rename only changes display metadata. It does not create a new behavior
revision or make findings older.

## Turn a finding into a useful test

Use a concrete observation to improve a rule:

1. Inspect the finding's exact input and recorded evaluation. Decide what
   result you expect for that input.
2. Choose **Edit Rule…**. The Rule Editor retains the finding as tuning
   context and warns if it came from an older revision.
3. Use **Copy Input**, add a Validation Case with **+ Add case**, and paste the
   exact input. Set its expected result and, optionally, a note. Include a
   contrasting case so that broadening the rule does not hide valid findings.
4. Adjust the specification or trigger if needed. Save the draft with
   `Command-S`, then click **Run Tests** to evaluate the saved cases against
   the current draft and selected compiler. If an explicit compiler needs a
   build first, the action is **Build & Run Tests**.
5. Inspect the results and click **Deploy** when the draft expresses the
   behavior you want. Deployment prepares and activates the exact draft and
   its coverage; a failed deployment leaves the previous active revision in
   place.

Validation Cases live in `tests.json` beside the rule and are not added to its
PAW specification. Results are stored locally by case content, exact spec, and
compiler snapshot. Tests run only when requested: passing them is not a
deployment gate, and deploying does not automatically rerun them. Inspect
copied inputs for private information before sharing a case file.

The CLI's `rap rules test <id>` is different: it runs examples embedded in the
rule's specification, not `tests.json`. See [Writing rules](writing-rules.md)
for the source format and both testing workflows.

## Understand the purple question mark

A purple **?** indicates that an agent likely needs a reply. It can come from
an explicit Codex `request_user_input` call or the bundled local fuzzy rule
that checks for blocking questions. It is an attention signal, separate from
rule violations, and does not represent every native approval state.

Submit the next prompt in that conversation to clear it, or choose **Mark no
reply needed** when no response is necessary. This action clears RAP's
attention indicator; it does not answer the agent's question.
