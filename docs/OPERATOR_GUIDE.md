# Operator guide

An **experiment** is a saved test procedure. **Build** edits a working copy; a **run** records
one attempt using a particular version and configuration. Editing the working copy does not
change earlier runs. Start with [Installation](INSTALLATION.md), then use the same run directory
when reopening the application.

## 1. Choose and edit an experiment

Open **Experiments**, search for a procedure, and read its purpose and requirements. For a
first Simulate walkthrough, choose **Endpoint Lab — Redacted Benign Collection**. Use
**Duplicate** to make a working copy, then open **Build** and give it a useful experiment name.

Inspect the steps on the canvas or switch to **Steps**. Select a step to inspect its method,
parameters, required inputs, and outputs. **Show all branches** reveals alternate routes;
the run review always includes the complete procedure. Hiding a branch does not exclude it
from execution.

Choose **Validate**, resolve any reported errors, then **Save version**. Overview distinguishes
unsaved changes from a working copy that matches its saved version. Save the procedure before
opening it from another browser connected to the same workspace.

## 2. Review and run Simulate

Choose **Review run**, select **Simulate**, set AI autonomy to **Off**, and choose the
`sandbox-simulate.v1` runner profile. A profile contains permissions and limits; it is not the
lab itself. Simulate does not start a runner or perform external behavior effects.

Choose **Run preflight**. Check the resolved steps, profile, scope, and cleanup. When the plan
is ready, choose **Submit Simulate job** and follow its progress to the saved result. A job
waiting for input or cancellation is not a completed run.

In **Runs**, open the result by its display name and creation time. **Rename run** saves a
presentation name while leaving its immutable ID and recorded evidence intact. The ID and
copy action remain available in the technical details. Search accepts a name or run ID.

## 3. Read the result before drawing a conclusion

The result separates the objective, independently observed activity, cleanup, and the path
taken. A synthetic success only describes the simulated path. Zero independent observations
does not demonstrate a real effect, detection miss, or successful prevention. Simulate cleanup
is **Not attempted** because it performs no lab effects.

For Execute, distinguish runner-reported results from independent observations and detector
matches. Investigate missing telemetry and incomplete cleanup before replaying. Use
**Download report** for readable Markdown or **Download run bundle** for the saved record;
saved detector revisions and their evaluations are separate resources.

## 4. Execute only in the reviewed environment

Prepare a disposable environment you are authorized to test; the
[prepared Linux lab guide](PREPARED_LINUX_LAB.md) describes the supported isolated setup.
In Runs, select **Execute** and follow the actual runner readiness state. Preparing or starting
the runner does not approve an experiment.

Select the appropriate runner profile, exact scope, and collectors, then run preflight. Review
the full procedure, allowed effects, limits, observations, and cleanup before creating the
approval-gated job. Approve that particular request only when its scope is correct. A changed
or expired request needs a fresh review; reopening a result never grants approval or reruns it.

## 5. Develop and test a detection from the result

Choose **Open Detection Lab** from a result to retain its source run. Inspect the available
independent observations before creating a rule. A linked candidate inside an immutable run
is separate from a saved detection: use **Save hypothesis from run** when that action is
available. For manual authoring, open **New rule** and **Save strict hypothesis**. The separate
**Create from run evidence** path offers **Draft rule with Assistant** and requires eligible
independent observations and an available configured provider. The AI-Off synthetic walkthrough
alone does not supply those prerequisites.

For SQLite or Sigma, validate the source using the installed backend, then open
**Run evaluations**. Select an existing source run by name, enter the experiment question and
case role, and choose **Evaluate full observed run**. Inspect the evaluated and matched records
and any missing evidence. Repeat against separate relevant attack, benign, and replay inputs;
choosing a role does not create those inputs or determine the outcome.

**Validate and save new revision** preserves the selected rule and its previous evaluations.
Local rule and evaluation inputs can be retained across navigation and reload in the same
browser tab; they are not saved rule revisions. **Export local inputs** preserves the rule's
local draft fields; use **Export evaluation inputs** separately for the question, source run,
role, and related revision. See [Detection Lab](DETECTION_LAB.md) for backend prerequisites and
limitations.
YARA evaluates supplied file content; metadata alone cannot establish a file-content match.

## 6. Replay and compare a supported change

Choose **Replay & compare** from a result. Review the selected source and the exact or declared
variant before submitting a replay. Execute replay still needs current readiness and approval.
Compare existing runs by their names, modes, and creation times; a comparison does not run them.

A defense-change note records context; it does not deploy a control. The supported receiver
control test has distinct baseline, redaction-required, and prior-policy-restored phases, each
with its own preparation, review, progress, and result. Restoring that receiver policy does not
reset the lab. See [Replay and compare](REPLAY_COMPARE.md) for supported changes and lineage.
Compare measured objective, observations, detections, and cleanup without assuming a difference
proves causality or that an external security product prevented an action.

## Assistance and recovery

**Plan with Assistant** can propose a graph for review. The contextual **Assistant** uses the
selected supported objects; check its proposed changes and follow links to the actual results.
Provider availability, runner readiness, and browser connection are separate states. Off makes
no model calls; the deterministic offline provider is not a live model. Assist and bounded Auto
depend on the current operation, and neither bypasses Execute approval. See
[graph assistance](contextual-graph-assistance.md) and [AI Planner](AI_PLANNER.md).

After a request failure or lost connection, reopen the retained job or result and check its
actual status before submitting again. **Stop requested** does not mean effects have stopped or
cleanup is complete. Resolve interrupted work through its recovery controls; do not create a
replacement run to guess whether the first attempt finished.

Closing the browser tab does not stop the service. Settle active work and inspect cleanup before
stopping the launcher or upgrading. Reopen with the same run directory to retain saved work.
Use [Troubleshooting](TROUBLESHOOTING.md) for readiness failures and
[Responsible use](RESPONSIBLE_USE.md) for the authorization boundary.
