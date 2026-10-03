# Test a receiver redaction policy

Use **Compare → Test a lab receiver control** to measure a real, bounded control
inside an owned disposable Linux lab. The test runs the same saved experiment
against three separately prepared receiver sessions:

| Phase | Receiver policy | Question |
| --- | --- | --- |
| Baseline | Accept reviewed synthetic records | Does the handoff reach the receiver? |
| Redaction required | Accept only fully redacted records | Does requiring redaction prevent that same handoff? |
| Prior policy restored | Accept reviewed synthetic records again | Does a fresh session with the original policy restore acceptance? |

The baseline is deliberately permissive. This is an authenticated handoff to a
separate process on literal loopback. It is not remote lateral movement, a newly
discovered vulnerability, or proof of general prevention coverage. Receiver
prevention and detection results are evaluated separately.

The default **Compare and restore prior policy** workflow preserves these three
phases. **Retain redaction and verify legitimate use** selects the separate
workflow described below; existing saved comparisons are not converted.

## Prepare the experiment

Open BlueFire in the prepared disposable Linux lab and complete its normal native
runner setup. Simulate cannot start this receiver, and the Windows host cannot run
the control test directly.

In **Build**, save an experiment that creates public synthetic records, stages
them as JSONL, hands the bundle to the registered peer method, and cleans up its
workspace. Exactly one staging step must feed the single peer handoff. Both steps
must have fixed methods with no permitted alternative behaviors. Keep explicit
cleanup routes from the handoff for success, partial, blocked and failed outcomes.
Other graph validation and authorization requirements still apply.

To exercise the expected prevention difference, the staged records must retain
some synthetic test values. Fully redacted records can legitimately pass both
policies; that does not establish the intended prevention difference. Do not use
personal files or real credentials.

Select the saved version in Compare. **Inspect the selected saved experiment** opens
that exact version in a read-only Builder view; opening it does not replace your
working draft. In **Environment and run settings**, choose Execute and the
enrolled lab profile. **Target scope** must explicitly include
`sandbox.workspace` and `network.loopback`; the selected profile must permit both.
Include any other scopes required by the graph. Missing required scopes are
refused before receiver preparation; BlueFire does not add them for you.
The page checks eligibility and lab
readiness before the test can be saved. Runtime AI stays Off so that the phases
use the reviewed experiment without model-driven changes.

## Run the three phases

1. **Save control test** retains the selected experiment and run settings.
2. **Prepare baseline receiver** starts a short-lived, memory-only receiver in
   the lab. Review its policy, complete run plan, scope and cleanup.
3. **Accept and review run approval** saves that review. Give the resulting run
   its fresh Execute approval through the ordinary run controls shown inline.
4. Follow run progress. Inspect the receiver observation and run cleanup before
   continuing.
5. Prepare the protected receiver, review the changed policy and replay, and
   approve the resulting run. The replay is bound to the staged bytes recorded
   independently in the baseline.
6. Prepare the restored receiver and repeat the review and approval. Restoration
   creates a fresh session with the original policy; it does not revive an old
   process or reset the entire VM.

Each receiver accepts at most one policy decision. A receiver can expire during
review. BlueFire must verify its cleanup before allowing an explicit replacement,
which receives its own review and approval. A phase whose execution began or is
uncertain cannot simply be retried as a new run.

## Retain redaction and verify legitimate use

Choose **Retain redaction and verify legitimate use** before saving a new test.
The selected graph must stage records produced by its reviewed fixture-transform
and discovery chain, with **redact_values** false for the baseline. The retained
workflow uses these phases:

| Phase | Receiver policy | Fresh operation |
| --- | --- | --- |
| Baseline | Accept reviewed records | Execute the saved experiment and observe accepted retained values. |
| Redaction required | Require redacted records | Execute the original chain again; the authenticated staged bytes must match the baseline. |
| Legitimate redacted use | Require redacted records | Execute a full replay with only the bound transform's redaction parameter enabled. |

The final phase must independently observe acceptance of the same nonzero number
of generated records, all explicitly redacted. Its bytes deliberately differ from
the baseline. An empty input, a smaller record set, a missing observation, or
incomplete cleanup cannot establish preserved legitimate use. This is a controlled
variation of the same generated data, not unseen evaluation data.

After the phases settle, BlueFire retains the desired redaction policy for this
saved control test, selected experiment, exact profile, and scope. Each receiver still shuts down.
**Receiver stopped** and **Policy retained** describe different facts: this is a
saved lab configuration used by this control test's linked fresh retests, not a persistent host
service or a claim that an external destination remains protected.

Use the retained policy's retest control to start a separate test containing fresh
protected and legitimate-use runs. The authenticated original baseline remains a
comparison reference; it is not reported as newly executed. Both new sessions use
the retained redaction policy and each run needs fresh review and Execute approval.
The selection survives a service restart without adopting an old process or
renewing an expired approval.

Independently created tests, including a new test of the same saved experiment,
do not inherit this policy. Their explicitly selected workflow can prepare its
own permissive baseline. This control is not a global override of scenario execution.

An explicit rollback returns this saved control test's desired policy to reviewed-records
acceptance and records who made that decision. Every linked test and its cleanup
must settle before rollback. Earlier observations remain in history. Cleanup,
Stop, browser navigation, and replay never perform this rollback implicitly.
The original restoration workflow and its Assistant integration are unchanged;
retained-policy tests currently use explicit native controls with runtime AI Off.

## Coordinate with Assistant, or analyse an existing test

Manual **Save control test** needs no model. To coordinate a new test instead,
keep the same selected version and environment settings and choose **Coordinate
with Assistant**. Select an **Assistant mode** and **Assistant provider**, describe
the comparison, then choose **Start work**. This retains the exact saved version,
scope and run settings; it does not replace the current Builder draft.

Both **Assist** and the supported **Auto** mode can coordinate this bounded test
and interpret verified phase evidence. Neither mode prepares a receiver or grants
Execute approval. Follow the native links and explicitly prepare, review and
approve each phase as above. Runtime AI remains Off throughout this control test.
Assistant's submitted mode and provider stay bound to that operation; changing
new-request settings does not cancel or change saved work.

After each phase, Assistant can explain the accumulated verified observations.
Its **Model interpretation** and suggested next step are separate from the native
receiver decision, transport outcome and cleanup. **Verified facts supplied to
this analysis** shows the supporting references and counts. Admission of the
control-test owner is not completion of the three-phase comparison; an analysis
failure does not erase a native result or establish prevention.

For a manually created test with verified phase evidence, choose **Analyse with
Assistant**. This analyses the selected evidence available at that time; it does
not adopt the test or run a further phase. **Stop this operation** stops only that
analysis. For a test created through Assistant, **Open saved Assistant work**
returns to its coordinating operation: stopping that operation also requests
cancellation of its owned native work. In either case, closing the panel is not
Stop, and requested Stop is not verified cleanup.

**Recover evidence analysis** explicitly recovers a failed or interrupted analysis
or missing handoff. It reuses the recorded native phases; it does not repeat a run
or renew a receiver. Reopening or polling saved work makes no model request.
**Off** prevents new model submissions; use the saved operation's Stop control to
cancel work already submitted under Assist or Auto.

## Read the outcome and recover work

The results distinguish receiver acceptance, prevention by the receiver, and
insufficient evidence. Missing authenticated receiver evidence cannot become a
prevention pass. Inspect each run for action outcomes and observations; inspect
phase history for exact policy, session, artifact and cleanup records.

**Compare baseline and protected run** opens the normal comparison workspace.
**Check restoration against baseline** separately compares the restored phase.
**Download control report** exports the measured phase outcomes, supporting run
and receiver records, cleanup and limitations. An unfinished test exports its
current state without claiming that the full comparison succeeded.

Saved tests are listed in the control workspace, with unfinished work before
settled history and pagination for older records. Returning to a test reads its
saved state. It does not prepare a receiver, renew an expired session, repeat a
run or issue a model request.

If a response is lost, keep the retained request and check its status or retry
that exact request. Browser storage must succeed before a request can be sent.
If the experiment changes before the test is admitted, the original request is
retained as refused and cannot prepare a receiver. Set up a separate test to
review the current experiment; retrying the old request never substitutes a new
version or grants authority over changed settings.
**Stop control test** requests cancellation and cleanup; requested cancellation
is not confirmation that the receiver and run have stopped. Uncertain cleanup
must be resolved before the test is considered safely stopped.
**Cancel** on a phase's run also stops the entire control test, including when its
Execute approval has expired. That test and its unfinished phase cannot resume.
After the service confirms cleanup, choose **Set up another control test** to
start a separate test. Earlier phase results remain in the original test's
history; no approval is renewed automatically.

## What this guide establishes

These are implemented operator controls backed by portable lifecycle, binding and
provider-contract tests. Those tests use controlled provider and native protocol
doubles. They do not establish a completed installed baseline/protected/restored
journey or a live provider interpretation. Report those separately from actual
retained runs and model receipts; no such proof is claimed by this guide.
