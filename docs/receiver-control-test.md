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

## Prepare the experiment

Open BlueFire in the prepared disposable Linux lab and complete its normal native
runner setup. Simulate cannot start this receiver, and the Windows host cannot run
the control test directly.

In **Build**, save an experiment that creates public synthetic records, stages
them as JSONL, hands the bundle to the registered peer method, and cleans up its
workspace. Exactly one staging step must feed the single peer handoff. Both steps
must have a fixed method, without alternate branches on those steps. Other graph
validation and authorization requirements still apply.

To exercise the expected prevention difference, the staged records must retain
some synthetic test values. Fully redacted records can legitimately pass both
policies; that does not establish the intended prevention difference. Do not use
personal files or real credentials.

Select the saved version in Compare. Choose Execute, the enrolled lab profile and
the exact scopes required by the graph. The page checks eligibility and lab
readiness before the test can be saved. Runtime AI stays Off so that the phases
use the reviewed experiment without model-driven changes.

## Run the three phases

1. **Save control test** retains the selected experiment and run settings.
2. **Prepare baseline receiver** starts a short-lived, memory-only receiver in
   the lab. Review its policy, complete run plan, scope and cleanup.
3. **Accept and continue to run approval** saves that review. Open the resulting
   run and give its fresh Execute approval through the ordinary Runs controls.
4. Follow run progress, then use **Return to receiver control test**. Inspect the
   receiver observation and run cleanup before continuing.
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
