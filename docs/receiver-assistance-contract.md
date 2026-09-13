# Receiver assistance lifecycle

The existing ExperimentAssistance and RunJobController coordinate the native receiver comparison. The adapter reserves the existing `receiver.defense` owner and analysis children; it does not itself launch a receiver, execute a run, change policy or grant approval. Native phase controls remain explicit. See [the operator flow](receiver-control-test.md) for the manual and Assistant entry points.

`POST /api/v1/assistance/receiver-context` takes `{selection}`. A `receiver_scenario` selection contains an immutable `saved_scenario` reference and the existing native `run_intent`. The intent must remain Execute with runtime AI Off and no runtime provider. The context reports ineligible host, graph or native settings before model admission. Its `receiver_context` excludes volatile readiness; Compare checks current readiness when the operator prepares a receiver.

A `receiver_test` selection contains `receiver_job_id` and `receiver_context_digest`. The server verifies the admitted owner, finalized bundles, exact task/session/policy receipts and a nonempty ordered phase prefix. The model receives only bounded decision/count/cleanup facts and exact supplied references. Historical inspection freezes those facts; later phases append without rewriting the earlier interpretation.

The existing turn submission, GET, continuation and cancellation APIs are unchanged. Off makes no provider request or child. Assist and Auto may select exactly one supplied receiver capability. Auto is coordination and analysis authority only: every Prepare receiver action, native review and fresh Execute approval remains explicit.

For `receiver.test_and_compare`, the Assistant reserves one deterministic `receiver.defense` child. A completed owner job means admission completed, not that the three phases ran. The parent stays active across baseline reviewed-records, protected redacted-only and restored reviewed-records. Stop is checked through the retained Assistant ancestor at native preparation, review, publication and dispatch. Cancelling an owned native operation stops the creating turn, including its analysis jobs.

For `receiver.inspect_and_plan_next`, the Assistant owns only a `receiver.defense.inspect` child for its selected prefix. It does not adopt or cancel the selected receiver owner. Completing that one analysis completes this turn, while the native comparison may remain active. Model suggestions are advisory; the current native next action always determines whether a phase can be prepared.

After a creating owner's phase receipt is retained, the existing native completion hook reserves a deterministic prefix analysis through the same controller. No scheduler or second workflow engine is introduced. GET verifies and displays receipts only. If the process stops before this handoff, reopening exposes recovery through the existing idempotent `POST /continue`. A failed or interrupted analysis is never automatically repeated: explicit recovery permits at most three analysis attempts per prefix and nine per turn. Analysis recovery never repeats native effects or renews a receiver session. Without a running service callback or an explicit continuation, unattended recovery remains pending.

Analysis requests, model output and progress use the existing secret-safe persistence boundary. The server rechecks exact provider configuration and source prefix before the request and under the configuration lock before result retention; the writer transaction checks Stop and the reserved lineage. A lost submission response resolves the same UUID. A retained interpretation survives callback interruption without another request. Native run results and cleanup remain independently authoritative if analysis fails.

`turn.receiver_test` exposes owner identity/context digest, lifecycle ownership, native phases/current action and retained analysis jobs. `receiver_phase` result refs bind actual run IDs and native result digests; `receiver_inspection` refs bind exact analysis jobs and prefix digests. A successful model interpretation cannot turn transport failure or missing receiver evidence into prevention. Restoration means a fresh baseline-policy receiver; it is not host rollback, deployment or independent held-out defense validation.

Portable tests use provider and receiver/native protocol doubles. They establish lifecycle and binding behavior, not installed process isolation or model quality.

## Provider purposes and frontend recovery

Receiver coordination uses `bluefire_experiment_assistance`; each retained prefix
interpretation uses `bluefire_receiver_defense_inspection`. Both use the selected
provider's existing Responses or Chat Completions dialect, exact enrolled schema,
data policy and request budget. Supporting a purpose in the product does not
establish that an arbitrary model or endpoint satisfies that contract. Neither
purpose grants native Prepare or Execute authority.

The workbench retains the exact turn request before POST and restores it by GET
after reload. A lost response or early GET404 does not create a new submission
identity. Native receiver requests have their own retained receipts. Failed
analysis recovery is an explicit **Recover evidence analysis** action. A saved
owner backlink is accepted only when it matches the creating turn's reciprocal
reservation; an existing-test analysis never takes ownership of that test.

The progress view labels model interpretation with its actual provider and keeps
native acceptance, prevention, missing evidence and cleanup separate. Earlier
analyses remain bound to their captured phase prefix even after later phases or
cleanup updates. **Open control test and phase comparison** returns to the native
results. Portable serialized-response checks and UI state tests verify these
bindings and recovery paths; they are not installed A/B/A or live-provider proof.
