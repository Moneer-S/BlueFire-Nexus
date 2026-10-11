# S3 access review

The cloud access workspace keeps one scoped bucket-access objective, its reviews,
baseline and fresh observations, and unresolved recovery in the existing jobs and
run evidence system. It is available under **More tools > S3 access**. A missing or
changed enrollment is shown as unavailable, while previously saved evidence
remains readable.

Setup and execution use the same active managed profile selection. The installed
native policy must match its exact execution limits, dedicated S3 permissions,
approval requirement and supported local target scope, as well as the
authenticated runner and sandbox. A same-ID profile edit does not make an older
host policy current. Setup reports that mismatch without changing the host.
Configuration drafts likewise require exact current profile limits, not merely
lower limits. Changing those limits requires reviewing and installing the updated
configuration before new execution.

Execution rechecks the active profile version and exact discovered host bindings
after retaining its original task checkpoint. Drift at that point refuses
dispatch without removing the checkpoint or refunding reservations. Recovery
continues to validate the historical task, not a newly active profile.

## Reviewed stages

1. Inspect the enrolled baseline policy without changing it.
2. Establish probe-reader and legitimate-reader baseline reads against the exact
   generated primary and health objects.
3. Review the structural policy change and finite budget before applying it.
4. Start fresh probe and legitimate-reader checks, then compare their retained
   observations with the baseline. A denied probe alone does not establish that
   legitimate activity still works.
5. When a write outcome is uncertain, inspect the current policy against the
   original before/after documents. Drift stays explicit rather than being
   treated as a successful change or restore.
6. Separately review restoration of the exact original policy. A successful
   restore includes policy readback. An uncertain restore can use its remaining
   bounded reconciliation allowance; it is not automatically retried.

Apply is unavailable unless the remaining scope can cover the change, required
fresh checks, and bounded recovery. Later policy inspections cannot consume the
capacity still needed for those checks and restoration. The review shows the
current reservation separately from this unspent follow-up allowance. Previous
reservations are never refunded. A known pre-dispatch read refusal may permit a
newly reviewed read stage with new identities, while unknown cleanup blocks new
work.

## Durable evidence and recovery

Each operation retains the original request bindings and immutable run results.
Reload restores that history without executing a business action. A browser-side
uncertain submission offers saved-status inspection or an exact idempotent retry;
it does not automatically resubmit. Stop remains available even if the browser
cannot retain its local pending marker.

Recover saved results retains already sealed run records or adopts an authenticated,
already finalized original task result into the same pristine run. The original
request, sealed manifest, profile and transport identity must match the checkpoint
saved before dispatch. A known service-startup interruption is preserved in the
event history; partial publication or damaged evidence is refused without rewriting.
Running, absent or unavailable original tasks and unknown cleanup remain unresolved.
Recovery does not replay execution, obtain new credentials or refresh expired
authority. Absence of a result is not evidence that nothing happened.

## Authority and proof limits

The configured runtime must independently admit the exact enrolled scope,
protected launch context, request, review and remaining limits. Browser JSON,
saved approvals and their digests are not credentials or standalone execution
authority. This workspace does not enroll an AWS account, invent a credential
source, or widen the supported native action set.

Product tests use an explicitly synthetic executor. Runner-reported read and
policy observations remain distinct from independently collected cloud audit.
The workspace reports audit as **not collected** and independent observations as
**none**. The original workflow retains generated resources. The v2 fixture
workflow separately records whether its exact objects are not prepared, retained,
in need of reconciliation, or removed. Fixture cleanup retains the policy state
accepted at its review; it does not restore the original policy automatically.
Synthetic and runner-reported fixture outcomes retain those provenance labels.
They do not establish live defensive effectiveness, independent deletion proof,
or separate-identity runtime isolation.
