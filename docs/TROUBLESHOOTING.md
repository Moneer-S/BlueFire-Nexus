# Troubleshooting

## Execute preflight is unavailable

Open Runners and inspect inert status. Bootstrap a matching packaged runner, start it, and verify
active enrollment, authenticated transport, manifest digest, inventory parity, exact profile,
scope, policy, collector readiness, budgets, and cleanup. Do not broaden scope or disable a
control just to make preflight pass.

## The browser cannot open BlueFire

Relaunch `bluefire ui` and open the exact one-use loopback URL it prints. Do not copy the fragment
capability into logs. A bare URL works only after that browser exchanged the fragment for its
HttpOnly local session. Proxying or remotely publishing the listener is unsupported.

## Observed evidence is absent

Runner receipts prove dispatch, not independent observation. Enable a supported collector,
review its health and environment prerequisites, and repeat the authorized run. Preserve an
explicit evidence gap when the observer cannot establish a field.

## A detection does not match

Parsing, conversion, malicious-fixture execution, observed-evidence evaluation, benign
evaluation, and deployment are different states. Inspect backend versions, field mapping,
unsupported fields, false-positive notes, and the exact evidence provenance before tuning.

## Replay checkpoint is refused

Execute node restart requires an intact content-addressed checkpoint bound to the source bundle,
scenario, plan, profile, scope, runner identity and inventory, catalog, cleanup state, and material
file hashes. Corruption or incompatible authority is intentionally refused. Create a fresh run if
the original disposable lab can no longer recreate and verify the prefix.

## Cleanup or cancellation fails

Keep the disposable sandbox intact. Reconcile the durable intent/commit journal and use the
registered cleanup path; never delete an arbitrary caller path through the runner. Stop the local
runner only after the process-tree cancellation and recovery status are terminal.
