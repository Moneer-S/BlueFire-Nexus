# Managed runner execution deadlines

The normal service sizes a newly started managed host from the largest budget
among its current Execute profiles, the same profile set used for enrollment.
The outer native process deadline is that budget plus five seconds for completion.
Each sealed action still receives only its remaining approved run budget; the
profile's effect, step, artifact, byte, and total time limits are unchanged.

Authenticated health reports the running host's actual execution deadline.
Execution clients use that deadline with the existing publication/response
margins, including after the UI service restarts. Control clients retain short
readiness deadlines, and the host's ingress socket deadline remains ten seconds.
Worker shutdown retains its separate native execution/publication bound.
Status for a selected profile checks that profile's current budget; general
runner status checks the same maximum Execute budget used when starting a host.

A profile that outgrows a running host is unavailable for execution. After
current work completes, explicitly stop and start the runner in Runners. The
service never replaces a live host or renews an approval to resolve this mismatch.
Older hosts that do not report their deadline likewise need an explicit restart
before automatic profile sizing can be verified.

An explicitly supplied `ManagedRunnerLifecycle(runner_timeout_seconds=...)`
remains a fixed outer override, including lower test/operator limits; it may end
an action before the full profile budget. A direct lifecycle caller that supplies
no profile budget retains the legacy 35-second default. The normal product
service always supplies current profile budgets.

The existing 86,400-second outer cap remains unchanged. Automatic sizing refuses
profile budgets above 86,395 seconds because the completion margin cannot fit.
It does not silently clamp an accepted action's budget or expand that cap.
