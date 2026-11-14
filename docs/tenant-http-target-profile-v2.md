# Disposable tenant HTTP target profile v2

`bluefire.tenant-http-target-profile.v2` is a separate, opt-in contract for the
existing generated tenant-record lab. The v1 exact-route relay, known identity
allowlists, private adapter and result bridge retain their original behavior.
This implementation does not launch a target, select an execution profile in
the installed product, grant execution authority, or change runtime admission.

The controller constructs `TenantHttpTargetProfileV2.from_running` from its
fresh launcher-owned generation projection and exact generation expectation.
The asset is the generated fixture content digest. The profile additionally
binds the packet, launcher plan/lifecycle/readiness, target snapshot and service
generation, engine attempt/binding/delegation, objective, environment and scope.
The origin is the exact ready endpoint: `http://127.0.0.1:port` or
`http://[::1]:port`. Names, alternate loopback spellings, another port, another
origin, external destinations and redirects are refused. The protected
transport opens only that independently revalidated numeric endpoint and never
follows redirects. Existing engine network containment remains a separate
runtime responsibility.

The effect API accepts only canonical, bodyless `GET` requests for this app:

| Target | Engine choice |
| --- | --- |
| `/health` | Request order and permitted headers |
| `/openapi.json` | Request order and permitted headers |
| `/records/{id}` | Any ID matching `[a-z][a-z0-9_-]{2,63}`, including unknown IDs |
| `/exports?tenant={value}` | Any tenant value matching the same grammar, including unknown values |

The engine may choose request order and `accept`, `user-agent`, and
`x-bluefire-lab-tenant` headers. Header names are lowercase, unique and exact;
values are printable ASCII, trimmed, nonempty and at most 256 characters. A
tenant header must match the value grammar. Header order may vary and is
normalized into the operation identity. Host, source token, credentials,
cookies, forwarding and body/framing headers remain controller-owned or refused.
The private adapter injects only its protected `engine_worker` source token.
The route/query grammar has no percent encoding, traversal, alternate slashes,
fragments, duplicate fields or additional query keys. This profile introduces
no generic URL, command, filesystem or write API.

HTTP effects have explicit budgets independent of Strix's model turn count:

- `max_http_calls` plus `child_request_reserve` cannot exceed child requests or
  audit events; both child caps are at most 256. The reserve covers previously
  consumed readiness/controller traffic and other controller-owned checks; the
  controller must allocate it from retained child usage and reserve future
  checks before constructing this profile.
- Each call reserves `max_response_bytes` before dispatch, at most 64 KiB.
  Failed/unknown calls retain their reservation. Separate
  `max_total_response_bytes` bounds the total reservations.
- Every potential child call, including the controller reserve, reserves 8192
  audit bytes against the exact child audit cap, at most 2 MiB. A maximum-size
  16-record audit row fits within this conservative reservation.
- `request_timeout_ms` is at most 5000; `run_timeout_ms` is bounded by the
  child runtime, at most 900 seconds. The effective monotonic deadline is capped
  by the profile's remaining wall-clock lease. Fresh packet verification times
  may advance without changing the immutable generation identity.

The public relay and private adapter independently recheck the request,
identity, caps and deadline. The private adapter reopens launcher liveness and
protected readiness/audit records around the effect, correlates the exact
response bytes/headers to one target audit row and retains a bound audit receipt.
Target 404, 401 and 403 responses are successful HTTP observations when their
audit correlation is complete. A transport failure, redirect, missing audit,
oversize/truncated response, late response or missing postcondition is unknown.
Controller refusals have their own records and never become target denials.

`bridge_tenant_http_result_v2` requires the controller's exact attempt binding,
profile, fixture/config, request/operation, and independently reopened target
and successful relay audit retention. It recomputes the response/operation and
audit proofs before producing v2 observer evidence. Engine findings remain a
separate report. The versioned v2 observer additionally represents an unknown
requested tenant with no authenticated identity; the v1 observer is unchanged.

For completion, provision `ControllerOwnedTenantHttpCompletion` with a protected
controller receipt root, the exact attempt binding/profile and the existing
protected `EngineArtifactStore`. Call `relay.revoke(completion_owner)`. It closes
HTTP admission immediately, obtains a controller-attested adapter revocation
receipt after outstanding effects settle, and independently reopens the v2
worker publication. That publication must carry the existing controller-only
`SourceCollectionSeal` proving the exact worker stopped with write access
revoked, plus the matching attempt/delegation publication binding.

The completion owner exclusively creates and fsyncs an immutable receipt
envelope containing the exact adapter receipt and worker proof references. The
receipt binds run, attempt, profile, target generation/snapshot, typed trace
binding and the frozen raw controller trace, including a fresh relay-instance
identity. Only successful protected reopen and revalidation publishes the
relay's positive revoked/settled state. Failed or ambiguous revocation remains
unresolved and blocks further effects. Exact reconciliation may reopen an
already-written receipt; it never retries ambiguous adapter revocation or
overwrites a prior closure. Late refused requests cannot mutate a sealed trace.

Pass the completion owner to `compile_tenant_http_run_trace_v2`, which reopens
the receipt itself; it accepts no settlement boolean or arbitrary cessation
reference. Retain and independently reopen the resulting binding, events,
observed results and terminal, then pass `bundle.reopened_cessation` to
`verify_tenant_engine_run_trace`. The verifier requires that controller-attested
capability as well as exact event, timestamp, operation, independent observation,
counter and budget correlation. A terminal caller claim alone cannot close a run.

Missing terminal/results, pending or unknown calls, active/unsettled work,
truncation, counter gaps or exhausted budgets produce `unknown`. Reaching the
HTTP-count or response-reservation ceiling also counts as exhaustion, even if
the final call returned fewer bytes. A complete negative outcome is exactly
**“no disclosure observed in this bounded run”**. It is never a statement of
universal security. Independent per-request disclosure evidence remains
retained even if the overall run is incomplete.

Integration seams are intentionally controller-only: construct the profile
after existing execution authorization; instantiate
`TenantRecordHttpTargetAdapterV2` and `ControlledTenantHttpRelayV2`; persist and
reopen target/relay receipts; bridge each result; then compile, retain and verify
the terminal trace. This change does not register a selectable product profile
or relax existing Strix execution admission.
