# Strix Test-provider runtime and tool conformance

`ControllerOwnedTestProviderRuntime` owns an attempt-local controller gateway,
private deterministic Test-provider listener, lifecycle-locked generation source,
numeric-loopback protected transport, and bounded hash-only audit adapters. It
never loads environment credentials or instantiates a live inference client.
The private fixture bearer is generated in memory, differs from the worker's
gateway bearer, and never enters relay requests, audit receipts, or responses.
One direct `AF_INET` connection dispatches each request to `127.0.0.1`; transport
does not resolve DNS, consult proxies, follow redirects, reconnect, or retry.
Absolute deadlines, request/response caps, strict HTTP framing and decoded
material scans apply before successful responses are released. Late, revoked,
or ambiguous dispatches consume reservations and cannot become successful
responses. The listener also bounds concurrent connections and HTTP input.

Every successful receipt states `fixture_usage_estimate=true`,
`live_model_proof=false`, and actual cost zero. Existing policy cost reservation
ceilings remain positive; fixture receipts spend none of those reservations.
These records prove deterministic transport, tool-turn and lifecycle mechanics
only, never model decision quality.

## Explicit interfaces

- Construct the runtime with an exact `ModelGatewayPolicy`, attempt-local gateway
  bearer and optional `ControlledProviderManifest`. It implements
  `ControlledProviderGenerationSource` and exposes `gateway`, `forwarder`,
  `transport`, `audit`, `relay_audit`, `binding`, and `gateway_port`.
- The public listener binds numeric loopback on an ephemeral port. The admitted
  worker route must preserve the policy authority
  `bf-model-<attempt suffix>:8081` in `Host`; a numeric SDK base URL alone is not
  an installed route qualification. Request IDs are controller-generated; workers
  cannot supply protected dispatch IDs or binding headers.
- `session(expected)` retains the lifecycle lock. Every `checked_binding()`
  verifies the same live listeners, process, numeric socket, descriptor,
  generation, manifest, and protected material reference. These are in-process
  controller custody facts, not separately attested native Strix worker identity.
- `gateway.revoke()` drains provider calls without stopping the generated lab.
  `runtime.close()` revokes, drains and releases both fixture listeners.
- `capture_tool_profile()` and `verify_tool_profile_capture()` in
  `strix_tool_capture.py` create/verify descriptor-only offline candidates from
  bounded exact wire bodies. Messages and tool results are excluded; known
  protected material must be passed for decoded descriptor scanning.
  Caller-declared provenance is explicitly not installed-runtime proof.

## CLI no-tools preflight

The [pinned CLI preflight](https://github.com/usestrix/strix/blob/6b7ae2ebe4d47037a927aade23265ff4e4f27e84/strix/interface/scan_setup.py#L115)
uses exactly two text messages and no tools. A separate strict grammar accepts
those source-backed messages, the exact Test-provider model and bounded tuning.
The runtime returns one deterministic nonstreamed Chat Completion containing
`OK`, with fixture usage and correlated audit. It does not relax the existing
streamed tool grammar or serve arbitrary no-tools prompts. Only one preflight
is allowed, before tool phases. Exact installed SDK envelope/header compatibility
still needs capture and review; source-backed compatibility is not installed
proof.

The worker-facing listener requires `X-Stainless-Retry-Count: 0` on every
accepted request. Missing, duplicated, non-canonical, or non-zero values are
refused before they consume the protected provider budget. Stainless metadata
is not forwarded as a fresh controller request, so an SDK retry cannot be
silently relabeled as one.

## Exact tool capture and enrollment remain closed

`APPROVED_PROFILE_DIGESTS` remains empty. A supplied manifest or capture cannot
approve itself. A full exact installed pinned Strix/SDK request must be captured
into a checked-in fixture and reviewed in code before adding a serving digest.
Synthetic test descriptors are never such a capture. Tool serving refuses an
unenrolled profile even after a successful no-tools preflight.

Profiles bind the pinned commit/tree, SDK `0.19.0`, root/noninteractive Chat
Completions mode, ordered base roster and source-backed sandbox suffix, and exact
full function and parameter digests. The profile preserves per-tool `strict`
presence/value: source-backed `repeat_request` and custom `apply_patch` may be
nonstrict; other tools stay strict. No blanket relaxation is allowed. Installed
capture must confirm these assumptions; unsupported variants need review.

## Versioned deterministic plans

V2 compatibility retains `view_agent_graph`, then `finish_scan`, and its exact
unassessed report. It does not claim target inspection.

V3 `bluefire.controlled-strix-mechanics.v3` instead requests one `repeat_request`
with a controller-preseeded Caido request ID and `modifications:null`, then
`finish_scan`. Its `target_inspection_seed` includes the same attempt ID, Caido
request ID and seed evidence receipt digest. A separate controller-owned
`target_seed_verifier` is required and checked freshly; a manifest cannot attest
its own seed. The installed controller must verify that this exact request
belongs to this attempt and the authorized target. The
[pinned replay tool](https://github.com/usestrix/strix/blob/6b7ae2ebe4d47037a927aade23265ff4e4f27e84/strix/tools/proxy/tools.py)
has `strict_mode=False`; the exact captured schema must match the supported
signature and enrolled full descriptor. The finite plan never discovers or
chooses the ID autonomously and never uses credentialed web search services.

Assistant calls and tool results must pair exactly. Result content is not
interpreted. The fixed V3 report says a paired result does not establish target
success, findings, coverage, or autonomous decision quality. Actual target replay
still requires independent Caido/target evidence.

This implementation and its local runtime tests launch no Strix, target, Docker
session, or live model. Remaining installed work is the exact SDK envelope/tool
schema capture, reviewed enrollment, admitted gateway Host route, independently
verified target seed receipt, and installed-session qualification through these
interfaces. Live-provider forwarding stays closed.
