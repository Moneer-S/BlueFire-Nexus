# Local API

BlueFire serves one loopback JSON API under `/api/v1`. Requests and responses use ordinary HTTP; run execution is managed by durable background jobs. The API is the HTTP adapter over the same `BlueFireService` used by the CLI.

## Security and transport

- Default listener: `http://127.0.0.1:8765`.
- Non-loopback bind addresses are rejected.
- Host must identify the current loopback listener and port.
- Every POST requires an exact same-origin `Origin` header.
- Request bodies require one numeric `Content-Length` and are limited to 1 MiB.
- Duplicate JSON keys, non-finite numbers, transfer encoding, absolute request targets, traversal, backslashes, and NUL paths are rejected.
- Responses use restrictive CSP, frame, referrer, permissions, and content-type headers.
- No permissive CORS or remote authentication is provided.

Do not expose this API through a reverse proxy, tunnel, port forward, or container publish rule without a separately reviewed authentication/authorization layer.

## Endpoints

| Method | Path | Result |
|---|---|---|
| GET | `/api/v1/catalog` | Modes, autonomy/provider metadata, behaviors, actions, profiles |
| GET | `/api/v1/scenarios` | Packaged scenario documents |
| GET | `/api/v1/settings` | Secret-safe local settings |
| POST | `/api/v1/settings/{setting_key}` | Upsert one setting |
| GET, POST | `/api/v1/scenario-versions` | List active saved versions or save a scenario version |
| GET | `/api/v1/scenario-versions/{scenario_id}` | Active saved scenario version |
| GET | `/api/v1/scenario-versions/{scenario_id}/versions/{version}` | Exact saved scenario version |
| GET | `/api/v1/resources/{kind}` | List one allowlisted resource kind |
| GET, POST | `/api/v1/resources/{kind}/{resource_id}` | Get or upsert one resource |
| POST | `/api/v1/resources/runner-profiles/{resource_id}/activate` | Validate and activate a stored runner profile |
| POST | `/api/v1/resources/runner-profiles/{resource_id}/deactivate` | Persistently withdraw a runner profile |
| POST | `/api/v1/resources/runner-profiles/{resource_id}/probe` | Bounded, sanitized runner inventory/health probe |
| POST | `/api/v1/resources/model-providers/{resource_id}/activate` | Validate and select a stored AI provider |
| POST | `/api/v1/resources/model-providers/{resource_id}/deactivate` | Persistently withdraw an AI provider |
| POST | `/api/v1/resources/plugins/{resource_id}/activate` | Activate reviewed declarative plugin metadata |
| POST | `/api/v1/resources/plugins/{resource_id}/deactivate` | Deactivate declarative plugin metadata |
| POST | `/api/v1/ai/drafts` | Draft one validated, deliberately unsaved scenario graph |
| GET | `/api/v1/detection-lab/health` | Detection persistence and parser/compiler readiness |
| GET, POST | `/api/v1/detections` | List candidates or upsert a strict hypothesis (`201`) |
| GET | `/api/v1/detections/{candidate_id}` | Get one strict persisted candidate |
| POST | `/api/v1/detections/{candidate_id}/parse` | Parse, compile, or structurally check source |
| POST | `/api/v1/detections/{candidate_id}/exercise-fixtures` | Exercise bounded malicious fixtures |
| POST | `/api/v1/detections/{candidate_id}/exercise-observed` | Exercise immutable observed run evidence |
| POST | `/api/v1/detections/{candidate_id}/evaluate-benign` | Evaluate bounded benign fixtures and notes |
| POST | `/api/v1/detections/{candidate_id}/reject` | Explicitly reject a non-terminal candidate |
| POST | `/api/v1/scenarios/validate` | Validated graph and issues |
| POST | `/api/v1/runs/preflight` | Plan, policy/readiness, scope, approval, cleanup, AI metadata |
| POST | `/api/v1/runs` | Submit a durable run job (`202`) |
| GET | `/api/v1/jobs/{job_id}` | Durable job state and progress |
| POST | `/api/v1/jobs/{job_id}/approval` | Approve one exact Execute intent (`202`) |
| POST | `/api/v1/jobs/{job_id}/retry` | Create a replacement for one safely settled interrupted job (`202`) |
| GET | `/api/v1/jobs/{job_id}/proposals` | List durable proposal reviews |
| GET | `/api/v1/jobs/{job_id}/proposals/{proposal_record_id}` | Exact proposal review envelope |
| POST | `/api/v1/jobs/{job_id}/proposals/{proposal_record_id}/accept` | Accept and deterministically replan (`202`) |
| POST | `/api/v1/jobs/{job_id}/proposals/{proposal_record_id}/reject` | Reject without graph mutation (`202`) |
| POST | `/api/v1/jobs/{job_id}/pause` | Request cooperative pause (`202`) |
| POST | `/api/v1/jobs/{job_id}/resume` | Resume a paused job (`202`) |
| POST | `/api/v1/jobs/{job_id}/cancel` | Request cooperative cancellation (`202`) |
| GET | `/api/v1/runs` | Run summaries |
| GET | `/api/v1/runs/{run_id}` | Full run, evidence, detections, events, manifest |
| GET | `/api/v1/runs/{run_id}/events` | Cursor-paginated run events |
| POST | `/api/v1/runs/{run_id}/replays` | Create a lineage-linked replay (`201`) |
| POST | `/api/v1/comparisons` | Compare two or more runs |

The service maintains a migrated local SQLite product store and exposes its schema/seed/restart-recovery summary in `catalog.product_state`. Settings, saved scenario versions, and allowlisted resource documents can be managed through the routes above. The ProductStore remains authoritative for recursive plaintext-secret rejection and content-addressed scenario versioning; the underlying Python store is not an implied public API.

## Requests

### AI graph draft

`POST /api/v1/ai/drafts` turns a bounded natural-language objective into a typed,
registered scenario draft. The body accepts exactly:

```json
{
  "objective": "Create synthetic records, inspect them, and clean up.",
  "provider_id": "deterministic-offline.v1",
  "max_nodes": 8,
  "max_edges": 16
}
```

`provider_id` may be omitted or null to use the active provider. `max_nodes` is
bounded to 1–16 and `max_edges` to 0–32; the defaults are 8 and 16. The
deterministic provider is fully offline. The configured Responses provider uses
its credential environment reference, strict Structured Outputs, no tools, and
deterministic fallback. No credential value is returned or persisted by this
operation.

The result has schema `bluefire.ai-graph-draft-result.v1` and contains
`draft_id`, `saved: false`, a complete `bluefire.scenario.v1` document,
`rationale`, `assumptions`, and an `audit` object. The audit records requested
and effective provider/model metadata, fallback and usage data, input and
allowlist digests, selected registered behavior IDs and parameter fields,
normalization details, and validation status.

Model output is not accepted as a scenario directly. It may choose only
registered non-metadata behavior IDs and exact primitive parameter values from
the request-specific catalog. It cannot supply action IDs, commands, paths,
artifact bindings, profiles, scope, approvals, execution mode, or policy.
BlueFire derives identity, graph bindings, provenance, and limitations, then
validates the normalized document against the registry. The draft is never
saved, run, approved, or otherwise authoritative; use the ordinary scenario
version and run workflows as separate explicit operations.

### Validate

```json
{
  "scenario": {
    "schema_version": "bluefire.scenario.v1",
    "id": "scenario.example.v1",
    "title": "Example",
    "purpose": "Validate one bounded behavior.",
    "start": "inspect_system",
    "steps": [
      {
        "id": "inspect_system",
        "behavior_id": "endpoint.discovery.system.v1"
      }
    ],
    "edges": [],
    "provenance": {
      "source": "Local reviewed example",
      "reference": "example contract",
      "license": "MIT",
      "derived": false
    },
    "limitations": ["Example only."]
  }
}
```

### Preflight or run submission

Canonical request fields consumed by the service are:

```json
{
  "scenario": {"schema_version": "bluefire.scenario.v1"},
  "mode": "simulate",
  "runner_profile_id": "sandbox-simulate.v1",
  "target_scope": {"scope_refs": ["sandbox.workspace"]},
  "autonomy": "off",
  "ai_provider_id": "deterministic-offline.v1"
}
```

The service requires explicit Execute scope and checks it against the profile. `POST /runs` does not accept an inline browser confirmation as authority; it removes any inline `approval`, creates an immutable bound approval request, and holds the job in `awaiting_approval`. Treat fields returned by preflight and run submission as authoritative; do not assume an extra client-only field changed backend behavior.

`action_implementations` is Execute-only and maps at most 100 bounded scenario step IDs to registered action IDs. Each selected action must belong to that step's behavior and be enabled by the exact runner profile. The resolved per-step choices are persisted in the job and plan and included in the exact approval state/plan digests. Simulate rejects the field, including an empty object, because simulations never select executable implementations.

```json
{"action_implementations":{"inspect_system":"endpoint.discovery.system.v1"}}
```

`ai_enabled` remains a compatibility alias: false maps to Off and true maps to Assist. Do not send it together with `autonomy`; new clients should use `autonomy`.

### Durable run jobs and Execute approval

`POST /api/v1/runs` returns `202` immediately:

```json
{
  "schema_version": "bluefire.run-job-submission.v1",
  "job": {
    "job_id": "job-0123456789abcdef0123456789abcdef",
    "state": "awaiting_approval",
    "progress": {"phase": "awaiting_approval"},
    "result_ref": null
  },
  "approval_request": {
    "approval_id": "approval-...",
    "status": "pending",
    "profile_id": "sandbox-execute.v1",
    "maximum_tier": "controlled",
    "expires_at": "2026-08-24T01:00:00Z"
  },
  "preflight": {"status": "approval_required", "ready": false}
}
```

Simulate jobs normally move through `queued`, `planning`, `running`, and `completed`. Execute adds `awaiting_approval`. Other durable states are `paused`, `cancelling`, `cancelled`, `failed`, and `interrupted`.

Before approving Execute, display the returned canonical preflight, approval binding/envelope, profile, target scope, tier, effects, and cleanup. Then submit only the operator identity:

```json
{"approved_by": "local-operator"}
```

to `POST /api/v1/jobs/{job_id}/approval`. The service recomputes preflight, verifies every stored binding field, approves and consumes the one-time record, and only then releases the worker. An expired, changed, reused, or non-waiting intent is refused. Approval responses never expose the nonce.

Poll `GET /api/v1/jobs/{job_id}` for state and progress. The response also includes the current nonce-free `approval_request` when one is bound to the job, so a reloaded client can redisplay the exact pending digests before enabling approval. A fresh AI-proposal Execute approval in job progress takes precedence over the already-claimed original request approval. Progress includes `phase` and bounded orchestration checkpoint fields; after the run finishes it includes `run_id`, `run_status`, and `completed_steps`, while `result_ref` is the run ID. Use that ID with run detail or the event-page endpoint. There is no SSE or WebSocket stream.

Pause, resume, cancel, and retry requests use `{}` bodies. Pause is acknowledged at an orchestration checkpoint, and a running cancellation may first report `cancelling`. Retry is replacement, never continuation: only a safely settled interrupted `scenario.run` job is eligible. A replacement Execute job is preflighted again, receives a new approval request, and cannot inherit or reuse the source capability.

### AI proposal review and continuation

An actionable Assist proposal, or any Execute mutation proposed under Auto, leaves the durable job in `awaiting_approval`. Job progress identifies `approval_kind: "ai_proposal"`, the `proposal_record_id`, and exact `state_digest`, `plan_digest`, and `proposal_digest`. The v2 record can carry the exact registered next edge for the observed outcome, a compatible behavior, bounded primitive parameter changes, an action already registered for the exact profile, or one bounded retry. Read the complete review envelope and digests, then accept or reject with exactly:

```json
{
  "decided_by": "local-operator",
  "state_digest": "sha256:...",
  "plan_digest": "sha256:...",
  "proposal_digest": "sha256:..."
}
```

The service refuses unknown fields, stale or already-resolved records, tampered digests/content, unregistered or cross-paired choices, an edge for another observed outcome, an action not enabled by the exact profile, an out-of-schema parameter, an exhausted retry, and a review that is not the job's current gate. Rejecting finishes the job at the original run without a continuation. Accepting Simulate reconstructs an immutable lineage-linked continuation, validates the exact bounded choice, recompiles the deterministic plan, reruns preflight, and releases the job without an Execute capability.

Accepting an Execute proposal does **not** release execution. Because the source workspace was cleaned, BlueFire reconstructs the accepted choice as a full replay from the scenario start in a fresh approval-specific workspace. It creates a new approval request bound to the mutated scenario, recompiled plan, target scope, profile, tier, provider, action map, and proposal lineage; the job remains `awaiting_approval` with `approval_kind: "ai_proposal_execute"`. Review that new envelope and call the ordinary job `/approval` endpoint. The original Execute approval is already claimed and explicitly refused. Planning/preflight are recomputed again at approval and execution, and normal policy/runner checks remain authoritative.

### Replay

```json
{
  "exact": false,
  "from_step_id": "discover_records",
  "swap_step_id": "discover_records",
  "swap_behavior_id": "sandbox.discovery.metadata.v1",
  "autonomy": "off",
  "ai_provider_id": "deterministic-offline.v1",
  "runner_profile_id": null,
  "parameter_overrides": {"discover_records": {"record_limit": 12}},
  "action_implementations": {"discover_records": "sandbox.discovery.metadata.v1"},
  "defense_change": "Enabled reviewed detection revision 2"
}
```

`exact: true` cannot be combined with a variant. `parameter_overrides` maps step IDs to complete parameter objects that are revalidated against the replayed behavior. Execute replay preserves the source plan's action choices for untouched steps. An explicit `action_implementations` override is validated against the replayed behavior and current profile and is recorded in lineage. A compatible behavior swap without an explicit action override deterministically re-resolves only the swapped step and records that change. Every Execute replay receives a fresh exact approval bound to the resulting choices; the source approval is never reused. Execute replay additionally needs target scope and inline approval. Replay currently remains synchronous within its POST request; it is not submitted through the background job controller.

### Product settings

`POST /api/v1/settings/{setting_key}` requires exactly:

```json
{"value": {"theme": "dark"}}
```

Keys are lowercase stable identifiers up to 200 characters. Values may be any JSON value, but every secret-shaped field must be null or an exact environment reference such as `{"env":"BLUEFIRE_API_KEY"}`. Unknown envelope fields and plaintext secrets are rejected.

### Saved scenario versions

`GET /api/v1/scenario-versions` lists the active durable version of each saved scenario. Save a validated registered scenario with:

```json
{"scenario": {"schema_version": "bluefire.scenario.v1"}}
```

Identical content reuses its content-addressed version; changed content creates the next version. The active and exact-version GET routes return the saved metadata plus canonical scenario document. The collection is not a complete version-history listing; clients that retain a returned version can retrieve it through `/versions/{version}`.

### Managed resources

Resource routes accept only these path kinds:

| Route kind | Stored kind |
|---|---|
| `actions` | `action` |
| `collectors` | `collector` |
| `comparisons` | `comparison` |
| `detections` | `detection` |
| `detection-backends` | `detection_backend` |
| `model-providers` | `model_provider` |
| `plugins` | `plugin` |
| `research-sources` | `research_source` |
| `runners` | `runner` |
| `runner-profiles` | `runner_profile` |

Upsert an item with exactly `document` and optional lowercase stable `status`:

```json
{
  "document": {"name": "Local collector", "enabled": true},
  "status": "ready"
}
```

Resource IDs use the same stable lowercase identifier rule as setting keys. Unknown kinds, extra path segments, query parameters, duplicate/unknown envelope fields, malformed IDs, and plaintext secret values are rejected. A generic save remains metadata-only: it does not dynamically install code, register a behavior, activate a collector, or expand runner authority. `active` and `inactive` are reserved statuses for runner profiles and model providers and cannot be supplied through generic upsert.

Detection is the exception to generic resource writes. `GET /api/v1/resources/detections` remains a compatibility read, but generic detection POST returns `409 detection_lifecycle_required`; all detection changes must use the explicit lifecycle routes below.

### Detection Lab lifecycle

Create a behavior-linked hypothesis with exactly the required identity fields and optional bounded research metadata:

```json
{
  "behavior_id": "sandbox.collection.stage.v1",
  "title": "Sandbox staging observation",
  "target_language": "internal",
  "logsource": {"category": "file_event", "product": "generic"},
  "selection": {"artifact_type": "file_observation", "path|contains": "staged/"},
  "provenance": {"source": "operator-authored", "license": "MIT"},
  "known_misses": ["Requires filesystem observation fields."],
  "predicted_fields": ["artifact_type", "path"]
}
```

`POST /api/v1/detections` derives the candidate ID from behavior, language, logsource, and selection. It can update only a candidate that is still a hypothesis; it cannot reset a progressed or rejected candidate. Every accepted operation appends a bounded lifecycle row containing action, prior/current state, outcome, input digest, timestamp, and immutable run ID when applicable.

Parsing uses an exact `{}` body for `internal`, and `{"source":"..."}` for Sigma, YARA/YARA-L, and SPL. Internal uses the maintained structured matcher, Sigma uses pySigma, and YARA uses YARA-Python with includes disabled and warnings treated as errors. SPL has only a structural checker: success records the bounded source and checker result but deliberately remains `hypothesis`. Missing authoritative adapters return `503` without advancing state; parser/compiler rejection is persisted as `rejected`.

Malicious and benign fixture actions accept explicitly named JSON fixtures, at most 128 and 1 MiB in total. YARA fixtures contain only `fixture_id` and text `data`; matching compiles the persisted source and uses a timeout. Internal and normalized Sigma exercises use the bounded structured matcher and record whether the source rule itself was executed. Benign evaluation also requires a bounded `notes` list:

```json
{
  "fixtures": [{"fixture_id": "benign-1", "path": "documents/a.txt"}],
  "notes": ["Declared benign fixture did not match."]
}
```

Observed exercise accepts only `{"run_id":"...","evidence_ids":["evidence-..."]}`. The run must be finalized, its bundle manifest must verify, each evidence content/record/identity hash is recomputed, and every selected record must have `observed` provenance. Callers cannot submit evidence inline. YARA bytes cannot be inferred from JSON evidence, and SPL is not authoritative, so observed JSON exercise is limited to internal and normalized Sigma selection semantics.

Candidate source, fixtures, notes, field drift, match counts, and lifecycle history are persisted in the `detection` resource with status equal to the honest candidate state. ProductStore's recursive secret-shaped-field rules apply to every persisted candidate; arbitrary commands, paths to execute, dynamic imports, and backend execution configuration are not accepted by these routes.

Plugin resources use the stricter `bluefire.plugin.v1` contract documented in [Plugin SDK](PLUGIN_SDK.md). Their save envelope contains exactly `document`; caller-supplied status and unknown manifest fields such as entry points, commands, or free-form execution configuration are rejected. The manifest ID must equal the route ID. Status is derived from `enabled` and `trust`, then changed only through the explicit plugin activation/deactivation routes.

```text
POST /api/v1/resources/plugins/{plugin_id}/activate
POST /api/v1/resources/plugins/{plugin_id}/deactivate
{}
```

Activation requires an enabled, reviewed or trusted manifest with strict provenance and a non-placeholder SHA-256 integrity identity. It registers durable metadata only and does not verify external bytes or publisher identity. Activation and inventory responses explicitly report `executable_loading: false` and `dynamic_actions: false`; Python entry points are disabled. `GET /api/v1/resources/plugins` includes sanitized health/inventory metadata, and active/inactive state survives restart.

Runner-profile and model-provider runtime changes use their explicit action routes with an exact `{}` body. Runner profile activation parses the stored document through the strict `RunnerProfile` contract, requires its document ID to match the resource ID, and validates every action/capability/tier/platform reference against the built-in registry before persisting `active`. Model provider activation likewise parses the stored document through `AIProviderConfig`, requires matching IDs, and makes that provider the default selectable provider. Activating one model provider persistently deactivates any previously activated provider. The reviewed deterministic provider is always retained as the fallback and cannot be deactivated.

Drafts and malformed documents never affect preflight or provider construction. An activated document becomes authoritative immediately and remains active after restart; `deactivate` persists `inactive` and removes it from normal selection. Active resources must be deactivated before their document can be edited. Editing an inactive document preserves its inactive status until a later successful activation. YAML configuration remains the baseline for resources without an activated or inactive persisted override.

The runner probe accepts no path, executable, environment-variable name, or secret from the request. It looks up one stored, strictly validated profile, resolves only that profile's `runner_binary` environment reference, invokes the fixed runner `inventory --json` transport with a 10-second/256-KiB boundary, and returns only allowlisted version, platform, action ID/version/readiness, and health fields. Raw inventory fields, paths, stderr, and exception text are not returned. A custom embedded runner transport is responsible for honoring the same bounded inventory contract.

### Compare

```json
{"run_ids": ["BASELINE_RUN_ID", "CANDIDATE_RUN_ID"]}
```

At least two unique IDs are required; the first is the baseline.

### Run event pages

`GET /api/v1/runs/{run_id}/events` reads the append-only event stream without returning the full run document. It accepts two optional decimal query parameters:

| Parameter | Default | Bounds | Meaning |
|---|---:|---:|---|
| `after_sequence` | `0` | `0` through `2^63-1` | Return events whose sequence is strictly greater than this cursor |
| `limit` | `250` | `1` through `1000` | Maximum events returned in this page |

Unknown, duplicate, signed, blank, non-decimal, or out-of-range values return `400 invalid_event_page`. A missing run returns `404 run_not_found`.

```json
{
  "schema_version": "bluefire.event-page.v1",
  "run_id": "RUN_ID",
  "after_sequence": 12,
  "next_sequence": 12,
  "has_more": false,
  "items": []
}
```

Use the returned `next_sequence` as the next request's `after_sequence`. When `items` is empty, `next_sequence` remains the supplied cursor. This is bounded polling over immutable local records, not a live event stream.

## curl examples

Read catalog:

```bash
curl --fail --silent http://127.0.0.1:8765/api/v1/catalog
```

Read up to 100 events after sequence 250:

```bash
curl --fail --silent \
  'http://127.0.0.1:8765/api/v1/runs/RUN_ID/events?after_sequence=250&limit=100'
```

POST requests must send the matching Origin:

```bash
curl --fail --silent \
  -H 'Origin: http://127.0.0.1:8765' \
  -H 'Content-Type: application/json' \
  --data '{"run_ids":["BASELINE_RUN_ID","CANDIDATE_RUN_ID"]}' \
  http://127.0.0.1:8765/api/v1/comparisons
```

## Error contract

Safe service errors use:

```json
{
  "error": {
    "code": "scenario_invalid",
    "message": "Scenario validation failed.",
    "details": ["specific safe validation message"]
  }
}
```

Common statuses include 400 for malformed requests or management envelopes, 403 for origin rejection, 404 for unknown routes/runs/jobs/resources/versions, 409 for run/replay/job-control or approval conflicts, 411 for missing length, 413 for oversized bodies, 421 for invalid Host, 422 for rejected scenario/resource/setting documents, 503 for a full local job queue, and 405 for wrong methods.

Unexpected exceptions are converted to a generic `service_error`; local filesystem paths and exception details are not returned.

## Current limitations

- Job state/control and run event pages are polling APIs; there is no SSE/WebSocket stream.
- Pause and cancellation are cooperative at bounded orchestration checkpoints, not forced thread termination.
- Execute replay remains synchronous and uses the inline replay approval contract; only new `/runs` submissions use durable background jobs.
- Run list/detail and event pages return canonical local store data; clients must poll for updates.
- There is no generated OpenAPI document or client package in 0.1.x.
- The API is local single-user trust, not a remotely authenticated control plane.
- Versioning is at `/api/v1` plus schema versions in documents; unknown fields inside domain contracts are rejected.
