# Command-line reference

The `bluefire` CLI uses the same service, validation, policy, durable product store, and run store as the local web console. Commands emit formatted JSON on standard output unless they start a long-running server.

```text
bluefire [--config PATH] [--runs-dir PATH] COMMAND ...
```

Put the global options before the command. `--config` selects the canonical YAML configuration and `--runs-dir` selects the immutable run-bundle directory. Successful commands return exit code `0`. Service/runtime refusals return a JSON error and exit code `2`; command-line syntax errors print argparse usage and also exit `2`. An interrupted receiver or UI server returns `130`.

Use `bluefire COMMAND --help` for the installed command surface. The examples below assume an authorized local lab and start in Simulate.

## Scenarios

A scenario command accepts exactly one of a YAML path or `--scenario-id` where shown.

```bash
bluefire scenario list
bluefire scenario versions
bluefire scenario version scenario.sandbox.research.chain.v1
bluefire scenario version scenario.sandbox.research.chain.v1 --version 2
bluefire scenario save scenarios/sandbox_research_chain.yaml

bluefire scenario validate scenarios/sandbox_research_chain.yaml
bluefire scenario validate --scenario-id scenario.sandbox.research.chain.v1
bluefire scenario preview --scenario-id scenario.sandbox.research.chain.v1
```

`scenario list` returns the active validated definitions. `versions` returns durable active-version metadata, `version` reads the active or exact version, and `save` validates the file before storing and activating a new content-addressed version. Saving the same content is idempotent; editing a saved definition produces a new version.

Preview and run options are:

```text
--mode simulate|execute
--profile RUNNER_PROFILE_ID
--autonomy off|assist|auto
--ai-provider PROVIDER_ID
--ai-enabled | --no-ai-enabled
--scope-ref SCOPE_REF                 (repeatable)
--action-implementation STEP_ID=ACTION_ID  (repeatable)
--approve
--approved-by AUDIT_LABEL
```

`--ai-enabled` is a compatibility alias: true maps to Assist and false maps to Off. Prefer `--autonomy`. Scenario commands include `sandbox.workspace` in requested scope by default; every additional `--scope-ref` must still be allowed by the selected profile and needed by the plan.

Simulate example:

```bash
bluefire --runs-dir .bluefire-runs scenario run \
  --scenario-id scenario.sandbox.research.chain.v1 \
  --mode simulate \
  --autonomy off
```

Execute requires an Execute profile, fresh runner readiness, exact policy/scope binding, and explicit approval. Preview first, then run only the unchanged reviewed request:

```bash
bluefire --config config/bluefire.example.yaml scenario preview \
  scenarios/sandbox_research_chain.yaml \
  --mode execute \
  --profile sandbox-execute.v1 \
  --scope-ref network.loopback \
  --scope-ref export.local

bluefire --config config/bluefire.example.yaml --runs-dir .bluefire-runs scenario run \
  scenarios/sandbox_research_chain.yaml \
  --mode execute \
  --profile sandbox-execute.v1 \
  --scope-ref network.loopback \
  --scope-ref export.local \
  --approve \
  --approved-by local-operator
```

The approval label records who acted in the local audit trail; it is not authentication or organizational authorization.

## Runs and bundles

```bash
bluefire --runs-dir .bluefire-runs runs list
bluefire --runs-dir .bluefire-runs runs detail RUN_ID
bluefire --runs-dir .bluefire-runs runs events RUN_ID
bluefire --runs-dir .bluefire-runs runs events RUN_ID --after-sequence 40 --limit 100
bluefire --runs-dir .bluefire-runs bundle validate RUN_ID
```

Events are ordered and paged by sequence. `--after-sequence` is exclusive and defaults to `0`; `--limit` defaults to `200`. Validate a finalized bundle before replay, comparison, export, or sharing. A valid hash chain proves internal consistency, not who produced the bundle.

## Durable jobs and proposal review

The web console creates durable jobs for asynchronous run control. The CLI can inspect and control those same records:

```bash
bluefire jobs detail JOB_ID
bluefire jobs approve JOB_ID --approved-by local-operator
bluefire jobs pause JOB_ID
bluefire jobs resume JOB_ID
bluefire jobs cancel JOB_ID
bluefire jobs retry JOB_ID

bluefire jobs proposals JOB_ID
bluefire jobs proposal JOB_ID PROPOSAL_RECORD_ID
bluefire jobs proposal-accept JOB_ID PROPOSAL_RECORD_ID decision.json
bluefire jobs proposal-reject JOB_ID PROPOSAL_RECORD_ID decision.json
```

Signals are state-dependent and can be refused. Retry creates a new job after a safely settled interrupted job; it does not restore stale execution authority. Execute retry performs fresh readiness and approval.

Proposal accept/reject files contain exactly the identity and three digests displayed by `jobs proposal`:

```json
{
  "decided_by": "local-operator",
  "state_digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "plan_digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "proposal_digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

Do not copy digests from another proposal. An accepted Execute mutation creates another fresh Execute approval request; accepting the model proposal does not itself authorize effects.

## Settings

```bash
bluefire settings list
bluefire settings set ui.preferences ui-preferences.json
```

The file must contain exactly the supported versioned preference object:

```json
{
  "schema_version": "bluefire.ui-preferences.v1",
  "theme": "system",
  "effect_mode": "simulate",
  "autonomy": "off"
}
```

Settings are secret-safe durable product records, but the current browser uses only theme plus effect/autonomy preferences. Settings do not define safety tier, policy, approval, target scope, cleanup, budgets, runner endpoint, or runner readiness. Those remain backend/profile authority and are bound during preflight and approval. Never place plaintext credentials in a setting document.

## Typed resources

```bash
bluefire resources list KIND
bluefire resources get KIND RESOURCE_ID
bluefire resources save KIND RESOURCE_ID document.json --status draft
bluefire resources activate runner_profile sandbox-execute.v1
bluefire resources deactivate runner_profile sandbox-execute.v1
bluefire resources probe runner_profile sandbox-execute.v1
```

CLI resource kinds are `action`, `collector`, `comparison`, `detection_backend`, `model_provider`, `plugin`, `research_source`, `runner`, and `runner_profile`. `document.json` is the resource document itself, not a `{ "document": ... }` wrapper; the CLI adds that envelope. If `--status` is omitted, the resource contract chooses its safe default: research sources start as `draft`, ordinary metadata starts as `ready`, and plugin state is derived from its strict manifest and trust review.

Activation and deactivation apply only to `runner_profile`, `model_provider`, and the declarative plugin lifecycle. A runtime resource must be deactivated before editing. Probe currently supports only `runner_profile` and reports an actual bounded inventory/readiness result. Research-source documents must carry the same ID as `RESOURCE_ID` and satisfy the strict immutable pin, version, URL, license, relationship, and review contract.

Plugin records are declarative metadata. BlueFire does not load Python entry points or gain connector/collector capabilities merely because a plugin manifest is active.

## Detection Lab

Inspect persistence and real parser/compiler readiness before advancing a candidate:

```bash
bluefire detections health
bluefire detections list
bluefire detections detail CANDIDATE_ID
```

Create and advance immutable candidates with JSON request files:

```bash
bluefire detections create hypothesis.json
bluefire detections parse CANDIDATE_ID
bluefire detections parse CANDIDATE_ID source.json
bluefire detections exercise-fixtures CANDIDATE_ID malicious.json
bluefire detections exercise-observed CANDIDATE_ID observed.json
bluefire detections evaluate-benign CANDIDATE_ID benign.json
bluefire detections reject CANDIDATE_ID rejection.json
bluefire detections clone CANDIDATE_ID clone.json
bluefire detections tune CANDIDATE_ID tune.json
bluefire detections compare BASELINE_CANDIDATE_ID comparison.json
```

An internal candidate parses with no request file. Sigma, SQLite, YARA, and SPL require `source.json`:

```json
{
  "source": "reviewed rule source"
}
```

SPL checking is structural only and cannot advance past hypothesis. Sigma requires exact pinned pySigma plus its SQLite backend for parse/conversion and uses a bounded local executor for lifecycle evaluation. Native SQLite accepts one fixed-schema `SELECT` that returns `fixture_id`. YARA requires YARA-Python for compilation and fixture execution; YARA-L remains unavailable because it is not the same language.

### Detection request files

`hypothesis.json` requires these six fields and permits the three optional lists shown:

```json
{
  "behavior_id": "sandbox.collection.stage.v1",
  "title": "Sandbox staging observation",
  "target_language": "internal",
  "logsource": {
    "category": "file_event",
    "product": "generic"
  },
  "selection": {
    "artifact_type": "file_observation",
    "path|contains": "staged/"
  },
  "provenance": {
    "source": "operator-authored",
    "license": "Review required"
  },
  "known_misses": ["Requires declared observation fields."],
  "predicted_fields": ["artifact_type", "path"],
  "public_baselines": []
}
```

Malicious exercise requires exactly a bounded `fixtures` array:

```json
{
  "fixtures": [
    {
      "fixture_id": "malicious-1",
      "artifact_type": "file_observation",
      "path": "staged/a.txt"
    }
  ]
}
```

Observed exercise never accepts caller-created evidence. It reads a finalized, integrity-checked run bundle and optionally narrows it to unique evidence IDs:

```json
{
  "run_id": "RUN_ID",
  "evidence_ids": ["EVIDENCE_ID"]
}
```

Benign evaluation requires fixtures and review notes:

```json
{
  "fixtures": [
    {
      "fixture_id": "benign-1",
      "artifact_type": "file_observation",
      "path": "documents/a.txt"
    }
  ],
  "notes": ["The declared benign fixture did not match."]
}
```

YARA fixture objects use bounded `data` instead of normalized observation fields. Rejection requires `reason` and permits `notes`:

```json
{
  "reason": "Selection is too broad.",
  "notes": ["Retained for audit only."]
}
```

Clone creates an editable hypothesis revision without changing rule semantics. It requires `reason` and optionally accepts `title`, `provenance`, `known_misses`, `public_baselines`, and `predicted_fields`:

```json
{
  "reason": "Create an editable revision."
}
```

Tune creates a new hypothesis revision and requires both `reason` and `selection`. It may also include `title`, `logsource`, `provenance`, `known_misses`, `public_baselines`, and `predicted_fields`; selection or log-source semantics must actually change:

```json
{
  "reason": "Narrow the staging path.",
  "selection": {
    "artifact_type": "file_observation",
    "path|contains": "archive/"
  }
}
```

Comparison requires a second candidate from the same revision lineage:

```json
{
  "candidate_id": "CANDIDATE_REVISION_ID"
}
```

Public baseline entries are accepted only when every provenance field exactly matches a registered pinned `research_source` resource. See [Detection Lab](DETECTION_LAB.md) for the lifecycle and baseline contract.

## Loopback artifact receiver

The canonical sandbox research chain's real primary network path sends an opaque artifact to literal loopback port `4317`. Start the bounded receiver in a separate unprivileged terminal before Execute:

```bash
bluefire receiver \
  --host 127.0.0.1 \
  --port 4317 \
  --max-requests 1 \
  --max-connections 16 \
  --max-body-bytes 5242880 \
  --request-timeout 5 \
  --idle-timeout 300
```

The receiver initializes no control plane or product database, but it does require the active enrollment at the fixed managed product root. It accepts an authenticated one-time `GET /bluefire/v1/challenge` followed by exactly `POST /bluefire/v1/artifact` from loopback with `Content-Type: application/octet-stream`, a decimal `Content-Length`, and a matching lowercase-hex `X-BlueFire-SHA256`. The HMAC chain binds the exact transport task, ephemeral receiver session, nonce, listener host/port, digest, and length. Request line, headers, body, aggregate request duration, idle duration, accepted-artifact count, and total connection count are independently bounded. A refused connection does not consume the verified-artifact slot, while `--max-connections` prevents unbounded refusal traffic and must be at least twice `--max-requests` to reserve the challenge plus upload connection for every possible accepted artifact. The body is never interpreted, executed, redirected, or forwarded, and readiness/summary logs do not include its content, enrollment key, or storage path. The bounded idle default is 300 seconds; `--idle-timeout` remains an explicit override.

Default operation transiently buffers at most `--max-body-bytes` for digest verification and does
not persist the body. Persistence is explicit:

```bash
bluefire receiver --host 127.0.0.1 --port 4317 \
  --max-requests 1 \
  --storage-dir /tmp/bluefire-receiver-artifacts-SESSION
```

The storage directory must be empty on first use, is marked as receiver-owned, and receives only non-overwriting content-addressed files. Use a disposable dedicated directory, not a repository, personal, shared, or production path. The server exits after its accepted-artifact limit, connection cap, idle timeout, or interruption. The runner records transport success only after strict, bounded parsing and constant-time verification of the authenticated acknowledgement, including its task/session, byte count, digest, and storage result. This authenticates the same-user managed receiver session; it remains a local lab receiver, not remote transport or authority for a different host, port, task, or session.

The deep endpoint lab uses the stricter one-shot variant:

```bash
bluefire receiver --host 127.0.0.1 --port 4317 --max-requests 1 --disposable-peer
```

`--disposable-peer` fixes memory-only storage, one accepted artifact, an eight-connection cap, a five-second per-connection deadline, and both idle and absolute lifecycle caps of 240 seconds. It exits immediately after the verified upload. Its authenticated challenge v2 and acknowledgement v3 add receiver PID, mode, artifact-limit, storage, and terminal-disposition bindings; peer handoff emits the logical v2 receipt with an opaque approved-task capability handle. Those fields state protocol intent. Release evidence must separately observe that the reported receiver PID is a different real process and has exited.

See [Runner deployment](RUNNER_DEPLOYMENT.md) for the complete Execute setup and cleanup model.

## Replay and run comparison

Exact replay keeps the immutable source snapshot and disallows variants:

```bash
bluefire --runs-dir .bluefire-runs replay RUN_ID --exact
```

Variant controls are:

```text
--from-step-id STEP_ID
--swap-step-id STEP_ID --swap-behavior-id BEHAVIOR_ID
--profile RUNNER_PROFILE_ID
--autonomy off|assist|auto
--ai-provider PROVIDER_ID
--ai-enabled | --no-ai-enabled
--scope-ref SCOPE_REF                      (repeatable)
--defense-change TEXT
--action-implementation STEP_ID=ACTION_ID  (repeatable)
--approve --approved-by AUDIT_LABEL
```

Example:

```bash
bluefire --runs-dir .bluefire-runs replay RUN_ID \
  --from-step-id discover_records \
  --autonomy off \
  --defense-change "Enabled reviewed detection revision 2"
```

Execute replay requires a selected Execute profile, a fresh disposable workspace, current runner readiness, current scope/policy checks, and fresh exact approval. It never reuses the source run's approval. A restart-from-node variant seeds normalized prior artifact metadata but does not materialize a trusted checkpoint or replay prerequisite effects; missing or out-of-scope runner-owned state must be refused.

Compare two or more finalized runs; the first is the baseline:

```bash
bluefire --runs-dir .bluefire-runs compare BASELINE_RUN_ID CANDIDATE_RUN_ID
```

Comparison retains path, outcome, evidence, detection, telemetry, controls, cleanup, AI, budget, duration, and replay-lineage deltas. Improvement/regression labels are descriptive signals, not causal proof. See [Replay and compare](REPLAY_COMPARE.md).

## Reviewed source intake

Import the shipped, reviewed MITRE ATT&CK T1082 metadata into a new namespace under the selected
BlueFire product-state root:

```bash
bluefire --runs-dir .bluefire-runs research intake-t1082 \
  --destination-id operator-review-20260829 \
  --profile sandbox-execute.v1 \
  --operator local-source-reviewer
```

`--destination-id` is a lowercase logical identifier, not a filesystem path. The command refuses an
existing namespace, traversal, absolute paths, platform device names, and arbitrary source or
transform requests. `--profile` must select an Execute profile whose authenticated runner reports
the fixed reviewed system-discovery opcode ready; `--operator` supplies the printable local audit
identity for trust, install, and activation.

The JSON result includes a relative product-state reference, canonical envelope SHA-256 and byte
count, record/output digests, the complete reviewed provenance envelope, and an exact
size/SHA/required-notice binding for the packaged license bytes; it does not expose an absolute path.
Missing or changed license bytes refuse the operation. The source contributes declarative metadata
only. BlueFire separately signs the fixed independent package recipe with an in-memory-only local
key, persists local trust and the package, verifies it against the selected runner, and activates its
behavior and action in the durable catalog. No private key or upstream executable content is saved,
and no network request occurs. A bounded private recovery stage retains only the public key and
signed envelope until package installation completes, so an interrupted install can reuse the exact
trusted signature without retaining private material.

Each success atomically writes a canonical per-destination operation receipt and returns its
path-free `operation_receipt` descriptor. The record binds the intake and artifact hashes, local
operator and runner profile, signed package digests, activation outcome, resulting catalog
generation/digest, and UTC completion time. A caught interrupted publication releases the
destination; after a hard stop, the same destination securely resumes only if its existing state is
the exact canonical artifact expected by the reviewed intake.

If runner activation fails after package installation, rerun the same command and destination after
restoring readiness; the released destination is recreated and the exact installed package is
resumed. Retrying a completed destination replays its immutable receipt without another activation.
A later intentional review therefore uses a new destination; it revalidates an already-active exact
package without another install, trust event, or catalog generation.

## Managed runner lifecycle

Lifecycle operations are explicit and local:

```bash
bluefire --config config/bluefire.example.yaml runner status --profile sandbox-execute.v1
bluefire --config config/bluefire.example.yaml runner bootstrap --profile sandbox-execute.v1
bluefire --config config/bluefire.example.yaml runner bootstrap --profile sandbox-execute.v1 --allow-upgrade
bluefire --config config/bluefire.example.yaml runner start --profile sandbox-execute.v1
bluefire --config config/bluefire.example.yaml runner stop --profile sandbox-execute.v1
bluefire --config config/bluefire.example.yaml runner revoke
bluefire --config config/bluefire.example.yaml runner remove --confirm-runner-id bluefire-rust-runner.v1
```

`runner status` is an inert, path-free read and never bootstraps or starts a process. Bootstrap verifies and installs the exact packaged artifact, or an explicit source-development override, before creating local enrollment. `--allow-upgrade` is a separate operator confirmation and succeeds only while the host is stopped and all task, receipt, trust, and artifact gates are clean. Start launches the separate same-user loopback host and requires authenticated readiness. Stop requests authenticated shutdown; it is also the safe reconciliation path for a stale process record. Revocation requires a stopped host with no unresolved watchdog or receipt obligations. Removal requires the complete status-reported runner ID and refuses live or orphaned transport state. Lifecycle output omits managed paths and credentials.

## Other inspection commands

```bash
bluefire plugins inventory
bluefire research status
bluefire --runs-dir .bluefire-runs research intake-t1082 --destination-id operator-review --profile sandbox-execute.v1 --operator local-source-reviewer
bluefire ui --host 127.0.0.1 --port 8765
```

`plugins inventory` reports the static loader boundary and does not read saved/active manifests; use `resources list plugin` or the local API/UI for managed plugin metadata. Research status lists metadata-only behaviors; it does not download or execute public research. The reviewed intake command uses only the already-vendored pinned T1082 asset; it performs no network access. The UI and API bind loopback only. `bluefire ui` prints its one-use capability URL only after a successful bind; open that exact URL, do not log or share it, and relaunch if the local browser session is absent or expired.

## JSON request-file rules

Every CLI argument named `document` must point to UTF-8 JSON whose root is an object. Arrays, scalars, malformed JSON, and unreadable files are rejected before the service call. Settings, plugin manifests, Detection Lab requests, and runtime configuration resources have strict command-specific contracts; generic metadata resources receive stable-ID and recursive secret-shaped-value checks but do not share one uniform field/list/size schema. File names may appear in local error messages, but file contents and configured secret values are not echoed by the CLI.

Treat request files as reviewed inputs:

- keep secrets out of files, settings, scenario YAML, and browser fields;
- copy exact proposal digests from the current pending review;
- use immutable research pins and license metadata for public baselines;
- store only sanitized fixtures and evidence intended for the lab;
- validate finalized run bundles before replay, comparison, or sharing.

The CLI manages same-user local enrollment, revocation, and TLS 1.3 mutual authentication for the separately hosted loopback runner. It does not add cross-host transport or enrollment, asymmetric signed artifacts, general shell execution, production collectors, or production SIEM validation. Those remain explicit product limitations.
