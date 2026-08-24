# BlueFire Rust Runner

This crate is the execution authority for the disposable BlueFire Nexus local
vertical slice. The Python control plane can construct plans and select a
registered action, but it cannot provide an executable, command, shell script,
or arbitrary payload to this process.

The only public commands are:

```text
bluefire-runner inventory [--json]
bluefire-runner execute --manifest <manifest.json> --profile <profile.json> [--json]
```

`--json` is accepted for control-plane compatibility. Both commands emit JSON;
`execute` emits `bluefire.runner-result.v1`. Exit code `0` means success, `3`
means refused/control-blocked, `4` means an attempted action failed, was
partial, timed out, or could not clean up, and `2` means the input/CLI contract
itself could not be read.

Fixture transforms execute directly through compiled Rust enum variants. There
is no helper subcommand or externally invokable policy-bypass path. Process
discovery uses the Windows Toolhelp snapshot API or one platform-selected,
absolute `ps` path with a fixed argument vector on Linux/macOS; caller input can
never select an executable or argument.

## Registered actions

| Action ID | Typed parameters | Required capabilities | Tier | Effects |
|---|---|---|---|---|
| `sandbox.fixture.create.v1` | `path`, `content_template` (`telemetry-seed`, `harmless-document`, `empty`) | `filesystem_write` | `safe` | create-new sandbox file |
| `sandbox.fixture.transform.v1` | `input`, `output`, `transform` (`uppercase-ascii`, `reverse-bytes`) | `filesystem_read`, `filesystem_write` | `safe` | in-process transform plus create-new output |
| `sandbox.discovery.list.v1` | `path`, `max_entries` | `filesystem_read` | `safe` | bounded sandbox directory inventory |
| `sandbox.discovery.metadata.v1` | `path` | `filesystem_read` | `safe` | sandbox metadata and bounded file hash |
| `endpoint.discovery.system.v1` | none | `system_discovery` | `safe` | compiled system identity APIs |
| `endpoint.discovery.processes.v1` | `max_entries` | `process_discovery`, `process_spawn` | `safe` | bounded native/fixed-adapter process inventory |
| `sandbox.discovery.recursive.v1` | `path`, `max_entries`, `max_depth` | `filesystem_read` | `safe` | bounded, non-link-following sandbox traversal |
| `sandbox.archive.tar.v1` | `inputs`, `destination` | `filesystem_read`, `filesystem_write` | `controlled` | deterministic create-new ustar archive |
| `sandbox.collection.stage.v1` | `inputs`, `destination_directory` | `filesystem_read`, `filesystem_write` | `controlled` | bounded create-new copies |
| `sandbox.network.loopback.v1` | `artifact`, `destination {host,port}` | `filesystem_read`, `network_loopback` | `controlled` | fixed HTTP POST to a literal, declared loopback socket |
| `sandbox.export.local.v1` | `source`, `destination` | `filesystem_read`, `filesystem_write`, `export_local` | `controlled` | bounded sandbox-local create-new copy |
| `sandbox.cleanup.v1` | `receipt_ids` | `filesystem_write`, `cleanup` | `safe` | hash-checked deletion of receipt-owned objects only |

Every parameter structure uses Serde `deny_unknown_fields`. The registry is a
fixed Rust array; there is no dynamic library, Python entry point, action alias,
generic command, URL, hostname resolution, proxy, redirect, or shell dispatch.
`inventory --json` also exposes every action as
`bluefire.runner-action-sdk.v1`, including its semantic version, JSON Schema,
target types, observation hints, cleanup relationship, enforced limit classes,
readiness, and provenance/license metadata.

## Manifest JSON

The root object uses `bluefire.runner-manifest.v1` and rejects unknown or
duplicate fields. Fields are:

- `schema_version`: exactly `bluefire.runner-manifest.v1`.
- `request_id`, `run_id`, `step_id`: stable provenance identifiers.
- `behavior_id`: one of the selected action descriptor's compatible behavior
  IDs.
- `action_id`: one of the twelve exact IDs above.
- `mode`: lowercase `execute`. The Rust runner refuses `simulate`; simulation
  remains entirely in the control plane.
- `runner_id`, `runner_profile_id`: must exactly match the loaded profile.
- `platform`: `windows`, `linux`, or `macos`; it must match the profile, action,
  and actual host.
- `requested_at`, `expires_at`: RFC 3339 timestamps. Requests may live for at
  most one hour.
- `params`: the action-specific typed object in the table above.
- `target_scope.filesystem`: portable relative sandbox prefixes. `.` means the
  sandbox root. Absolute, drive, UNC/device, alternate-separator traversal,
  dot-components, reserved-device, symlink, and reparse-point paths are
  rejected.
- `target_scope.network`: exact `{host,port}` pairs. Hosts must be literal
  loopback IP addresses and ports must be nonzero.
- `required_capabilities`: the exact descriptor capabilities, serialized in
  snake_case. The profile must independently grant all of them.
- `safety_tier`: exactly `safe`, `controlled`, or `restricted`, and exactly the
  descriptor's tier.
- `limits`: positive `timeout_ms`, `max_stdout_bytes`, `max_stderr_bytes`,
  `max_artifact_bytes`, and `max_files`; none may exceed the profile.
- `cleanup_action_id`: exactly `sandbox.cleanup.v1`.
- `policy_digest`: the loaded profile's `sha256:<hex>` digest.
- `approval`: `null` or `{approved_by, approved_at, expires_at, request_hash}`.
  When the profile's approval threshold applies, the approval must be live and
  bound to the normalized request hash.
- `evidence_refs`: parent evidence identifiers copied into the result evidence.
- `request_hash`: `sha256:<hex>` of canonical sorted-key JSON after replacing
  both this field and `approval.request_hash` with empty strings.

Example shape (hashes are placeholders and must be recomputed):

```json
{
  "schema_version": "bluefire.runner-manifest.v1",
  "request_id": "request:fixture-1",
  "run_id": "run:demo-1",
  "step_id": "step:fixture",
  "behavior_id": "sandbox.fixture.create.v1",
  "action_id": "sandbox.fixture.create.v1",
  "mode": "execute",
  "runner_id": "runner:local",
  "runner_profile_id": "profile:disposable",
  "platform": "linux",
  "requested_at": "2026-08-23T12:00:00Z",
  "expires_at": "2026-08-23T12:10:00Z",
  "params": {
    "path": "fixtures/seed.txt",
    "content_template": "telemetry-seed"
  },
  "target_scope": {
    "filesystem": ["fixtures"],
    "network": []
  },
  "required_capabilities": ["filesystem_write"],
  "safety_tier": "safe",
  "limits": {
    "timeout_ms": 5000,
    "max_stdout_bytes": 8192,
    "max_stderr_bytes": 8192,
    "max_artifact_bytes": 1048576,
    "max_files": 32
  },
  "cleanup_action_id": "sandbox.cleanup.v1",
  "policy_digest": "sha256:<64 lowercase hex characters>",
  "approval": null,
  "evidence_refs": [],
  "request_hash": "sha256:<64 lowercase hex characters>"
}
```

## Runner profile JSON

Profiles use `bluefire.runner-profile.v1`:

- `profile_id`, `runner_id`, and `platform` bind routing.
- `sandbox_root` is an existing local directory. The runner canonicalizes it
  and refuses a symlink/reparse root.
- `allowed_actions` is an allowlist; `control_blocked_actions` wins even when an
  action also appears in the allowlist.
- `capabilities` are profile-granted snake_case capabilities.
- `max_safety_tier` is `safe`, `controlled`, or `restricted`.
- `approval_required_at_or_above` is a tier or `null`.
- `target_scope` is the maximum filesystem/network scope.
- `limits` are hard maxima.
- `policy_digest` is `sha256:<hex>` of canonical profile JSON after replacing
  this field with an empty string.

`seal_profile` and `seal_manifest` are public helpers for trusted builders and
tests. A digest detects mismatch/tampering but is not an authenticity
signature; production deployment should deliver profiles through a protected
local channel.

## Result, evidence, and cleanup

Results use `bluefire.runner-result.v1` and always echo the request/action/
behavior/runner/profile/platform/request-hash/policy-digest provenance. Status
is one of `success`, `failed`, `partial`, `refused`, `control_blocked`,
`timed_out`, or `cleanup_failed`. Captured output includes retained text, total
bytes, and a truncation flag.

Pre-effect refusals emit `control_blocked` evidence. Any started action emits
`executed` evidence. Evidence IDs and policy/request/output digests use
`sha256:<hex>` and preserve manifest parent references. This runner deliberately
does not claim independent `observed` evidence; a separate observer must do so.

Every create-new action uses `bluefire.runner-receipt-wal.v2`: it persists an
exact receipt intent before effect, syncs bytes in runner-owned staging,
publishes without overwrite, verifies the result, and persists a commit.
Pending intents remain discoverable after interruption. Callers pass only
receipt IDs to `sandbox.cleanup.v1`; the runner checks object type, size, and
SHA-256, removes safe partial staging, deletes files before owned directories,
refuses altered objects, consumes successful receipts, and treats an
already-consumed receipt as idempotent success. Cleanup never accepts a caller
path.

## Verification

The tests cover registry closure, strict parameter schemas, valid actions,
platform/capability/tier/approval/allowlist/control-block/scope enforcement,
portable traversal rejection, Unix symlink refusal, bounded process discovery,
recursive count/depth limits, deterministic archiving, legacy-helper bypass
refusal, resource limits, partial staging, structured evidence, receipt cleanup
and tamper refusal, pre-connect network refusal, a real ephemeral-loopback POST,
a slow/trickle monotonic-deadline case, and JSON CLI/SDK contracts. No test
connects outside `127.0.0.1`.

Run on a machine with Rust installed:

```text
cargo fmt --manifest-path runner/Cargo.toml -- --check
cargo clippy --manifest-path runner/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path runner/Cargo.toml
```
