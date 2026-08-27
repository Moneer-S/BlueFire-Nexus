# Action SDK

BlueFire has two related action contracts:

1. the **logical action** in `bluefire/catalog/actions.yaml`, used by scenarios and the Python planner;
2. the **executor action descriptor** in the Rust static registry, exposed as `bluefire.runner-action-sdk.v1`.

They are intentionally different. Logical parameters and typed artifacts must pass through an explicit `RunnerActionAdapter`; a scenario cannot supply runner paths, process arguments, sockets, or receipt internals directly.

## Rust descriptor

Every compiled `ActionDescriptor` declares:

| Field | Contract |
|---|---|
| `schema_version` | `bluefire.runner-action-sdk.v1` |
| `action_id` | Stable versioned action ID |
| `action_version` | Semantic implementation version |
| `behavior_ids` | Compatible registered behaviors |
| `summary` | Concise effect description |
| `platforms` | Supported runner platforms |
| `parameter_schema` | JSON Schema object with `additionalProperties: false` |
| `capabilities` | Exact runner-side capabilities |
| `safety_tier` | `safe`, `controlled`, or `restricted` |
| `target_types` | Declared scope/target categories |
| `observation_hints` | Independent sources/signals that may observe the action |
| `cleanup_action_id` | Registered cleanup action or null |
| `declared_limits` | Enforced timeout/output/artifact/file/depth limit classes |
| `readiness` | Current inventory readiness |
| `provenance` | Source, reference, and license |
| effect flags | Filesystem, network, and process effects |
| `cleanup_receipt` | Whether successful effects create cleanup ownership |

Read the live inventory rather than copying this table into tooling:

```bash
cargo run --release --manifest-path runner/Cargo.toml -- inventory --json
```

## Runtime trait

Rust actions implement a two-phase interface:

```rust
pub trait Action: Sync {
    fn descriptor(&self) -> &'static ActionDescriptor;
    fn prepare(&self, params: Value) -> Result<Box<dyn PreparedAction>, ActionFailure>;
}

pub trait PreparedAction: Send {
    fn execute(
        self: Box<Self>,
        context: &ActionContext<'_>,
    ) -> Result<ActionOutcome, ActionFailure>;
}
```

`prepare` strictly deserializes action-specific parameters using Serde `deny_unknown_fields`. Shared runner preflight validates manifest/profile identity, action registration, behavior compatibility, platform, capabilities, tier, scope, approval, lifetime, limits, cleanup binding, and request/profile digests before `execute` is called.

Observation is expressed through descriptor hints and separate collectors; an action must not label its own result `observed`. Cleanup is a separately registered action that accepts receipt IDs, not arbitrary paths.

## Logical catalog contract

A logical `bluefire.action.v1` entry contains:

- stable ID, title, purpose, tier, capabilities, and platforms;
- typed input/output artifact ports;
- typed parameters (`string`, `integer`, `number`, `boolean`, or `string_list`) with defaults/required/range/enum constraints;
- mutation flag and cleanup action ID;
- provenance.

The logical catalog describes operator intent. It must not expose executor-only fields such as `path`, `destination`, `executable`, `args`, `receipt_ids`, or socket objects unless those values are derived by a reviewed adapter from typed artifacts and policy.

## Built-in action pack

| Action ID | Executor parameter object | Effect |
|---|---|---|
| `sandbox.fixture.create.v1` | `path`, compiled `content_template` enum, `record_count` (1..100) | Create one exact deterministic JSONL fixture |
| `sandbox.fixture.transform.v1` | `input`, `output`, `redact_values` boolean | Validate and canonicalize the exact fixture schema, optionally replacing every value with `synthetic-redacted` |
| `sandbox.discovery.list.v1` | `path` | Return one metadata record for the exact regular-file fixture; do not enumerate siblings or read contents |
| `sandbox.discovery.metadata.v1` | `path` | Return one metadata record, including read-only state, for the exact regular-file fixture; do not read contents |
| `endpoint.discovery.system.v1` | empty object | OS/architecture facts |
| `endpoint.discovery.processes.v1` | `max_entries` | PID/name records through fixed platform adapter |
| `sandbox.discovery.recursive.v1` | `path`, `max_entries`, `max_depth` | Non-link-following subtree inventory |
| `sandbox.archive.tar.v1` | `inputs`, `destination` | Deterministic create-new ustar archive |
| `sandbox.collection.stage.v1` | `inputs` (exactly one), `destination_directory`, `bundle_format` (`jsonl` or `json`) | Validate the complete input before creating one deterministic bundle |
| `sandbox.network.loopback.v1` | `artifact`, `destination {host, port}` | Fixed HTTP POST to literal loopback |
| `sandbox.export.local.v1` | `source`, `retention_label` (`ephemeral` or `review`) | Temporary create-new copy at a label-derived runner-owned path |
| `sandbox.execution.native-canary.v1` | `rounds` (1..4096) | Deterministic bounded in-process numeric computation with no effects |
| `sandbox.identity-material.seed.v1` | empty object | Create the exact public canary at `identity-material/public-canary.json` |
| `sandbox.identity-material.inspect.v1` | empty object | Inspect only that exact canary and return digest and count metadata, never values |
| `sandbox.peer.handoff.v1` | `port` (1024..65535) | Authenticated handoff of exactly one `staged/bundle.json` or `staged/bundle.jsonl` to literal `127.0.0.1` |
| `sandbox.observability.variant.v1` | `representation` (`canonical` or `chunked_hex`) | Create `observability/variant.bin` as an exactly reversible comparison representation |
| `sandbox.restricted.persistence-marker.v1` | `path`, compiled marker bytes | Fixed non-executable persistence-detection canary inside the runner-owned sandbox |
| `sandbox.cleanup.v1` | `receipt_ids` | Receipt-bound quarantine, revalidation, removal, and authoritative verification report |

The create, transform, exact-file discovery, collection, and export descriptors are implementation version `2.0.0`; cleanup is `1.1.0`. The five representative descriptors—native canary, identity seed, identity inspection, peer handoff, and observability variant—are version `1.0.0` and declare `ready` in the compiled inventory. The other built-in descriptors remain `1.0.0`. Inventory consumers must validate those versions and readiness instead of inferring them from the stable `.v1` action IDs.

The adapter—not scenario input—chooses the fixed create path `fixtures/input.jsonl`, the transformed path, the exact discovery path, destination directories, and receipt IDs. Logical input is deliberately smaller: create exposes `record_count`; transform exposes `redact_values`; list and metadata expose no parameters; collection exposes `bundle_format`; export exposes only `retention_label`; native canary exposes only `rounds`; identity seed and inspection expose no parameters; peer handoff exposes only `port`; observability variant exposes only `representation`; and cleanup requires `verify_removal: true`. The executor derives its typed path and receipt fields from bound artifacts and policy.

Native canary performs only deterministic compiled computation for 1..4096 rounds; it cannot name a process, command, script, executable, or effect. Identity seed writes an exact 189-byte public synthetic JSON canary at `identity-material/public-canary.json`, and identity inspection reads only that bound artifact. Inspection returns its byte count, field count, and SHA-256 digest without returning values or enumerating siblings. These actions do not access or represent credentials.

Peer handoff accepts exactly one typed artifact at `staged/bundle.json` or `staged/bundle.jsonl`. The runner hardcodes literal `127.0.0.1`, authenticates the handoff, and rejects a caller host, path, or non-staged artifact; the blocked-network profile blocks the action. Observability variant reads that staged bundle and writes only `observability/variant.bin`. `canonical` is continuous lowercase hexadecimal; `chunked_hex` adds line feeds after 64-character chunks with no trailing line feed. Both decode exactly to the source bytes, and result metadata records the selected representation, source and output digests and sizes, and equivalence verification. This is transparent reversible comparison material, not a bypass, evasion, or control-impairment primitive.

Fixture create writes 1..100 canonical JSONL records whose exact fields are `record_id`, `synthetic`, `template`, and `value`. Transform rejects extra, missing, out-of-order, or unrecognized values before writing. With `redact_values: true`, every accepted record's `value` becomes the fixed public string `synthetic-redacted`; with `false`, accepted values remain unchanged.

List and metadata receive only the exact bound fixture path and each return exactly one regular-file metadata entry. Neither action accepts a count limit, enumerates the fixture's directory, or hashes or otherwise opens file content. Collection receives exactly one such bound input, validates its complete JSONL record set and limits before creating `staged/bundle.jsonl` or `staged/bundle.json`, and reports one accepted input, zero rejected inputs, the preserved record count, digest, size, and `complete: true`. There is no nested `staged` result object and no partial bundle on an input error.

Export maps `ephemeral` and `review` to separate fixed runner-owned paths. Both outputs are temporary, receipt-owned local copies; `review` is a policy classification, not a promise that the copy survives the scenario. Normal `always` cleanup deletes either label.

## Results and partial work

`ActionOutcome` carries status, typed output, bounded stdout/stderr summaries, receipt IDs, optional cleanup report, structured error, and limitations. Valid statuses are:

- `success`
- `failed`
- `partial`
- `refused`
- `control_blocked`
- `timed_out`
- `cleanup_failed`

If an action creates any owned object before a partial result, it must return the corresponding committed receipt. The control plane authenticates its exact schema, bounds, request/action/profile/workspace binding, filename digest, and commit before treating a successful, partial, or timed-out mutation as cleanup-owned. A valid intent without a commit remains available only for failed or cancelled recovery. Never convert partial or timeout into success to simplify graph routing. Cleanup's `output` and `cleanup` fields carry the same authoritative report, including whether verification ran and counts for verified removed paths, verified absent paths, and removed receipts.

## Adding an action

An action is complete only when all layers agree:

1. Choose a narrow neutral behavior and stable versioned IDs.
2. Define logical inputs, outputs, parameters, capabilities, tier, effects, cleanup, provenance, observables, and limitations.
3. Implement a compiled Rust parameter type with `deny_unknown_fields`.
4. Add a complete static descriptor and action implementation.
5. Enforce every path, destination, count, byte, output, and time bound inside the runner.
6. Emit receipts immediately for create-new effects and preserve them on partial outcomes.
7. Add one explicit Python adapter from logical artifacts/parameters to executor parameters. Do not add a reflective fallback.
8. Add an honest deterministic simulation transition or mark simulation unavailable.
9. Register the action in a least-privilege profile and at least one real scenario.
10. Add Rust boundary tests, Python registry/adapter/simulation tests, refusal tests, cleanup tests, and an opt-in disposable Execute test where safe.
11. Update inventory, docs, and provenance.

## Required negative tests

At minimum, test refusal for:

- unknown action or field;
- wrong behavior/platform/tier/capability;
- action not enabled or explicitly blocked;
- missing/expired/mismatched approval;
- expanded target scope;
- absolute, traversal, device, symlink, or reparse path;
- zero or excessive limits;
- output/artifact/file/depth overflow;
- cleanup of a caller path, altered object, or forged receipt;
- any legacy helper or generic command path.

## Prohibited interfaces

Do not add a generic `command`, `shell`, `script`, `payload`, `interpreter`, `binary`, `url`, `hostname`, `proxy`, `redirect`, dynamic-library, or arbitrary plugin executor. A new capability must be a reviewed, typed, versioned action with an explicit effect and cleanup model.
