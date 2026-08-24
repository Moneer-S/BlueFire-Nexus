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
| `sandbox.fixture.create.v1` | `path`, compiled `content_template` enum | Create one new sandbox file |
| `sandbox.fixture.transform.v1` | `input`, `output`, compiled `transform` enum | Bounded in-process transform |
| `sandbox.discovery.list.v1` | `path`, `max_entries` | Bounded directory list |
| `sandbox.discovery.metadata.v1` | `path` | Metadata and eligible digest |
| `endpoint.discovery.system.v1` | empty object | OS/architecture facts |
| `endpoint.discovery.processes.v1` | `max_entries` | PID/name records through fixed platform adapter |
| `sandbox.discovery.recursive.v1` | `path`, `max_entries`, `max_depth` | Non-link-following subtree inventory |
| `sandbox.archive.tar.v1` | `inputs`, `destination` | Deterministic create-new ustar archive |
| `sandbox.collection.stage.v1` | `inputs`, `destination_directory` | Bounded create-new copies |
| `sandbox.network.loopback.v1` | `artifact`, `destination {host, port}` | Fixed HTTP POST to literal loopback |
| `sandbox.export.local.v1` | `source`, `destination` | Sandbox-local create-new copy |
| `sandbox.restricted.persistence-marker.v1` | `path`, compiled marker bytes | Fixed non-executable persistence-detection canary inside the runner-owned sandbox |
| `sandbox.cleanup.v1` | `receipt_ids` | Revalidated receipt-owned deletion |

The adapter—not scenario input—chooses path conventions, compiled transform/template values, destinations, and receipt IDs.

## Results and partial work

`ActionOutcome` carries status, typed output, bounded stdout/stderr summaries, receipt IDs, optional cleanup report, structured error, and limitations. Valid statuses are:

- `success`
- `failed`
- `partial`
- `refused`
- `control_blocked`
- `timed_out`
- `cleanup_failed`

If an action creates any owned object before a partial result, it must return the corresponding receipt. Never convert partial or timeout into success to simplify graph routing.

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
