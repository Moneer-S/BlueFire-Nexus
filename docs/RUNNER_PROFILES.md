# Runner profiles

A runner profile is the maximum authority available to one Simulate or Execute environment. A scenario does not grant authority, and an operator request can narrow—but never expand—the profile.

## Profile fields

| Field | Meaning |
|---|---|
| `id` | Stable versioned profile ID |
| `mode` | Exactly `simulate` or `execute` |
| `environment_type` | `disposable`, `persistent_lab`, `cloud_lab`, or `custom` |
| `platforms` | Allowed `windows`, `linux`, and/or `macos` platform identifiers |
| `runner_binary` | Declarative environment-variable reference retained for an explicit source-development/custom transport override |
| `sandbox_root` | Declarative environment-variable reference for an explicit operator-owned disposable sandbox override |
| `scope` | Named maximum scope references |
| `network_allowlist` | Canonical CIDR networks with explicit prefixes |
| `capabilities` | Granted semantic and effect capabilities |
| `safety_tiers` | Allowed `safe`, `controlled`, and/or `restricted` tiers |
| `approval_required` | Must be `true` for Execute profiles |
| `enabled_actions` | Exact action allowlist; empty for Simulate |
| `blocked_actions` | Explicit control blocks; wins over the allowlist |
| `cleanup_policy` | `always`, `on_success`, or `manual` |
| `budgets` | Positive step, time, artifact-count, and byte maxima |
| `secrets` | Named environment-variable references only |

Unknown fields, duplicate values, non-canonical networks, invalid environment names, and an Execute profile without approval are rejected.

For the default managed lifecycle, these fields do not let a scenario or browser select a process path. `runner bootstrap` chooses the exact verified packaged artifact (or an operator-set source-development override), records its digest and inventory, and uses an owner-private managed sandbox unless the reviewed sandbox override is present. `runner start` then launches that exact bootstrap record and binds the selected profile through local enrollment and authenticated transport. Status and profile probes never bootstrap or start a process.

## Shipped profiles

`config/bluefire.example.yaml` contains:

- `sandbox-simulate.v1`: default, no enabled runner actions, no approval;
- `sandbox-execute.v1`: the twelve safe/controlled built-in actions, loopback plus local export, mandatory approval and cleanup;
- `sandbox-blocked-network.v1`: the same safe/controlled Execute inventory, with `sandbox.network.loopback.v1` explicitly control-blocked to exercise the registered local fallback;
- `sandbox-restricted-owned.v1`: only the fixed-path restricted persistence-detection canary and cleanup, no network scope, and mandatory exact approval.

These are demonstration profiles. Copy and narrow one for a specific authorized lab; do not treat an example as organizational authorization.

## Least-privilege example

```yaml
- id: discovery-only.execute.v1
  mode: execute
  environment_type: disposable
  platforms: [linux]
  runner_binary: {env: BLUEFIRE_RUNNER_BINARY}
  sandbox_root: {env: BLUEFIRE_SANDBOX_ROOT}
  scope: [sandbox.workspace]
  network_allowlist: []
  capabilities:
    - endpoint.discovery
    - system.discovery
    - process.discovery
    - process.spawn
  safety_tiers: [safe]
  approval_required: true
  enabled_actions:
    - endpoint.discovery.system.v1
    - endpoint.discovery.processes.v1
  blocked_actions: []
  cleanup_policy: always
  budgets:
    max_steps: 4
    max_seconds: 20
    max_artifacts: 20
    max_bytes: 1048576
  secrets: {}
```

This example supports only the two discovery actions. `process.spawn` is required for the fixed Linux/macOS `ps` adapter; it does not grant a generic process action.

## Scope model

The control plane accepts named scope references:

- `sandbox.workspace`: runner-owned relative filesystem paths;
- `network.loopback`: literal loopback destination used by the fixed transport action;
- `export.local`: sandbox-contained local export path.

The restricted canary still uses only `sandbox.workspace`. Its semantic `sandbox.restricted` capability selects a reviewed action tier; it does not grant a broader filesystem scope.

The selected action adapter derives its required references. Execute requires an explicit operator scope whose set contains those references and is a subset of the profile. Missing scope creates a visible `target_scope_refused` policy/control record and prevents runner dispatch for that action.

Runner manifests translate named scope into concrete executor scope:

- normalized relative filesystem prefixes;
- exact `{host, port}` network destinations.

The Rust runner checks those concrete values against its separately sealed profile.

## Capability and tier model

An action must satisfy all of these intersections:

1. action ID is enabled and not blocked;
2. behavior permits the action;
3. action/profile/current platform intersect;
4. all behavior/action/effect capabilities are granted;
5. both behavior and action tiers are allowed;
6. requested scope is contained;
7. limits do not exceed the profile;
8. cleanup and approval requirements are met.

A profile should grant only capabilities required by its enabled actions. A broad capability string does not make an unregistered action executable.

## Cleanup policy

The control plane currently refuses an Execute plan containing mutating actions unless the profile uses `always`, enables `sandbox.cleanup.v1`, does not block cleanup, and the graph includes cleanup. `on_success` and `manual` remain valid schema values for non-mutating or future workflows but are not adequate for the shipped mutating Execute scenarios.

## Approval

Every shipped Execute profile requires approval. The runtime approval record is short-lived and bound to:

- normalized request hash;
- action ID;
- runner profile ID;
- target-scope digest;
- issue and expiry timestamps.

Changing a parameter, binding, action, profile, or scope invalidates the previous binding. The CLI's `--approved-by` value is an audit label, not authenticated identity.

## Review checklist

- Is the environment owned/authorized and accurately labeled?
- Are all platforms necessary?
- Is every enabled action used and reviewed?
- Does `blocked_actions` encode the intended control test?
- Are capabilities exactly those advertised by enabled actions?
- Are tiers no higher than required?
- Are scope and CIDRs minimal? (The shipped network action needs loopback only.)
- Are budgets small enough for the experiment?
- Is cleanup always enabled for mutations?
- Are secret values absent and only environment references present?
- Did runner inventory and Execute preflight pass on the intended host?
