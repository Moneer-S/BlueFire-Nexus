# Owned user-service lifecycle prerequisite

Status: internal contract and deterministic software tests. No systemd method,
observer, setup control, profile capability or execution path is registered by this
change. It does not establish service execution, persistence, cleanup or detection
coverage on any platform.

The next proposed endpoint method creates, enables and starts a reviewed user
service, then stops, disables and removes its owned resources. A user manager can
keep a service alive after its invoking process exits. The existing tool-adapter
v1 process-tree and workspace cleanup contract cannot cover that lifetime.

## Identity and observation

`bluefire.tool_adapters.service_lifecycle` defines an immutable
`bluefire.owned-user-service.v1` identity. It binds the reviewed authorization,
runner profile, workspace, target-scope digest, non-root UID, boot, manager
invocation, fresh unit nonce, exact unit-content digest and cleanup deadline.
The unit name is derived from the nonce; no path, command, payload or arbitrary
unit name is accepted. The one-hour identity ceiling is a schema maximum, not
permission to execute for that duration.

The trusted adapter must reserve the nonce and prove that the unit and its install
links were initially absent before recording an intent or causing effects. It must
not overwrite or adopt an existing service. An identity digest is neither a
signature nor proof of ownership. Deserialized data cannot grant authority.

Cleanup assessment requires an intact, independently observed evidence record from
the designated future service observer, with matching identity, profile and target.
The observation must follow the cleanup request, not be in the future, and be at
most five seconds old at evaluation. The assessment retains the evidence ID and
record hash. It never substitutes an action's exit status for an observation.

| Assessment | Required interpretation |
| --- | --- |
| `verified_absent` | The available manager reports the unit absent and inactive; the unit file and enable links are absent; the entire owned cgroup is empty. |
| `residue` | At least one of those independently inspected resources remains. |
| `unknown` | Evidence is missing, malformed, stale, incomplete, or from the wrong kind of producer. Manager unavailability cannot prove absence. |
| `identity_mismatch` | Owner, boot, manager, unit, profile, target or resource identity changed. Do not automatically act on that resource. |

Expiry does not prevent assessment of later cleanup: overdue resources still need
reconciliation. This is a read-only assessment contract, not a permission check or
cleanup dispatcher. Hash verification protects recorded consistency; the eventual
collector integration must establish source authenticity and actual observations.
The observer ID is reserved here and is not advertised as an available collector.

## Required integration before admission

A concrete adapter must still supply the fixed unit contents and executable
identity, sanitized unit environment, manager and cgroup readiness, trusted
installation binding, resource-specific target/capability review, pre-effect
rechecks, and a durable intent/receipt protocol. Start, enable, stop, disable,
removal and manager reload require separate truthful outcomes and interruption
reconciliation. Stop must cover the owned cgroup, not only a remembered PID.
Removal must verify exact file/link identities and never remove unrelated units.
Unexpected manager replacement or changed resources must surface for recovery.

The independent observer must query manager state and inspect the actual owned
filesystem and cgroup resources within a stable collection window. An adapter
cannot declare those resources absent from its own success result. These required
checks are not implemented by the identity parser or its authored fixtures.

Admission must use a reviewed contract beyond v1's workspace/process-tree policy.
Legacy exact-plan approvals and installed profiles gain no user-service authority.
No lingering change, host policy change or elevated system-wide service is included.
Live validation requires its own reviewed disposable environment and authorization.

## Upstream relationship and limits

The selected upstream reference is Atomic Red Team's system-wide **Create Systemd
Service**, T1543.002 test `d9e4f24f-aa67-4c6e-bcbf-85622b697a7c`, at commit
[`6132b92779873cb0d05bef07ba0a480d47eb1cc8`](https://github.com/redcanaryco/atomic-red-team/blob/6132b92779873cb0d05bef07ba0a480d47eb1cc8/atomics/T1543.002/T1543.002.yaml).
The exact YAML is 7,925 bytes with SHA-256
`eba68d4d167136669371009508d097c547d1ec1142feb0f0a2bc8ce0475b8a53`.
That test requires elevation and accepts free-form unit paths and Exec actions.
Those inputs and its shell/recursive removal commands are not admitted here.
A future user-service method is an explicitly constrained adaptation, not execution
of that system-wide test unchanged. No user-level Atomic test exists at this pin.

The pinned Atomic license is MIT; the existing Red Canary notice is retained.
Systemd and any separately installed payload utility have their own terms and must
be reviewed before adoption or redistribution. No dependency is installed, bundled
or made required by this prerequisite. BlueFire's license remains MIT.

Rollback removes this unused prerequisite without changing existing receipts or
execution. Once an adapter is admitted, its own rollback must retain the ability
to reconcile any outstanding owned resources.
