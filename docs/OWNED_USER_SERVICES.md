# Owned user-service lifecycle prerequisite

Status: internal identity, authorization, durable reservation/recovery and software
tests. The fixed service action is unavailable: it is not registered in the catalog
or ordinary runner action registry, and native dispatch refuses it. There is no
service observer or setup control. These prerequisites do not establish service
execution, persistence, cleanup or detection coverage on any platform.

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
the designated future service observer, with full confidence (1.0) and matching
identity, profile and target. Lower confidence cannot prove cleanup.
The observation must follow the cleanup request, not be in the future, and be at
most five seconds old at evaluation. The assessment retains the evidence ID and
record hash for intact records within the assessment's size bound, including
records rejected for producer, confidence, time or shape. Missing, oversized or
integrity-invalid input supplies no trusted reference. It never substitutes an
action's exit status for an observation.

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

## Authorization and resource lifetime

The separate `bluefire.owned-user-service-scope.v1` contract defines the experiment
before approval is consumed. It binds the exact scenario and step, fixed action,
profile policy, target, workspace, non-root UID, boot and user-manager instance.
It also binds both reviewed installations, generated unit identity, fixed template
and rendered content, setup/cleanup operations, parameters and resource ceilings.
This is additional authority; a legacy exact-plan approval cannot acquire it by
adding a scope after approval.

The only payload is a fixed BlueFire workload that waits once for 1–120 seconds.
It accepts no command, script or extra arguments and creates no files, sockets or
child processes. Its successful exit is not evidence that a service ran or that
cleanup succeeded. The unit's memory limit uses the selected parameter, which
cannot exceed the reviewed ceiling. Each operation's manifest timeout must fit
its reviewed setup or cleanup limit even when the runner profile permits longer.

Setup authority expires within five minutes of scope creation. Cleanup has a
separate reviewed deadline within the existing one-hour identity ceiling. After
setup expires, only receipt-owned cleanup for that same identity may proceed
within its cleanup window. The approval must have been valid when claimed; this
does not renew it, authorize another unit or allow new setup. Expired cleanup
authority leaves an unresolved obligation requiring a new reviewed recovery
decision, never a claim of successful removal.

`bluefire.owned-user-service-grant.v1` ties that scope to the coordinator's consumed
approval, exact execution manifest/profile/task, and committed pending journal
binding. The authenticated transport covers the complete grant-bearing payload;
the manifest/profile task identifier retains its existing meaning. Ledger replay
must validate both bindings and cannot drop a grant or reinterpret a legacy task
as a service request. Deserializing a grant is not issuer authentication.

Orchestration obtains the pending binding from its configured
`ServiceIntentJournal`, rather than accepting a binding from a run request. It
captures the committed record before claiming approval and rechecks the same
revision and full binding immediately before grant creation and dispatch.
Missing, completed, replaced or advanced records refuse dispatch; a correctly
formatted invented binding is not journal authority.

The protected host-to-watchdog-to-native launch boundary has an additional
provenance requirement: expected code identity must be pinned independently of
the supplied context, and the trusted watchdog must revalidate the configured
host's actual enrollment. A self-signed document, even in sealed descriptors,
cannot establish that authority. The configured account and installed trusted
code remain trust anchors; this is not a defense against that account replacing
its own software or a privileged attacker. The native source pin covers the
watchdog entrypoint, not its entire Python import closure; those imported modules
remain trusted installed software. Full installation-backed admission
and the effect adapter remain prerequisites to enabling this action.

On Linux, a watchdog launched from an application virtual environment retains
that environment for enrollment validation. Its argument identity comes from
the active application interpreter, while the actual executable remains the
verified inherited descriptor. The virtual environment configuration and
identity are checked before launch and again at readiness; ambient Python
launcher and module-path variables are not inherited. These checks preserve the
trusted installed dependency context, not independent authentication of every
imported package.

## Durable coordination and admission prerequisites

### Durable intent and recovery

`ServiceIntentJournal` in `bluefire.tool_adapters.service_journal` persists a
bounded history in a private SQLite database. Its location is trusted setup
configuration, never an action or model parameter. A reservation binds one request
to the exact immutable identity and reserves its generated unit nonce within that
database. Reusing the nonce with a different authorization, workspace, manager or
request is refused, including after cleanup. All coordinators for that resource
scope must use the same journal; separate databases do not provide a shared lock.

Before an effect, the future coordinator records its intent with an expected
revision. The transaction commits before returning. Only one unresolved operation
is permitted; a stale competing revision is refused. A restart preserves the
pending operation as `inspection_required`. It never automatically repeats a
start or assumes that an unrecorded result means nothing happened. A coordinator
must inspect the owned resource and record the known or unknown result before
continuing.

Setup advances through creation, reload, enablement and start once each. A failed
or unknown setup result permits only cleanup. Cleanup progresses through stop,
disablement, owned-link removal, owned-unit removal and reload; a failed or unknown
cleanup stage may be retried, preserving its previous result. The entire history
is capped at 32 operations. Exhaustion retains `cleanup_required` and needs explicit
reconciliation; it does not claim the resource was removed or permit an unrecorded
effect. Successful cleanup reaches `verification_required`, never `verified_absent`.
Only fresh independent observations can establish absence through the assessment
contract above.

The journal records metadata and invokes no service or process. Its canonical
record hash detects inconsistent storage, not forgery by someone who controls the
database. Schema, identity, revision, operation order and database key bindings
are checked on every read. Setup must supply an existing owner-private parent.
POSIX admission requires the current owner, directory mode 0700 and file mode
0600; macOS additionally rejects extended ACLs and ownership-ignoring mounts.
Windows admission verifies the native protected owner-only DACL, including
inheritance on the parent; chmod is not a Windows privacy guarantee. Existing
shared storage is refused without permission repair or database writes. A new
file is exclusively created with private permissions before SQLite opens it.

Every transaction pins the parent, leases the exact database identity, and
rechecks ownership and privacy before commit. Links, reparse points and hardlinked
databases are refused. Because SQLite opens a pathname, POSIX admission also checks
the full ancestor chain before creating or opening storage: ancestors must belong
to the coordinator or root, and group/other-writable directories must enforce
sticky entry protection. This prevents another unprivileged owner from replacing
the private parent through an otherwise writable ancestor. The same checks run on
subsequent access without repairing permissions. These checks and cooperative locks do not defend against
a malicious process with the same owner credentials, privileged path swaps or
rollback to an older valid private database. Reopening never proves provenance
or recovers evidence already exposed by earlier permissive permissions.

Reservation does not prove initial absence, current ownership, readiness or
permission. Approval expiry does not prevent recording results or inspecting
cleanup history; it also gains no extension from a journal entry. The Rust effect
boundary must still enforce exact authority and identity before each operation,
and bind its resource receipts to these persisted intents before this can become
an executable method. The journal is not registered in a product execution path.

### Pending-operation handoff

`ServiceIntentJournal.pending_binding` captures the current committed pending
operation under the journal's existing private transaction. It requires the
expected revision and refuses empty, completed, stale or corrupt history. Its
`bluefire.service-operation-binding.v1` document binds the immutable service
identity, request and operation IDs, odd pending revision, and exact stored
document hash. The derived `recovery_state` presentation field is not part of
that stored hash. Capturing the binding does not change history or resolve an
interrupted operation.

The handoff also includes explicit reviewed-scope, manager-installation and
payload-installation digests supplied by the future reviewed setup. Changing
any pin changes the canonical binding digest. Python and Rust validate the same
closed, bounded UTF-8 document; authored shared vectors cover both parsers.
Unknown fields, duplicate JSON keys, malformed identities, completed revisions
and unregistered operation names are refused. The Rust decoder supplies validated
consistency metadata to protected admission and reservation layers. By itself it
adds no command, action, profile authority or execution permission.

Neither the journal hash nor successful decoding authenticates an approval,
installation or current resource. The opaque scope digest is not a wildcard or
a substitute for the explicit service-scope contract. Before any effect,
the runner still must authenticate that reviewed scope, resolve both protected
installations, recheck the live manager/resource identity, and durably reserve an
effect receipt bound to the exact handoff. The coordinator transaction does not
hold an effect lock across transport or provide runner replay protection.

A reopened pending operation remains `inspection_required` even when its handoff
can be reconstructed. Historical bindings remain readable after completion or
expiry and cannot release an effect. The existing nine journal operation names
retain their v1 semantics; changing setup or cleanup order requires a new protocol,
not reinterpretation of old records. Actual service observation, cancellation,
cleanup and reconciliation remain required integration work.

### Native reservation and interruption

The native reservation store uses a trusted enrollment-owned location, never a
path supplied by a task. It pins owner-private directories, files and lock
identities, rejects unsafe links or replacements, and retains an append-only,
bounded history with durable writes. Within that stable enrollment, the resource
key includes UID and unit nonce; changing the boot or manager cannot bypass an
unresolved reservation for the same unit.

A new reservation provides a single dispatch permit. An identical repeated
request returns the retained record without a new permit; changed contents or an
uncertain earlier operation are refused. Process success, failure and unknown
outcomes do not resolve uncertainty. A separate trusted observation is required
before progression or retry. Completed identities remain reserved, and storage
exhaustion refuses new work without evicting cleanup obligations. Hashes detect
inconsistency, not same-account forgery or restoration of an older filesystem.

These are software contracts, not proof of manager state. The production observer
and effect path are still unavailable. Ordinary library dispatch explicitly
refuses the fixed action and aliases that try to reach it, so adding a catalog
entry cannot silently bypass protected admission.

### Remaining runtime and observation work

A concrete adapter must still connect the fixed unit and protected executable to
sanitized unit environment, observed manager and cgroup readiness, resource-specific
target/capability review, pre-effect rechecks, and the durable intent/reservation
protocol. Unit directives alone do not prove that an unprivileged manager can
enforce the requested namespaces or resource limits. Start, enable, stop, disable,
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
The upstream [systemctl v255.4 source](https://github.com/systemd/systemd-stable/blob/v255.4/src/systemctl/systemctl.c)
identifies its license as LGPL-2.1-or-later. The proposed integration invokes a
separately installed executable; it does not copy, link or bundle systemd code.
Each admitted distribution build still requires exact provenance, readiness and
license review. No systemd dependency is installed or made required by this
prerequisite. The fixed payload is BlueFire code, and BlueFire's license remains MIT.

Rollback removes this unused prerequisite without changing existing receipts or
execution. Once an adapter is admitted, its own rollback must retain the ability
to reconcile any outstanding owned resources.
