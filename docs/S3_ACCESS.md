# S3 Access Hardening

## Outcome

The scoped workflow will test whether a dedicated same-account probe role can read
one generated S3 object, remove its single experiment-owned bucket-policy Allow,
then freshly test that same object while a separate legitimate role still reads
both the primary object and a generated health object. Independent audit evidence,
cleanup and guarded explicit rollback are separate obligations.

## Implementation Status

The contract/policy planner, fixed worker entrypoint and protected-runtime loader,
authenticated host integration, native supervision and durable send ledger are
implemented in source. A saved operation uses the existing jobs, runs and evidence
stores. The planner accepts no credential values. Deterministic fake tests and a
pinned official SDK with inert transport exercise the component boundaries; native
validation and installed workflow verification are separate gates.

No AWS calls have been made, and no cloud capability or runtime is automatically
enrolled. Missing protected installation or host authority leaves execution
unavailable. These components do not establish effective access or prevention.
Original-result recovery is implemented in the coordinator for an already-finalized
authenticated task; installed recovery proof remains separate. One protected Linux
interpreter prefix reached the actual fixed entry's Ready/EOF boundary offline,
without a containment ACK, credentials or cloud calls. That historical component
proof is not verification of the current integrated package or an authorized
installed workflow. The explicit v2 fixture lifecycle is implemented in source
with synthetic contract, SDK and saved-store tests; its fresh native, official-SDK
and installed validation remain separate gates. Audit collection and broader
composition integration remain required. The cloud phase is not complete.

`S3AccessScope.from_mapping` validates an immutable structural scope with one
commercial-partition account/region, three distinct same-account roles without
role paths, one general-purpose bucket, one scope-derived generated prefix and
exactly two digest/size-bound objects. Object bytes are bounded collectively.
The scope includes an ownership-receipt digest, exact baseline policy digest,
scope-owned statement IDs, bounded counters/time allowances and timezone-aware
expiry. These digests identify proposed inputs, not verified ownership or approval.
`assert_current(clock=...)` explicitly checks the current interval using an injected
timezone-aware clock. Parsing a historical scope does not require it to be current.

The region is an exact input, not a wildcard or a lookup into a global current
region list. Only the supported commercial naming grammar and standard regional
S3/STS plus global IAM hostname forms are derived. This is not a statement that a
region, service or account is available or enabled. Enrollment must verify that
separately and fail unavailable without fallback. GovCloud, China, custom endpoints,
FIPS, dual-stack, access points and directory buckets are not supported here.

## Owner-Local Setup

The S3 workspace now includes a profile-specific connection panel. Listing profiles
does not contact a host. An explicit connection check uses the existing authenticated
runner transport, verifies the saved profile and transport identity before and after
inspection, and reports missing, incomplete, invalid or configured local state.
Runtime integrity, protected-reference expiry and scope time are separate fields;
AWS access remains untested. Existing runner start, diagnostics, enrollment recovery
and upgrade controls remain explicit and do not submit an experiment.

Runner Profiles offers an `S3 access - Linux` starting configuration, including in
an empty catalog. Saving creates an inactive durable draft through the existing
resource lifecycle; explicit validation and activation remain separate. Managed
S3 profiles must be dedicated Linux cloud-lab envelopes with required approval,
no ordinary action methods, no network-target extensions and no credential or
native-tool bindings. The reserved S3 method is not added to the ordinary action
catalog. Their step budget must cover every fixed reviewed stage, currently at
least two worker tasks. Activation alone does not enroll a host or grant AWS access.

The configuration draft panel accepts at most 128 KiB of nonsecret configuration
JSON. Review is structural only: it neither reads a referenced local path nor
connects to a runner or AWS. It reuses the exact host-configuration, scope and
policy validators. Browser intake additionally requires a dedicated S3-only native
profile, the selected active saved profile, no network target extensions, finite
standard sandbox targets and limits exactly matching that saved profile. Unknown fields,
credential material, unrelated native integrations and implicit fixture upgrades
are refused. This narrower intake does not relax the owner-local or native checks.

New product drafts use `bluefire.s3-host-environments.v3`. Each environment includes
`managed_profile_digest`, copied from the selected profile's `profile_digest` in
`GET /s3-access/setup`. This is the canonical content hash of the complete
managed profile's `to_dict()` document, not its narrower sealed native policy.
The existing native `profile` document and its seal remain unchanged. The optional
`fixture_lifecycle` descriptor is still required for fixture operations; a v3
configuration without it does not gain fixture authority. Review preserves the
exact source and never inserts or refreshes the digest implicitly.

The protected host configuration retains this digest through installation and
authenticated discovery. Setup and every new dispatch compare it with the current
active profile, including fields absent from native execution limits. A changed
same-ID profile requires separately reviewed authority. Legacy v1/v2 configuration
and historical original-task results remain readable, but legacy discovery reports
`profile_changed` and cannot authorize new product execution. An older host response
without the binding is refused. No automatic migration or in-place authority
replacement is provided; existing retained configurations still require the separate
history review described below. Recovery never converts an old result into a new task.

An export contains exactly the reviewed source bytes, bound to their SHA-256 and
the selected saved profile digest. Editing the draft or selecting a changed profile
invalidates its displayed review and export. Failed checks and late responses do
not replace the current draft. Draft input is browser-memory state, not a durable
configuration store or installation receipt. Full guided authoring from an empty
scope, protected-runtime deployment and fresh installed/cloud verification remain
separate requirements.

Setup uses an existing enrolled, non-root Linux host and its selected cloud-capable
profile. It does not create trust, install a runtime, acquire AWS credentials, start
a worker or extend the approved scope. The fixed managed enrollment must already
be valid, owner-private and active. Unsafe permissions are refused without repair.

The local commands are:

```text
bluefire s3 status --profile PROFILE
bluefire s3 configure review --profile PROFILE --draft CONFIGURATION_JSON
bluefire s3 configure apply --profile PROFILE --draft CONFIGURATION_JSON --review REVIEW_JSON
bluefire s3 credentials set --profile PROFILE --environment ENVIRONMENT --expected-revision REVISION_DIGEST --stdin
bluefire s3 reconcile --profile PROFILE [--record-digest RECORD_DIGEST]
bluefire s3 reconcile --profile PROFILE --record-digest RECORD_DIGEST --complete
```

The draft is the exact versioned host configuration described here, including the
installed protected runtime and sealed profile. The review result is valid for at
most two minutes and binds the configuration, enrollment generation and current
revision. Applying the same configuration again is idempotent; changing retained
authority is not an implicit update. Configuration and protected references live
in a separate authenticated, append-only `s3-access` directory, not inside the TLS
material directory. History is bounded to 32 revisions.

Temporary material must already have been deliberately acquired for the approved
scope. Import accepts a bounded noninteractive standard-input document using the
existing temporary-material schema. There are no credential arguments, environment
variable lookup, browser upload or ambient provider-chain fallback. Import protects
the material under its exact generation/environment/scope purpose and checks the
expected revision. It neither resets execution allowances nor extends expiry.

Status reads protected-reference metadata without decrypting cloud material. Its
`local_reference_metadata_only` scope is deliberate: a current reference does not
prove AWS accepted it, that roles are reachable, or that an access outcome occurred.
Authenticated discovery now keeps an environment visible but unavailable when its
reference is absent or expired. The workspace reports that prerequisite separately
from an unavailable runtime. Actual dispatch still validates the request deadline,
runtime, scope and supplied credentials independently.

Reconciliation checks the given original record digest without replaying a write.
When a lost response leaves that digest unknown, omit `--record-digest` to inspect
the authenticated pending or latest record's digest, operation and sequence only.
An empty store reports `not_found` without creating storage. Inspection neither
decrypts protected references nor publishes a pending record.
To finish an interrupted local publication, explicitly pass `--complete` with the
inspected digest. Completion authenticates the original pending record against
the current enrollment and revision chain, then publishes those exact bytes. It
does not acquire, decrypt or replace credentials, append another revision, renew
expiry, refund execution allowances or contact AWS. A repeated completion of the
current record reports `already_committed`. A changed digest, unsafe file, changed
enrollment or unexpected record requires inspection; it is never silently removed.
Publication uses atomic non-replacing rename, including the pending writer claim,
so a crash cannot leave a two-link record. Files retained from older development
versions with unexpected links or staging entries still fail closed and are not
automatically adopted. No credential data appears in the result. This source
implementation has local storage, authenticated loopback and workspace regression
coverage. A native Linux filesystem probe verified atomic claims, destination
collision refusal, unsupported-operation refusal and post-publication interruption
with generated files and verified cleanup. That component check is not proof of
configured cloud setup. Native Linux setup, integrated installed onboarding and
live cloud verification remain separate requirements.

## Supported Policy Language

Policies must use version `2012-10-17`, a list of 1-32 statements, and no additional
top-level fields. Each statement has exactly `Sid`, `Effect`, `Principal`, `Action`
and `Resource`. SIDs are unique ASCII alphanumeric identities. Principals are one
exact same-account IAM role ARN. Actions are exactly `s3:GetObject`, as a string or
single-item list. Resources are one or both exact approved object ARNs, as a string
or a duplicate-free list. No condition, wildcard, variable, `Not*`, public principal,
account-root principal, service principal, assumed-role session or controller grant
is accepted. Overlapping role/resource routes are rejected even under different SIDs.

The owned probe Allow must cover only the primary object. The owned legitimate
Allow must cover both primary and health objects. Other supported statements may
Allow or Deny other exact roles and are retained structurally, including list shape
and statement order. This narrow language intentionally refuses more complex
policies instead of interpreting or rewriting them. JSON formatting and object-key
order are not preserved; all statement fields, values and array order are preserved.

`plan_hardening(scope, baseline)` checks the bound baseline digest and removes only
the exact owned probe statement. Its immutable result retains both complete policy
snapshots and digests plus the scope digest. `S3PolicyChange.from_mapping` recomputes
that exact change when loading saved review material.
`verify_readback(scope, change, observed)` requires the exact complete postimage.
`plan_rollback(scope, change, current)` returns the original complete policy only
while that postimage still matches. Unrelated changes cause refusal, not a merge.
These are structural preimage/readback checks, not an atomic remote compare-and-swap.
The native ledger serializes the configured bucket authority; duplicate bucket
authorities are refused within host configuration and visible authenticated hosts.
This is not a distributed lock. Exclusive resource ownership against external
controllers and ambiguous-response reconciliation remain explicit requirements.

Removing this statement does not rule out identity policies, session policies,
permissions boundaries, SCPs or other access routes. There is no IAM simulator or
effective-access-success claim. Fresh scoped reads and separately correlated audit
observations remain necessary. Existing approvals do not authorize this workflow.

## Worker Component

`S3WorkerRequest.from_mapping` revalidates the complete scope, exact policy change,
runtime/launch/generation bindings, operation deadline and send allowance. Supported
v1 operations are only policy inspection, read-only reconciliation, apply, rollback,
probe read and legitimate read. Writes require an exclusive-writer receipt digest;
validating that digest's
syntax is not verification of exclusive ownership. Fixture creation/deletion and
audit collection are not silently added to this contract.

## Explicit Fixture Lifecycle

A newly reviewed v2 enrollment binds the existing scope, enrollment generation,
exclusive-writer receipt and a never-versioned general-purpose bucket without
Object Lock. Existing v1 enrollments cannot acquire fixture operations implicitly.
The two scope-bound payloads are generated canonical JSON for the primary and
health purposes, not arbitrary owner-provided bytes.

Saved Prepare, Reconcile Fixtures and Cleanup stages use the existing jobs, runs,
durable original-result recovery and exact review mechanism. Preparation confirms
absence, creates with `If-None-Match: *`, then verifies size, SHA-256, scope/intent
metadata and ETag. Cleanup verifies the full expected object first and uses the
reviewed `If-Match` ETag, followed by absence and bounded exact-prefix readback.
A known-absent cleanup is read-only. Versioning, Object Lock, foreign keys,
incomplete listings and unsupported object metadata fail closed.

ETag is a conditional content/identity token, not proof against every metadata or
external-writer race. Exclusive ownership remains an explicit deployment premise.
Lost write acknowledgement requires a fresh read-only reconciliation, never write
replay. An accepted conditional-delete reservation remains consumed even when no
send occurs. Bounded recovery allowances protect cleanup and reconciliation;
they are not refunds or automatic retries.

Object receipts retain the last exact observation and its request IDs/provenance.
Failed reads stay in stage history without borrowing old observations. Uncertain
object mutations and process cleanup are distinct. Cleanup may retain either a
settled baseline or accepted hardened policy; it does not imply rollback. An
uncertain or drifted policy must be reconciled first. Cloud audit remains
`not_collected`; synthetic and worker-reported results are not independent audit
evidence. The v2 source and test additions do not enroll a host or authorize AWS
access.

## Saved Imported Audit Reviews

The S3 workspace can save local correlation of supplied CloudTrail JSON or gzip
files against a finalized baseline or retest read. Each review binds the original
workflow, operation, sealed run, request, worker result and outcome digests.
Historical validation does not discover, contact or start an execution host.
Stopped exercises and unavailable runtimes do not prevent reviewing retained runs.

Imports are limited to four files, 512 KiB combined compressed/input bytes and
1 MiB expanded bytes, plus the scope's existing event and byte limits. Incomplete,
concatenated and oversized gzip streams are refused. At most 32 immutable reviews
can be saved per exercise. Source byte digests and minimized event projections are
retained; raw file contents and arbitrary event text are not stored. Repeated saves
with the same submission and input are idempotent; changed input cannot replace a
saved review. The browser retains only a pending identity and input digest. An
uncertain response can be recovered from saved history or retried with the exact
original files. Starting another review removes only the local reminder.

Delivery completeness is operator-reported. Matched, conflicting, missing, unknown,
truncated, awaiting-delivery and worker-unreported outcomes remain distinct.
Imports are `operator_import`, not authenticated collection; synthetic runner
provenance is preserved. Independent collection, full object bytes and effective
access remain unproven. The exercise's `audit: not_collected` field and original
execution grants are unchanged. This feature makes no AWS calls, enrolls no audit
collector, and does not deploy detections or prove a defensive change.

## Fixed Worker

`S3WorkerHandshake` requires a matching ready/containment acknowledgement before
accepting one bounded credential frame. That state machine does not prove isolation
or authenticate its peer. The native supervisor must create the private channel
only after containment and protected-runtime identity are verified. Credentials
must be explicit, short-lived and absent from arguments, environment, logs and
durable results. Python memory erasure is not claimed.

`S3SdkAdapter` verifies the controller's caller account and assumed-role identity.
Each reader operation creates one fresh STS session and verifies the returned
session ARN and role/session ID through that session's own caller identity before
reading. Enrollment must additionally bind role generations and resource ownership.
Every S3 request carries the exact bucket owner, bucket and generated key or policy
resource. Apply and rollback re-read the full preimage immediately before the put,
then require the exact full readback. S3 has no atomic policy preimage condition;
the native exclusive-writer premise and recovery workflow remain required.

The fixed call sequence permits no automatic retry, redirect, extra operation or
alternate endpoint. A pre-send request is validated after SDK serialization, then
requires a matching one-use native permit. The final transport checks that the
permitted request has not changed. The supervisor must durably debit before ACK;
an ACK still counts if the worker expires before sending. An uncertain policy write
returns `reconcile_required`, never an instruction to retry it.

`BotocoreFactory` requires supplied SDK bindings, CA path and runtime assertion;
it does not discover or import an ambient installation. It configures explicit
credentials, regional endpoints, no proxies and one total attempt. These constructor
seams are not themselves production admission. The fixed loader validates a closed
manifest, protected interpreter/stdlib/worker trees, the reviewed SDK payload bytes,
service models and CA file. It isolates configuration and import paths, removes
ambient credential/auth-token resolution and disables SDK/history/debug logging.
An actual compatible protected Linux installation remains an execution prerequisite;
version labels, a manifest digest or fake origin checks do not establish one.
No wire field can select a factory, executable, import or fake test driver.

An explicit offline compatibility suite exercised Botocore `1.43.110` serialization,
signing, response parsing and official HTTP-session behavior against inert
connections. The dedicated five-distribution SDK tree is checked before and after
the suite. Socket creation and network/name-resolution operations are denied before
SDK import; the SDK's import-time IPv6 availability probe is recorded as a blocked
socket-construction attempt. All API responses and credentials are synthetic.
This is component-level compatibility evidence, not an installed-product test,
OS-enforced process/network isolation or admission of that runtime for live use.

The official SDK retains TLS, signing and parsing. Its private transport interface
is wrapped before eager response consumption; every response status has a 64 KiB
application-body bound, deadline checks around bounded reads, and close handling.
Compressed responses and malformed/oversized lengths are refused. Generated object
reads additionally require exact size and SHA-256. Private transport compatibility
must be checked against the selected attested release. TLS/header buffers and total
process memory are not bounded by this wrapper. Read timeouts are capped by the
remaining deadline at client construction; clock checks do not interrupt a blocked
read, so an independent native deadline and process-tree cleanup remain necessary.

Results contain only validated request IDs, HTTP status, allowlisted error codes,
exact observation digests and closed outcome fields. Transport exception messages,
headers, credentials and object bytes are not returned. Missing/invalid request IDs
cannot confirm success. `validate_result` preserves worker-reported provenance and
refuses isolation/effective-access claims. A service `AccessDenied` observation is
not by itself proof of a specific defensive change or an independent audit event.

The offline SDK suite also exercises the fixed loader's real session configuration
with protected-host admission explicitly stubbed. Separately, one protected Linux
prefix passed actual entry Ready/EOF compatibility without an ACK, credentials or
cloud calls. Neither check enrolls a runtime or proves an authorized installed
workflow or the current integrated package.

## Native Consistency Boundary

The Rust binding independently parses the worker's normalized UTC
document, including closed nested scope and policy types. It rejects duplicate
keys, unknown fields, implicit missing nulls, numeric coercions, scope drift and
changes beyond the exact owned policy statement. It uses the existing canonical
JSON hashing implementation and derives the same finite call sequence, resources,
regional hosts, methods and payload digests. A shared synthetic corpus binds the
Python and Rust tests; the opt-in official-SDK tests compare actual safe send
projections with those independently derived expectations.

The STS payload check binds the fixed SDK serializer's exact query-form ordering
and escaping, not a new signing implementation. A serializer change must receive
fresh compatibility review rather than silently accepting a different digest.
The send-preview parser validates one bounded frame and its caller-supplied next
sequence, but cannot issue an acknowledgement or consume authority. These types
are consistency checks only; authority comes from the separately authenticated
managed-host admission and protected fixed-worker deployment.

## Supervised Boundary

The reserved `owned.aws.s3_access.v1` action requires the explicit
`cloud_aws_s3_access` host capability. It cannot run through the ordinary action
registry, and it does not widen ToolAdapter v1 or a loopback capability. The native
supervisor independently binds the reviewed scope, original request, runtime,
deadline and finite call sequence. Credentials travel only through the private
contained worker channel, not arguments, environment or durable evidence.

Reservations and each send debit are recorded durably before the worker receives
a permit. Failed or unsent attempts are not refunded. The ledger counts the probe
read and both legitimate reads, preserves the reviewed retest/rollback budget, and
refuses further operations for an orphaned or unknown-cleanup reservation. An
unlocked lease or parent-death signal is not proof that the worker is absent.

The deployment premise is trusted fixed code on a protected enrolled host, not
isolation from malicious same-UID code. Filesystem metadata and process memory are
not claimed inaccessible to that UID. Before dispatch, a synchronous durable
checkpoint retains the exact original task/hash, sealed request/profile and
authenticated host identity without credential material. Missing or failed
checkpoint persistence refuses dispatch. Recovering an already-finalized original
result uses that same authenticated task without discovering a new environment,
replaying execute, renewing approval expiry or issuing credentials. A changed
enrollment, runner binary or inventory is not accepted as the original host.
Missing, still-running and unavailable results remain unresolved. The enrolled host
must still be authenticated and available through its existing lifecycle client;
this path does not start or enroll a replacement host. Fully orphaned cleanup,
including the spawn-before-durable-
birth-record gap, remains fail closed until actual owned-child absence is proved.
Policy readback and rollback are distinct from process cleanup and independently
correlated audit evidence.

## References

- [AWS policy principals](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html)
- [AWS statement IDs](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_sid.html)
- [S3 PutBucketPolicy](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketPolicy.html)
- [S3 regional endpoints](https://docs.aws.amazon.com/general/latest/gr/s3.html)
- [Regional STS endpoints](https://aws.amazon.com/blogs/security/how-to-use-regional-aws-sts-endpoints/)
- [CloudTrail data events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html)
- [Botocore configuration](https://docs.aws.amazon.com/botocore/latest/reference/config.html)
- [Botocore before-send events](https://docs.aws.amazon.com/botocore/latest/topics/events.html)
- [Official SDK transport source](https://github.com/boto/botocore/blob/develop/botocore/httpsession.py)
- [Official SDK response parsing boundary](https://github.com/boto/botocore/blob/develop/botocore/endpoint.py)
- [STS AssumeRole response](https://docs.aws.amazon.com/boto3/latest/reference/services/sts/client/assume_role.html)

The moving source links explain the integration design; they are not runtime pins.
