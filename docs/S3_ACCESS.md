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
installed workflow. Fixture/audit lifecycle and broader composition integration
remain required. The cloud phase is not complete.

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
operations are only policy inspection, read-only reconciliation, apply, rollback,
probe read and legitimate read. Writes require an exclusive-writer receipt digest;
validating that digest's
syntax is not verification of exclusive ownership. Fixture creation/deletion and
audit collection are not silently added to this contract.

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
