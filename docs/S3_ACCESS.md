# S3 Access Hardening

## Outcome

The scoped workflow will test whether a dedicated same-account probe role can read
one generated S3 object, remove its single experiment-owned bucket-policy Allow,
then freshly test that same object while a separate legitimate role still reads
both the primary object and a generated health object. Independent audit evidence,
cleanup and guarded explicit rollback are separate obligations.

## Implementation Status

The pure contract/policy planner and an unregistered SDK-worker component are
implemented. The planner accepts no credential values. The worker is tested with
deterministic fake clients/streams and a pinned official SDK using inert transport;
it has no executable entrypoint,
runtime loader, secret channel or registered action. No AWS calls have been made.
Neither component grants authority or establishes enrollment, effective access
or prevention.
The supervised native executor, durable operation/control workflow, audit collector,
composition integration, workspace UI and authorized installed proof remain required.

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
The future executor needs exclusive resource ownership, serialized writers and
ambiguous-response reconciliation before it can safely use the proposed change.

Removing this statement does not rule out identity policies, session policies,
permissions boundaries, SCPs or other access routes. There is no IAM simulator or
effective-access-success claim. Fresh scoped reads and separately correlated audit
observations remain necessary. Existing approvals do not authorize this workflow.

## Worker Component

`S3WorkerRequest.from_mapping` revalidates the complete scope, exact policy change,
runtime/launch/generation bindings, operation deadline and send allowance. Supported
operations are only policy inspection, apply, rollback, probe read and legitimate
read. Writes require an exclusive-writer receipt digest; validating that digest's
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
seams are not an attested production loader. Selecting and verifying a fixed SDK,
Python, dependency/service-model and CA tree is still an explicit execution blocker.
That loader must also isolate configuration and imports, prevent all ambient
credential/auth-token resolution, and disable SDK/history/debug secret logging.
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

The next implementation work is the typed native authority/runtime boundary,
durable reservation/reconciliation, supervised execution, generated-fixture and
audit lifecycle, then one usable saved workspace workflow and authorized retesting.
This component is not a completed cloud phase.

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
