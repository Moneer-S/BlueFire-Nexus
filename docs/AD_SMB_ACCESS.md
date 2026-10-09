# AD SMB Access Validation

The AD workspace saves a finite review-and-evidence workflow for one generated
share and two generated files on an explicitly owned Windows member server.
It distinguishes the probe reader from the legitimate reader and preserves
known negative outcomes, including ineffective hardening and broken legitimate
access. A settled counterexample does not prevent reviewing rollback.

## Saved Workflow

The workspace supports inspection, baseline reads, reviewed share-ACL hardening,
fresh retest, exact-preimage rollback, and bounded audit collection as separate
operations. Reviews bind the saved scope, current evidence, implementation and
remaining limits. Jobs and run bundles retain the original task context before
dispatch. Recovery asks only for that original task's stored terminal result;
it does not rediscover a replacement host, resolve new credentials, or replay
the operation. Ambiguous execution, cleanup and partial publication stay
unresolved rather than being presented as successful validation.

Execution is unavailable unless exact prior host enrollment and the separate
admitted receiver configuration are installed and current. The saved workflow is covered
by synthetic executors and real persistence tests; the Windows descriptor,
share, generated-file and fresh-read components have separate bounded native
component tests. Those tests are not live AD or share-access evidence.

## Enrolled Channels

AD control-plane channels are separate from ordinary loopback runner transport
and from the scope's SMB, DNS and Kerberos flows. Each channel names exactly one
member or client host, one private IPv4 destination and port, one controller
source address, one profile, exact certificate and implementation identities,
a finite validity interval, and a separate reviewed network-policy receipt.
There is no DNS fallback, wildcard listener, proxy, domain-controller channel,
remote shutdown, arbitrary tool dispatch, or automatic firewall configuration.

The role-specific enrollment loader reads an already installed, owner-private
bundle. Each side has only its own encrypted private key, the peer's public
certificate, the CA certificate, and locally protected message authentication
material. It does not create enrollment or transfer keys. TLS 1.3, certificate
identity, signed messages and the existing durable receiver ledger are reused.
The channel digest is included in the enrollment generation so changed scope
or address policy cannot silently recover a task from a different channel.
The initial adapter supports authenticated health, inventory and original-task
recovery/cancellation only; native execution remains explicitly refused.

## Configured Admission

The fixed AD operation uses the enrolled host, exact native profile and
supervised Windows Job boundary. A protected credential is delivered through
a bounded private pipe after child identity and readiness have been verified.
No password belongs in HTTP parameters,
process arguments, environment variables, normal logs or exported evidence.
The ordinary channel adapter does not dispatch execution. A separate explicit
admitted receiver now checks the exact sealed profile, current Windows platform,
private work root and protected client credential metadata before construction.
It holds the pinned binary across the existing bounded inventory check and
listener construction; a later identity failure closes the owned listener and
ledger or reports cleanup as unverified. The client credential metadata digest
is an explicit input, not inferred from whatever material happens to be present.
Member construction cannot accept reader material.

The admitted client permits only the exact AD operation and validates original
result wrappers, including negative and partial evidence. Lost responses and
`not_found` recovery never trigger a replacement Execute. Ordinary loopback and
control-only AD classes are unchanged. Product startup reads only the fixed
owner-private AD controller configuration beneath its managed runner root.
It does not install configuration, start listeners, enroll hosts or select a
replacement environment. Missing or invalid configuration stays unavailable.
The explicit receiver entry reads only its fixed role configuration and uses
the existing serve/shutdown lifecycle until stop or the original scope/channel
expiry, with owned listener, worker and ledger cleanup checked.

Signed health adds a closed, exact configured-admission projection on the
explicit admitted classes only. This is configuration readiness, not physical
host attestation, completed member inspection or proof of SMB authentication.
The native worker rechecks the local host before Ready and before dispatch.
Guided installation/enrollment remains a separate prerequisite; no public API
accepts arbitrary configuration paths, reader credentials or an execute toggle.
Fake-process/transport tests and pure
native tests are not live credential, host-admission or SMB evidence.

The private receiver adapter now uses the existing ledger transaction to reserve
the exact finite phase slots. Concurrent task hashes cannot reuse a slot or
exceed the scoped read/session budget. Failed and ambiguous reservations still
count. Preceding local logon IDs come only from the exact saved read results in
recipe order, never creation timestamps or a new identity lookup. A missing or
unsettled predecessor prevents another fresh read. This adapter is not exposed
as a public execution switch.

The private worker uses length-prefixed public request, Ready, one-use Begin
and terminal frames. Ready must match the held child PID, original task,
request hash, packet digest and random challenge before local admission is
rechecked. Only then may the client resolve the selected probe or legitimate
credential; member operations and original recovery have no credential resolver.
The existing protected-byte provider and pinned private directory are reused.
The client bundle contains no controller credential, and no setup or enrollment
writer is exposed. Private buffers are erased on return where possible, without
claiming complete erasure of provider, OS or immutable Python memory.

The fixed child is created suspended, assigned to an owned kill-on-close Windows
Job and resumed before stdin delivery. Wall-clock and monotonic deadlines,
frame/output ceilings, exact EOF and verified process-tree cleanup bound this
one operation. A validated finite worker-error terminal with its exact failure
exit is retained as a failure, never as success. Any timeout, malformed terminal,
other nonzero exit, unexpected stderr
or unknown cleanup prevents a settled terminal projection. A native error
envelope is not successful access validation. Authenticated transport alone
does not promote runner-reported facts into independent audit evidence.

Before durable transport completion, operation-specific schemas validate the
native result against its original target, descriptor and file identities.
Transport completion means the original terminal is preserved; it does not
mean the test expectation succeeded, a write settled, audit is complete, or
remote cleanup was proved. Recovery revalidates the same original record after
request expiry without decrypting a reader credential or starting a worker.
Recovery still requires the original enrolled channel to be currently valid;
it cannot substitute a renewed channel or another enrollment generation.

New receiver receipts record the first validated completion time within the
original request interval and after a feasible original packet-preparation
instant. Member snapshots label this receiver time; it is not a fabricated
native or remote event timestamp. Historical receipts remain readable, but a
member snapshot missing that timestamp cannot be invented during recovery.
Known denial, unknown write and partial audit results retain their original
meaning in the minimized workspace projection. Raw audit bytes stay in the
original receiver record rather than being copied into the public summary.

The fixed four-MiB transport ceiling includes the saved packet and result
wrapper. The worker derives a smaller terminal allowance and an audit byte
allowance that reserves worst-case JSON escaping and event separators. Reaching
that allowance retains partial capture evidence with `byte_limit`; it is not
reported as exhausted collection or silently truncated success.

Admission must supply verified file-ID and volume-serial pairs, the selected
NTFS/share descriptor preimages, exact UNC hardening and host/principal readiness
receipts. Public volume serials preserve all 64 bits as sixteen lowercase hex
digits. A local cloned token or a new LUID does not prove the outbound remote
principal, Kerberos authentication or a fresh server logon. These remain
separate authenticated observations and audit correlations. A successful API
return, missing audit event or local process cleanup is not proof of effective
access or remote session destruction.

New native admission profiles use the five standard integer limits:
`timeout_ms`, `max_stdout_bytes`, `max_stderr_bytes`, `max_artifact_bytes` and
`max_files`. Historical synthetic profile fixtures are not silently upgraded.
For this recipe the share identity digest binds canonical stable ShareMetadata,
excluding transient current-use counts and the separate share descriptor. NTFS
digests bind the selected OWNER, GROUP and DACL descriptor only, not SACL data.
Audit requests retain the original scope-created to request-requested interval;
there is no implicit time-window clamp or retrospective authenticity upgrade.
For newly admitted native tasks, the implementation generation is the canonical
hash of the runner binary digest, inventory digest and channel digest. It is a
consistency binding, not authentication, and does not change historical records.
