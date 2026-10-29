# Owned-loopback SFTP preparation and unregistered consumer

`bluefire/tool_adapters/owned_sftp.py` is a preparatory, tool-owned metadata seam.
It is absent from the shipping registry, native setup inventory, action catalog,
Rust dispatcher and readiness path. Matching data always returns
`execution_available: false`. No approved build or binary digest is included.
BlueFire's existing v1 contract and gzip/chmod hashes remain unchanged.

The closed design requires OpenSSH portable 10.6p1 (tag `V_10_6_P1`, commit
`a8c72b842423f0774f542d3c2197247c3dd28d74`) and strace 7.2 (tag `v7.2`, commit
`195ac8ddbf6fad16ff1ff125b0feb725b6c46dcf`). These are provenance pins, not a claim
that any Linux distribution has supplied an approved build of them.

The metadata uses six finite roles: SFTP client, SSH transport, server, session
helper, authentication helper and observer. Each member binds the pinned source,
an exact package/build token and manifest reference, the existing native
installation identity (hash, size, Linux architecture, fixed tool/version and
canonical absolute location), and a distinct protected-installation evidence
reference. All OpenSSH roles must name the same build. The bundle is canonical,
bounded and immutable; member ordering does not affect its identity. It cannot be
passed as a list to the existing single-executable native setup API.

`prepare_client_selection` compares the bundle against a separately supplied
expected bundle digest, then compares all required request references against a
separately supplied current prerequisite set. These cover the owned loopback
endpoint, separate privileged server-preparation receipt, resource, generation,
content, pinned host key, reader identity, access observation and new session.
Neither matching hashes nor parse success authenticate those supplied values.
Callers must not derive the expected/current set from the request or from
historical findings. Missing references or generation changes fail closed.
The logical request contains no host, port, path, argv, configuration, script,
remote command, privileged operation or client-supplied readiness claim.

The client operation remains current-user dispatch. Privileged server preparation
is an explicit prerequisite reference, not an operation this module can authorize
or execute. The future authorized server receipt must establish a separate owner
and reader, isolated endpoint, generated keys and exact foreground server policy.
Generated-key preparation, if needed, requires its own reviewed setup; `ssh-keygen`
is deliberately not an extra executable hidden in this retrieval bundle.

The source also contains an unregistered Rust client consumer in
`runner/src/owned_sftp.rs`, `owned_sftp_process.rs` and
`actions/owned_sftp_action.rs`. Its source has been formatted, but compilation,
Rust test execution and installed native acceptance are pending. It is not an
available method. There is no production constructor or deserializer for
`VerifiedSftpAdmission`, and its compiled reviewed-build table is empty. Neither a
matching metadata request nor an `ActionContext` authenticates server preparation,
resource generation/access, endpoint, host key or new-session facts. The existing
runner context has no resolver for those facts. A separately reviewed compiler-owned
resolver must obtain them from authenticated current configuration/resource evidence
and a private generated-fixture credential channel before it can mint this type.
The private admission also requires a distinct `ObserverReadinessLease`, with
authenticated observer-admission and readiness references, exact bundle/scope and
new-session binding, a readiness time and an expiry covering the whole client
deadline. Its fields are private and it has no production constructor, wire parser
or caller boolean. Client checks reject stale, future, differently scoped or
short-lived leases before effects. The issuer/current observer resolver remains
unimplemented; adding executable hashes alone cannot make this workflow ready.
The consumer takes the non-cloneable admission by value and checks its exact
request hash, runner profile, workspace and reviewed operation. A caller cannot
reuse the same session capability for a second retrieval. Input-inspection
progress is marked after pure admission gates and before protected executable
reads; failed setup does not falsely imply that no input inspection occurred.

The consumer implements one real OpenSSH `get` into an anonymous file, followed by
size/digest verification and the existing durable receipt publication protocol.
Its logical request supplies resource/generation/content references and expected
size. The private admission, rather than a model or request path, binds the one
canonical remote resource beneath the owned server's `/owned/` namespace. Original,
staging-copy and unrelated report resources exercise the same method. There is no
hardcoded fallback edge, recursive transfer, arbitrary batch, shell, proxy, custom
configuration, agent or background transport operation.

The held protected client executes by descriptor; SFTP executes the held SSH
transport using its specifically inherited descriptor. Pinned SFTP source retains
that descriptor and keeps SSH in its process group. SSH then closes inherited
descriptors at startup. Its identity and exact known-host data therefore use sealed
parent-owned anonymous files through `/proc/<runner>/fd/<held-file>`; parent handles
remain held until the client/transport cleanup assessment ends. Actual procfs
readability under the current UID, dumpability and security policy is an unresolved
environment prerequisite. Failure must remain closed; do not weaken that policy.

The download file is anonymous, and the child inherits an OS `RLIMIT_FSIZE` equal
to the expected bounded size (at most 1 MiB), plus a zero core-file limit. Only the
output and transport descriptors are additionally inherited by the client. Batch,
identity and known-host inputs are sealed. Diagnostic pipes are nonblocking and
counted rather than retained; cancellation and deadlines reserve time to signal
the unreaped owned client group, reap and assess pipe/group absence. The result
`ReapedClientGroupAbsent` describes that group only. It cannot establish absence
of escaped descendants or settle all endpoint effects. Reviewed helper behavior,
and later containment/observer evidence where required, remain admission gates.

Partial/cancelled downloads have no disk pathname. Only verified completed bytes
enter `SafeRoot`'s existing durable intent, synced staging, no-replace publication
and commit path. Failures retain the execution fact; an interrupted publication
retains its durable intent/receipt for existing recovery. Authored Rust tests cover
changed references, helper substitution, fixed invocation, cancellation/deadline,
diagnostic overflow, uncertain cleanup, content mismatch, no-overwrite publication
and receipt commit/retry. Those tests have not yet been compiled or run.
Publication errors preserve uncertainty: a `write_new` error can leave an artifact
present, and a later commit error follows confirmed publication but may leave the
commit marker uncertain. Such outputs retain destination/intent identity and never
offer an available downstream artifact. Cancellation after confirmed publication
retains the artifact/receipt facts while withholding downstream availability.

Before enabling this method, integration must:

1. Compile and run the unregistered consumer and its authored tests. Supply a
   separately reviewed exact build/bundle identity to the empty compiled table.
   Independently recognize reviewed builds; inspect/recheck every protected member
   and its ancestors using `native_tool_inspection`. A reference cannot stand in
   for that inspection, library/loader review or executable TOCTOU handling.
2. Independently resolve authenticated current references from owned configuration
   and resource receipts. Verify the resource generation, current reader access,
   host key, loopback server binding and fresh session. Historical staging-copy
   provenance remains learning context and cannot establish current access.
3. Validate the implemented fixed nonrecursive `get`, anonymous-file size bound,
   descriptor/procfs behavior, receipt recovery and cancellation against the actual
   admitted build. Establish complete helper behavior/containment for any broader
   cleanup claim. Reuse existing runner supervision and receipts.
4. Keep server preparation outside the client dispatch. Confirm forced internal
   SFTP, no forwarding/PTY/user rc or command hooks, and the absence of the compiled
   system-rc path in the owned chroot. The upstream `session.c` invokes rc handling
   before internal SFTP, so `PermitUserRC no` alone is insufficient. Do not edit
   host-wide policy or weaken Yama, seccomp or privilege separation.
5. Authenticate and start the reviewed observer before effects; cover the server
   and credential transitions, keep buffer contents out of telemetry, and retain
   completeness/cancellation/tree-cleanup status. Validate against an untraced
   control. Client traces or process snapshots alone cannot prove server opens.
6. Demonstrate separate original denial, continuation using a discovered copy,
   copy success, owner permission defense, fresh-session denial and legitimate
   owner read. Preserve failed-route evidence. Only then consider registry,
   inventory, catalog and readiness activation through a separate review.

Primary references: [OpenSSH release](https://www.openssh.org/releasenotes.html),
[source pin](https://github.com/openssh/openssh-portable/tree/V_10_6_P1),
[privilege separation](https://raw.githubusercontent.com/openssh/openssh-portable/V_10_6_P1/README.privsep),
[session rc/internal SFTP path](https://raw.githubusercontent.com/openssh/openssh-portable/V_10_6_P1/session.c),
[strace release](https://github.com/strace/strace/releases/tag/v7.2),
[strace manual](https://raw.githubusercontent.com/strace/strace/v7.2/doc/strace.1.in).
The metadata and Rust adapter are independently authored and copy no upstream
implementation. OpenSSH remains an external dependency; no executable is bundled.
See `THIRD_PARTY_NOTICES.md` for the source/license boundary.
