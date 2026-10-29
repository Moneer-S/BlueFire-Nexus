# Owned-loopback SFTP preparation

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

Before enabling this method, the next Rust consumer must:

1. Add one fixed `NativeToolBinding`/compiled SFTP action through the existing
   action and reviewed-operation boundary, with an exact helper-bundle binding.
   Independently recognize reviewed builds; inspect/recheck every protected member
   and its ancestors using `native_tool_inspection`. A reference cannot stand in
   for that inspection, library/loader review or executable TOCTOU handling.
2. Independently resolve authenticated current references from owned configuration
   and resource receipts. Verify the resource generation, current reader access,
   host key, loopback server binding and fresh session. Historical staging-copy
   provenance remains learning context and cannot establish current access.
3. Generate one fixed nonrecursive `get` operation inside the compiled adapter;
   reserve output/effect receipts, cap bytes/time/processes, and supervise all
   helper descendants. Reuse existing bounded process/receipt code, not a shell,
   general loader, standalone supervisor or new store.
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
This independently authored Python metadata copies no upstream source code.
See `THIRD_PARTY_NOTICES.md` for the source/license boundary.
