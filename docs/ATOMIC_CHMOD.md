# Atomic chmod permission method

This document records the reviewed contract for a Linux-only Atomic Red Team
T1222.002 adaptation. The method is a bounded experiment over one receipt-owned
fixture. It changes selected POSIX permission bits on that fixture and records
the before/after identity for cleanup; it does not establish effective access.

The fixed contract is `sandbox.permission.chmod.v1`, with behavior
`sandbox.permission.relax.v1`, tool `gnu.coreutils.chmod.v1`, and versions
`1.0.0`. The reviewed upstream test is GUID
`34ca1464-de9d-40c6-8c77-690adf36a135`, from commit
`6132b92779873cb0d05bef07ba0a480d47eb1cc8`, path
`atomics/T1222.002/T1222.002.yaml`, with content digest
`sha256:76ea316186fe0c7f1d7bdaa9b29c92684eb7f63e28ba14834f50b9bd4fcc2049`.
The Atomic adaptation is MIT licensed; its complete notice is retained in
`bluefire/data/atomic_red_team_LICENSE.txt`. GNU chmod is an optional,
operator-installed [GNU Coreutils](https://github.com/coreutils/coreutils)
dependency under GPL-3.0-or-later. BlueFire does not bundle, download, link to,
or redistribute its source or executable. See [third-party notices](../THIRD_PARTY_NOTICES.md).

The only operator parameter is the finite mode choice `0600`, `0640`, `0660`,
or `0666`. The transformed fixture ID, its observed SHA-256, source receipt ID,
and size are supplied by existing typed artifact bindings from the reviewed
action/behavior contract; they are not operator, model, or action parameters.
The upstream YAML digest above identifies the reviewed source and is distinct
from the observed fixture-content hash. The adapter accepts no path, command,
executable, shell text, or arbitrary argument list. It owns the fixed
invocation shape `mode`, `--`, `/proc/self/fd/N`, where `N` is derived from the
held receipt-owned file descriptor.

The setup prerequisite is a root-owned, protected GNU chmod executable whose
content digest and size match the trusted profile. The operator supplies the
package version label; inspection does not run `--version` or independently
authenticate a package publisher. The label is included in approval binding.
Development and contract tests do not install, bundle, or invoke it. Runtime supervision remains
current-user, network-free, bounded, cancellable, and receipt-owned. The
original fixture bytes are retained and the creation receipt is used for
cleanup after the metadata mutation.

The security objective is limited to permission-bit relaxation on the selected
fixture. A private `0700` workspace prevents this method from demonstrating
effective access by another user; ACLs, parent traversal, identities, and other
security controls remain outside the observation. A successful chmod exit is
execution evidence only. Independent filesystem observation and cleanup must
remain separate evidence records.

The compiled action is registered as requiring setup. A saved installation
record alone does not establish readiness: the runner must inspect its protected
executable and match the reviewed bytes. The approval binds that installation;
the native adapter verifies it again before effects. Simulate reports authored
permission metadata and never invokes the tool. Software tests are not live
Linux execution evidence.

## Set up and review

In Runner profiles, choose **Configure methods** on the existing Linux Execute
profile used by your enrolled local runner. Deactivate an active profile first.
This retains its enrolled identity while you enable **Change sample file
permissions (GNU chmod)** together with its setup and cleanup methods. Save the
draft, then choose **Set up GNU
chmod** on its card. Enter the protected installation location and its declared
package version. Start the local runner through **Runners** if it is offline;
the draft does not need activation or enrollment for this read-only check.
**Inspect installation** reads the executable through the authenticated local
runner's inspection connection; it checks protected ownership, permissions, native ELF
architecture, bounded size, content hash and stable file identity without
launching the utility. A refused inspection carries no installation record.

Review the result and choose **Save tool binding**. This saves a profile draft;
activation and execution review remain separate. The runner checks the saved
bytes again during readiness and immediately before execution. A saved record,
a connection check or an authored simulation is not a live permission experiment.
Creating a new named profile does not add that identity to an existing runner
enrollment. Use the existing enrolled profile for this journey; enrollment
migration for additional profile identities is not part of this method.

In the graph, connect **Create sample records**, **Prepare sample records**,
the permission method and cleanup using their typed fixture input/output. Choose
the permission mode before review. The original fixture creation receipt owns
cleanup even if changing its metadata partially fails. The permission objective
must be evaluated using separate filesystem observations, not the action's exit
code. Retain unsuccessful results when comparing a revised permission detector
against benign activity and a fresh mode variation.
