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

Production execution is currently unavailable. The saved workflow is covered
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

## Remaining Admission

Enabling execution requires connecting the fixed AD operation to the enrolled
host, exact native profile and supervised Windows Job boundary, then delivering
one protected credential through a bounded private pipe after child identity
and readiness have been verified. No password belongs in HTTP parameters,
process arguments, environment variables, normal logs or exported evidence.
The current channel adapter is not that credential path.

Admission must supply verified file-ID and volume-serial pairs, the selected
NTFS/share descriptor preimages, exact UNC hardening and host/principal readiness
receipts. Public volume serials preserve all 64 bits as sixteen lowercase hex
digits. A local cloned token or a new LUID does not prove the outbound remote
principal, Kerberos authentication or a fresh server logon. These remain
separate authenticated observations and audit correlations. A successful API
return, missing audit event or local process cleanup is not proof of effective
access or remote session destruction.
