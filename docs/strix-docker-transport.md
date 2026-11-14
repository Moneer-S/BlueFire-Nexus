# Controller Docker transport and custody

`LinuxUnixDockerDaemonTransport` implements the existing `DockerDaemonTransport`
contract on Linux. The controller supplies a `LinuxDockerDaemonEndpoint` containing
the independently admitted daemon digest, absolute socket path, pinned device and
inode, and expected Linux peer PID, UID, and GID. These values remain controller-private;
they are never worker configuration, environment variables, or response fields.
Reading a socket's metadata does not admit a daemon or establish its lifecycle.
Admission must also establish the peer process lifecycle and protect the endpoint
directory from replacement; PID credentials are not a process-start-time proof.

Every exchange uses a fresh nonblocking Unix stream connection. The transport
checks the path identity before and after connection and checks `SO_PEERCRED`
before sending. It does not use TCP, DNS, proxy settings, redirects, or retries.
It sends the complete validated request bytes unchanged. Cancellation and an
absolute monotonic deadline apply to connection, sending, and receiving, with
bounded polling even when the peer makes progress.

Ordinary responses require one explicit bounded HTTP/1.1 frame. Duplicate
headers, conflicting lengths, close-delimited ordinary bodies, interim
responses, redirects, unadmitted upgrades, trailers, chunk extensions, and
surplus buffered bytes are refused.
Content-Length framing is preserved byte-for-byte. Bounded chunked framing is
decoded and replaced with Content-Length; the body and all other headers retain
their values. The proxy still independently validates its narrower operation
limit, semantic headers, response body, and resource ownership. Body, header,
wire-byte, chunk-line, and chunk-count limits are enforced before allocation.

The one exception is the exact non-detached, non-TTY exec-start operation. Its
request must carry Docker's canonical `Connection: Upgrade` and `Upgrade: tcp`
pair. The request parser also admits docker-py 7.1's exact
`Accept-Encoding: gzip, deflate` default, while responses with content encoding
remain refused. The transport accepts only the reviewed 101 upgrade or 200
attached variants with the modern non-TTY
`application/vnd.docker.multiplexed-stream` type from the pinned daemon, then
reads the hijacked socket to EOF under the same absolute deadline and
cancellation token. It validates each eight-byte
Docker frame before reading its payload, demultiplexes stdout and stderr, and
applies independent decoded-payload and framing-overhead budgets. It normalizes
the retained frames to a bounded HTTP 200 response for the effect-free policy
core. A truncated frame, invalid stream, excess payload/overhead, cancellation,
deadline, or lost socket is ambiguous after send. The socket is closed, no
request is replayed, and the policy proxy retains the exec/container for whole-
container reconciliation. Docker has no per-exec kill operation.

An optional controller dispatch gate may wrap only the request write. It is the
production composition point for reopening the current claim, controller fence,
cancellation state, and protected handle-to-container mapping immediately
before bytes leave the process. It is released before the potentially long
attached read. The transport does not create or infer that authority.

The gate remains structurally optional for legacy non-exec exchanges. Admitted
V2 exec stays dormant unless the controller also supplies a qualified external
`ExecOperationCustodyOwnerV2`. That owner must authenticate one current lease
before every create, start, and inspect effect; retain responsibility through
terminal settlement; and stop the attempt-owned container on deadline,
cancellation, or controller loss. Without it, the controller returns
`exec_custody_unavailable` before journal reservation or socket send. Closing an
attached stream is not proof that the process or its descendants stopped.

The controlled backend constructs the admitted request with `Host: docker`.
That private proxy identity differs from stock docker-py's Unix-pool
`localhost` authority. Installed composition must prove the controlled request
construction, or a separately reviewed canonicalization before claiming stock
docker-py wire compatibility. This transport never rewrites Host itself.

`DockerDaemonTransportError` contains a bounded reason code and the fields
`request_may_have_been_sent`, `request_bytes_sent`, and `response_started`.
A failed send attempt is conservatively uncertain even if the syscall reports
zero transferred bytes. A complete response does not prove policy acceptance,
resource ownership, or publication. The policy proxy keeps its existing
quarantine behavior on transport or publication failure.

`ProductStoreDockerProxyCustody` implements both `DockerProxyAuditSink` and
`DockerProxyCustody`. Pass the same instance as the proxy's `audit` and `custody`.
The adapter uses the product store's private database and transaction boundary,
requires durable SQLite commits, and retains an immutable, hash-chained,
attempt-, policy-, and daemon-bound journal. The proxy persists an operation
intent before transport, and full state before acknowledging an audit receipt.
No raw request, response body, socket path, or secret is retained in this journal.

`reopen()` returns the latest retained state, last request sequence, audit
records, incomplete operation bindings, and every known container and exec
identity, including pending and quarantined resources. An incomplete intent or
state/audit publication gap forces reconciliation. Supply its state and sequence
to a replacement proxy by constructing it with the same custody adapter and
`restore_from_custody=True`. The proxy validates the restored state, sequence,
policy, daemon, and journal together. The default construction path accepts
only a pristine journal, so a replacement cannot silently reset its sequence
or replay an operation. A reconciliation-required proxy refuses all requests.
Reopening never promotes pending resources, retries an operation, clears a
quarantine, or creates cleanup authority. Controller reconciliation still needs
the existing independent daemon, attempt, labels, inventory, and custody proofs.
The journal is not an external rollback anchor against the database owner.

For a V2 installed target-capable dispatch, the controller may provide a
`DockerV2EffectiveNetworkBinding` from its accepted attempt, claim, fence,
network policy, and exact target-plan digest. With the same durable custody
adapter wired as both audit sink and custody, a validated `container_inspect`
issues a `DockerV2EffectiveNetworkReceipt` only after its accepted publication
is reopened from the journal. The receipt names the observed sole network
attachment, exact container, response digest, published audit reference, and
current proxy state. `effective_network_receipt()` returns `None` before that
inspection or after custody becomes stale or uncertain. The controller must
check the receipt against its current activation and launch plan before
dispatch. This is evidence of container placement, not of target reachability,
network isolation beyond the inspected fields, or a successful target response.

The transport does not launch Docker or create a worker-facing listener. The
owned fake Unix-socket tests exercise transport behavior without a real daemon.
