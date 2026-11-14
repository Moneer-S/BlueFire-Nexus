# Controlled Caido socket channel

`create_controller_caido_socket_channel` constructs the execution adapter for
`EngineCaidoChannel`. Construction opens nothing. `bundle.channel.activate()`
binds only the plan's numeric IPv4 loopback port with exclusive ownership.
The worker sees ordinary HTTP with no added authentication headers or query.
The request grammar matches the sealed Strix candidate: Python 3.12.14,
`aiohttp` 3.14.5, `gql` 4.0.0 and `caido-sdk-client` 0.2.0. Health admits the
exact aiohttp defaults and no authorization. Authenticated GraphQL admits the
same defaults plus a bounded RFC 6750 bearer value, which is forwarded only in
the transient request and is never retained or audited. The one unauthenticated
GraphQL form is Strix's exact 76-byte `LoginAsGuest` bootstrap mutation with a
bounded `curl/<numeric-version>` user agent from the sealed image. Other curl
requests and other unauthenticated GraphQL bodies are refused.
No proxy request, redirect, upgrade, chunked body, duplicate length, pipelining,
DNS lookup, host dial, Docker API or address discovery is implemented.

The factory deliberately has no permissive production defaults. The integrating
controller must provide all of the following:

- A `ProtectedWorkerPeerVerifier` backed by protected process or network namespace
  custody. Its receipt binds the accepted socket's exact peer tuple, worker ref,
  attempt and plan. Merely recognizing `127.0.0.1` or a random port is insufficient.
- Attempt-local `CaidoConnectorCredentials` containing a separately provisioned
  32-byte key and exact plan digest. Never pass the key through the engine, HTTP,
  environment, audit or serialized SDK state.
- An `OwnedCaidoStreamProvider` that synchronously admits an already-owned private
  stream bound to `plan.connector_ref`. `open_exact` must be nonblocking;
  `revoke_exact` stops remote admission and closes remote streams, while
  `observe_exact` reports their separately verified absence.
- The private `CaidoOwnedConnectorPeer` uses a second owned capability bound to
  `plan.upstream_ref` to open only the owned container's namespace-local
  `127.0.0.1:48080`. Host loopback port 48080 is never assumed to be that endpoint.
  IPv4 streams must have numeric loopback local and peer addresses. For the
  upstream ref, the socket's actual peer port must also be 48080; a provider's
  claimed metadata is insufficient. An already owned local Unix stream is also
  accepted. No destination is taken from HTTP.

The provider for `ControlledControllerTransport.resolve_caido_exact` may return
the activated listener's numeric coordinates only after establishing those
capabilities and matching the request's resource and relay identities. Keep the
existing receipt contract: container port 48080, zero retries, `tls=False`,
`published_host_port=False` and all exact attempt/resource/relay bindings.
Platform worker-custody and container-stream implementations are prerequisites;
this module supplies no fabricated platform proof.

The private wire carries exactly one request and response per stream. Its fixed
header contains version, direction, plan digest, connector ref, attempt ID,
32-byte nonce, request SHA-256 and bounded length. HMAC-SHA-256 authenticates the
whole header and payload. Responses bind the same nonce and request digest;
the peer records a bounded nonce set and refuses replay. The key is not sent.
Only after authenticating and validating the full request may the peer open the
Caido endpoint. It rewrites the HTTP Host to the fixed container endpoint.

Limits cap simultaneous owned sockets, total exchanges, message bytes, headers,
JSON structure, audit storage and absolute per-exchange time. Each peer exchange
reserves both of its sockets. Trusted verifier/provider calls must themselves
be bounded. The parent controller owns the overall attempt deadline and must
cancel this channel when the attempt expires; an idle listener is not an
independent execution lease.

An accepted loopback socket consumes a concurrent-connection slot, but it does
not consume the finite exchange budget until protected worker custody is
verified. A local process that lacks that custody therefore cannot exhaust the
attempt's operation count. If Caido resolves a request but delivery to the
worker fails, the result is ambiguous and the whole channel is revoked before
the engine can retry the mutation under a fresh request identity. The exact
guest-bootstrap mutation also receives a stable attempt-bound request identity
and canonical digest. If the response reached a local socket buffer but the
worker retries because it could not use or observe that response, the channel
returns its bounded retained response without reopening the Caido operation.

`channel.cancel()`/`revoke()` stops admission and closes local and remote owned
streams. Partial activation also revokes both capabilities. Call `channel.drain()`
after in-flight calls return; retry a pending/unknown drain only to observe
cleanup, never to replay work. Absence requires the listener thread, accepted
workers, connector streams and remote capability to be absent. A drain receipt
does not prove container or network resource cleanup. Revoked objects cannot
reopen. A new attempt requires a fresh plan, key and capability instances.

Caido responses are control-plane data and never independent target evidence.
Target calls still use `FixedTargetRelay`; model calls still use
`ControlledModelGateway`. This adapter grants neither relay authority nor
arbitrary egress and does not change the controlled container's network policy.

The tests use only explicitly owned local fake endpoints and provenance-bound
wire fixtures for the pinned clients. They establish the socket, framing and
cancellation contracts, not an installed Strix/Caido session or Docker
execution proof.
