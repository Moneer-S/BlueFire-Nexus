# Test Caido protocol provider

BlueFire provides an explicit test-only Caido protocol provider for the installed
Strix mechanics path. It exists to exercise the pinned Strix bootstrap and the public wire
contract of the MIT `caido-sdk-client==0.2.0` without acquiring, embedding, or
running the Caido application, CLI, server, or an official or derived Caido
image.

This provider is not a replacement for Caido. Every identity and receipt fixes:

- `test_provider=true`
- `live_caido_proof=false`
- `production_eligible=false`
- `activation_mode=installed_deterministic_test`

A production or live-Caido composition must reject this identity. A successful
test-provider run establishes deterministic engine, SDK, transport, replay,
cancellation, and cleanup mechanics only. It does not establish live Caido,
autonomous model quality, target execution, or target-defense effectiveness.

## Exact public-wire subset

The provider admits only the operations required by the reviewed SDK and Strix
startup path:

1. The pinned Strix worker's exact unauthenticated `LoginAsGuest` mutation.
2. The SDK's unauthenticated `GET /health` request. The response identifies the
   BlueFire Test provider and includes `name`, `version`, and `ready`.
3. The SDK's exact authenticated `CreateProject` document with the fixed
   temporary `sandbox` input.
4. The exact authenticated `SelectProject` document for the provider-issued
   project identity.
5. The SDK's exact authenticated `DeleteProject` document for BlueFire
   lifecycle coverage.

Pinned Strix does not call `DeleteProject`. Its sandbox deletion ends the
session, so a passing delete test is controller cleanup coverage, not evidence
that upstream Strix performs project cleanup.

Unknown documents, introspection, aliases, batching, extra variables, duplicate
JSON members, alternate routes, absolute-form requests, proxy headers,
upgrades, redirects, chunking, and pipelining are refused. The attempt-local
bearer is generated in memory. It is never retained in audits, results, errors,
or provider identity documents.

## Listener custody and network boundary

The owned worker binds and listens on numeric `127.0.0.1:48080` inside its
private network namespace, then transfers that listener to the controller over
the authenticated descriptor channel. The controller launches the separately
supervised provider with the transferred descriptor. The provider process can
remain in the controller's network namespace while accepting connections on
the socket bound in the worker's namespace.

The controller attests the worker network-namespace device and inode, process
generation, and descriptor transfer. The provider checks the exact transferred
listener device and inode, kernel `SO_NETNS_COOKIE` against that attestation,
address, family, type, accepting state, and attempt-bound custody fields. It
does not mistake its own process namespace for the socket's namespace. Provider source
contains no socket creation, bind, listen, connect, DNS, target, model, Docker,
or generic forwarding operation. Actual target and tool actions continue
through their separate controller-owned Docker and relay boundaries.

The provider is launched only with controller-opened descriptors:

```text
python -I -m bluefire.test_caido_protocol_provider \
  --manifest-fd <fd> --listener-fd <fd> --audit-fd <fd> \
  --ready-fd <fd> --owner-fd <fd> --activate-fd <fd>
```

The installed controller owns the write end of the one-way owner pipe. Its
closure stops the provider even if the controller exits abruptly. A normal
controller stop closes that pipe, waits for the provider process, and verifies
its final durable `lifecycle/drained` audit record. The controller retains the
private audit file. The provider process receipt proves only its own process,
adopted socket copy, bearer, and project state are gone. The native worker's
separate listener descriptor and the target require their own cleanup proof.
The provider reports ready after adopting its listener but does not answer a
request until the controller checks the retained active attempt and sends a
one-use activation byte. A crash before that point closes the owner pipe and
drains the provider without admitting a request.

The process owner verifies the predeclared `caido_channel` resource owner
binding from the saved prelaunch transaction. It retains the exact ready line,
provider process PID/start/boot identity, and private audit inode before
activation. Restart recovery must reopen those values from the protected owner
journal, verify that the original process is no longer live, and inspect the
final append-only audit. Caller-supplied replacement identities cannot be used
as proof. The drain receipt's `evidence_ref` binds the verified audit digest to
the saved process and resource owner identity.

The static installed-artifact check is:

```text
python -I -m bluefire.test_caido_protocol_provider --describe
```

The descriptor reports the composite digest of all three maintained implementation
files. Admission binds that digest plus the SDK wheel, provenance fixture,
project document, and pinned Strix bootstrap digests.

## Lifecycle, replay, and retained audit

The exact manifest binds the accepted claim, runtime admission, controlled
profile, authorization, attempt, container, provider generation, listener
custody, and finite request, byte, mutation, replay, and refusal budgets. Its
full canonical mapping produces the provider identity reference.

Each mutation has one attempt-local logical slot. An exact committed replay
returns the byte-identical retained response without repeating the internal
effect. A changed request conflicts. Create and select results become stale
after deletion, while an exact delete replay remains valid. Audit preparation
is durable before an internal mutation and the committed response digest is
durable before delivery. An audit failure makes the runtime unknown and revokes
the bearer.

Cancellation first stops admission and bearer authority, closes the adopted
listener and accepted connections, then discards project state. Drain confirms
provider listener, bearer, pending handler, and project-state absence. It does
not claim target, container, Docker network, or lab cleanup.

## Provenance and proof level

- `caido-sdk-client 0.2.0` wheel SHA-256:
  `bc573651681c093ee9663c7924d38d522a89cea60e2ce00d34ba9b02942b1da1`
- Exact SDK authentication dependency: `caido-server-auth==0.1.2`, wheel
  SHA-256 `40c6cd3728e24cdff402c4efa5d8f55bf6e6cc73ac0169bdea1ad1e34faff8ff`.
- Reviewed wire fixture SHA-256:
  `0f83caa9253b07fec972b5aae877b8495cf5c81c8893df27b708fc515fe74966`
- SDK project document SHA-256:
  `ea2c5935a9921295c029d2912589df5997f2b9eec185b1bf73556f1af7d986cf`
- Pinned Strix bootstrap source SHA-256:
  `f493e3a7c9219e52520d2fadfd8dde78782e17440056f98aa068b146a0e788af`

The SDK integration check must use CPython 3.12 in an isolated environment
installed from the verified SDK, authentication, and transport wheels. The
focused direct-loopback test also checks the two supplied wheel hashes before
making SDK calls; the host must supply those artifact paths through
`BLUEFIRE_CAIDO_SDK_CLIENT_WHEEL` and `BLUEFIRE_CAIDO_SERVER_AUTH_WHEEL`.
Hash-bound fixtures remain compatibility evidence when that closure is
unavailable. Neither proof level may be presented as an installed Strix run
or a live-Caido session.
