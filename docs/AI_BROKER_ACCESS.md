# AI provider access and broker enrollment

Prepared-lab provider brokerage is **not yet available**. This implementation adds
an explicit access interface and an injected private-channel contract. It does not
start a broker, open a socket, pass a descriptor, or change the lab's network
namespace. Deterministic channel tests exercise the normal service check, graph
draft and simulated proposal paths through the existing Responses and Chat
Completions parsers. Those tests establish integration, not live-provider access
or target isolation.

## Existing installations

`DirectAIProviderAccess` retains configured endpoint and environment-key behavior.
Normal service bootstrap, provider catalog readiness, provider checks, graph drafts
and runtime proposals use the same service-owned access interface. Existing
transport injection remains supported. No provider route, CLI configuration or
stored provider schema changes are needed for direct installations.

## Explicit enrollment

Trusted control-plane composition may construct `BrokerEnrollment` and inject a
`BrokeredAIProviderAccess` into `BlueFireService`. There is no public enrollment
endpoint or automatic broker discovery. The enrollment binds:

- The exact canonical provider configuration, including provider ID, dialect,
  endpoint, model, environment reference, redaction and request/retry/token bounds.
- A random session ID and absolute expiry, with a creation lifetime of at most
  fifteen minutes. Expiry, replacement or changed configuration requires fresh
  enrollment; the access owner never silently refreshes or rebinds.
- Exact schema digests for the connection check, runtime proposal and any supported
  graph-draft schema. Graph schemas include catalog choices and requested bounds;
  an unenrolled catalog/bounds variation returns `broker_schema_unavailable`.
- The destination policy. `public_https` rejects plaintext, localhost and literal
  non-global addresses. `explicit_endpoint` represents a separately approved exact
  local/private provider endpoint. Neither setting asserts DNS resolution or
  network-route isolation; these must be enforced by the future broker.

The service asks for readiness or sends one existing structured-request body.
The interface accepts no caller-selected URL, headers or credentials. The broker
owns credential resolution; the service neither resolves the key reference nor
receives key bytes on this path. Readiness is a credential-ownership check and
never certifies connectivity. A successful connection check requires the ordinary
strict synthetic response parser and does not use deterministic fallback.

## Channel and result boundaries

Each request binds session, enrollment digest, fresh request ID, relative timeout
and the exact body-byte digest. The body is capped at 1 MiB and must reproduce the
existing structured-request grammar for its enrolled model, dialect and schema;
extra fields, tools, streaming and model/schema substitutions are rejected.
The broker-side channel must run `validate_broker_request`, reject reused request
IDs, and apply the absolute session and per-request deadlines.

Responses must match the exact session, enrollment, request ID and request digest.
Only bounded response bytes, an exact readiness state or a closed diagnostic code
are accepted. The ordinary provider parsers still check envelope, schema, usage,
proposal allowlists and approval rules. Late, malformed or mismatched responses
cannot become parsed success. Ordinary provider failure may retain the configured
deterministic fallback, explicitly labeled with the failure reason; cancellation
never becomes fallback. No broker status grants execution authority.

The access owner combines job cancellation with service lifetime. Closing it
cancels the channel and waits a bounded interval for active calls to drain. The
future channel must interrupt blocked I/O, enforce its deadline and retain exact
process ownership on unsuccessful cleanup. A caller-supplied channel object is a
trusted internal dependency, not authentication of an arbitrary external endpoint.

## Required next boundary before lab support

A later reviewed composition must create a fixed outer broker and authenticated
private channel before entering the target namespace. It must pin the configured
destination, apply explicit local endpoint approval or public-address resolution
and connection pinning, prohibit redirects and proxy inheritance, and prevent
credential/header disclosure in reports. Control-only descriptors must not pass to
the runner or target; same-UID socket permissions alone are insufficient. Exact
worker launch identity, parent-death handling, cancellation, restart refusal,
descriptor closure and network/host isolation must be tested in the owned lab.
This contract does not provide a general proxy or weaken existing target isolation.
