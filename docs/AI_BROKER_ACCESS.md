# AI provider access and broker enrollment

Prepared-lab brokerage has an optional fixed Linux startup path. Its portable
tests exercise ordinary service checks, graph drafts and simulated proposals
through the framed broker and existing Responses/Chat Completions parsers.
These tests do not establish live-provider access or Linux target isolation;
the owned-lab process/descriptor proof remains a separate release prerequisite.

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
  local/private provider endpoint. The HTTP worker resolves the enrolled host once,
  checks every returned address before connecting, and connects only to those
  addresses while preserving the original TLS hostname and certificate checks.
  Public policy rejects private, loopback, reserved, link-local, unspecified and
  multicast addresses. Redirects and ambient proxies remain disabled.

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
fixed channel interrupts blocked reads and writes. Cancellation during a partial
request closes the unusable channel; cancellation after a complete write sends an
exact cancellation frame and drains its one response before reuse. A request
timeout after a complete write follows the same bounded settlement, then reports
a retryable timeout while retaining the channel. A late success is drained, not
returned as success. Malformed, mismatched, closed or undrainable channels still
fail closed. This settlement does not extend provider execution or enrollment;
session expiry still tears down the broker and target. The owner
retains exact process/channel objects after unsuccessful cleanup. A caller-supplied channel object is a
trusted internal dependency, not authentication of an arbitrary external endpoint.

## Fixed prepared-lab startup

An explicit `prepared_lab start --ai-provider-definition PATH` reads one public
`AIProviderConfig` JSON object. It resolves only that configuration's credential
reference at the operator boundary and sends the result over owned bootstrap
stdin. No credential value enters command arguments, target/UI environments,
public enrollment records or the inference response channel.

The freshly prepared clone reserves UID/GID 1001 for the broker and retains 1000
for the product. The broker keeps its control-plane network while its private
mount/IPC namespace hides host mounts and sockets. The target keeps the existing
mount/network/PID/IPC isolation and loopback-only routes. The installed venv,
fixed module paths and interpreter target must be root-owned and non-writable;
the product tree is mounted read-only before untrusted work.

Anonymous bootstrap sockets use kernel SCM credentials. Parent checks bind each
exact PID and creation time. Both namespace init and the final-exec UI clear and
verify dumpability before receiving an inference descriptor. The UI waits for
the parent's final admission acknowledgement before entering the ordinary CLI
UI service. Bootstrap descriptors close before target admission; only the UI
owns its non-inheritable inference endpoint. Runner launches do not receive it.
The broker owns the other endpoint and checks exact enrollment, schema and fresh
request IDs. EOF/session expiry cancels outstanding requests and drains owned
processes. Restart or expiry requires fresh enrollment; no old session is adopted.

Use `--ai-destination-policy explicit_endpoint` only for an explicitly approved
local/private provider. `public_https` is the default. The graph schema binds
`--ai-max-nodes` (default 8), `--ai-max-edges` (default 16) and the built-in catalog.
Changed bounds/catalog/configuration refuse until a new session is enrolled.
Only the normal UI receives this channel in this slice; an independently launched
interactive CLI process does not discover or borrow the UI descriptor.

Before release, the owned Linux lab must independently prove SCM namespace PID
mapping, `/proc`/descriptor denial from target UID, absent runner inheritance,
unchanged network/host isolation, cancellation and complete teardown. No real
account, credential or paid inference is needed for that proof: use an owned
deterministic control-plane endpoint and a synthetic token.
