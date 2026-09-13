# Security Policy

## Supported surface

Security fixes target the maintained 0.1.x bluefire Python package, the aligned runner Rust crate, the canonical configuration and scenario examples, and tests_platform on the current default branch.

Superseded direct-effect code and scenarios are retired from the working tree. Historical Git objects are not part of the maintained execution path and must not be treated as a supported or safe runner.

## Threat model

BlueFire Nexus coordinates authorized, bounded security experiments on a local system. Its primary security goals are:

- prevent Python planning, AI output, scenarios, and plugins from becoming arbitrary execution channels;
- keep execution within a reviewed Rust action registry and explicit runner profile;
- make platform, capability, safety-tier, scope, approval, budget, and cleanup decisions inspectable;
- keep local files and network effects inside runner-enforced bounds;
- preserve evidence provenance without presenting simulations or runner reports as independent observations;
- keep configuration references and run artifacts local unless the operator explicitly moves them.

BlueFire does not make an untrusted host trustworthy. Protect the machine, runner binary, sandbox root, configuration source, environment, and operator account using normal system controls.

## Two-mode safety model

The product recognizes exactly two top-level modes.

**Simulate** is the default. It models registered behavior transitions in Python and does not invoke the Rust runner. Its outputs use synthetic or counterfactual provenance. A successful Simulate result is not evidence that an action ran or that a defense observed it.

**Execute** is explicit. It requires an Execute profile, explicit operator target scope, a compatible runner inventory, a registered action, policy approval, and request-bound operator approval. Execute can create or transform sandbox files; inspect bounded system, process, directory, and file metadata; create deterministic archives; stage or locally export sandbox artifacts; send to an explicitly allowed loopback socket; and remove receipt-owned artifacts. Those are real local effects.

Changing AI autonomy, a scenario parameter, or a UI control does not change these mode guarantees.

## Execution boundary

Python owns contracts, catalog lookup, graph validation, planning, policy evaluation, manifest construction, result normalization, evidence storage, detection lifecycle, replay, comparison, CLI, API, and UI.

Python does not implement behavior actions. Explicit managed bootstrap verifies one platform-native runner artifact and records its exact digest/inventory; the separately hosted same-user process may invoke only that binary with a fixed argument grammar. The authenticated transport rejects executable-content fields such as generic commands, shells, scripts, payloads, interpreters, and binaries.

Logical behavior parameters and typed artifact bindings are not passed directly to the runner. RunnerActionAdapter is the only translation boundary. It maps each known action ID to a fixed sealed executor schema and rejects unknown actions, unknown parameters, absolute paths, traversal, and unresolved artifact references.

The Rust runner independently validates:

- schema versions and unknown fields;
- action and behavior IDs against its compiled inventory;
- current host, requested platform, and profile platform;
- action allowlist, control-block list, capability set, and safety tier;
- manifest and profile digests;
- request lifetime and resource budgets;
- filesystem and network scope;
- approval binding and expiry;
- cleanup action and receipt ownership.

A Python allow decision does not compel the runner to execute. Runner refusal and control-block outcomes must remain refusals in normalized results.

## Scope and cleanup

The canonical packaged example grants only runner-owned workspace, local export, and literal loopback network scope. Its network allowlist is 127.0.0.1/32 and ::1/128. No private, public, or inferred target network is configured by default. Checkout copies are parity-tested against the packaged defaults.

Runner paths are relative to an existing sandbox root. The runner rejects absolute, drive, device, traversal, symlink, and reparse-point escape paths. Create-new actions issue receipts. Cleanup accepts receipt IDs rather than caller-selected paths and revalidates owned object type, size, and digest before removal.

A cleanup receipt and bundle digest are integrity records, not authenticity signatures. Production deployments should protect profiles, approvals, the runner binary, and run bundles using operating-system access controls and, where needed, an external signing system.

## Approval model

An Execute profile must require approval. Approval is bound to the exact request hash, action ID, profile ID, and target-scope digest and has an issue and expiry time. Reusing an approval for a changed action, parameter set, scope, or profile is invalid.

The command-line convenience flag for approval does not replace organizational authorization. Use Execute only in an environment you own or have explicit permission to test.

## Configuration and secrets

Canonical configuration stores environment-variable names through EnvironmentReference objects; the parser does not resolve or serialize their values. Do not commit secret values, runner credentials, customer identifiers, internal inventories, or private environment details.

The example references BLUEFIRE_RUNNER_BINARY, BLUEFIRE_SANDBOX_ROOT, and OPENAI_API_KEY by name. Set applicable values in a protected local environment appropriate to your platform.

## AI provider boundary

AI autonomy is `off`, `assist`, or `auto` and remains independent of execution mode. Off creates no provider. Assist persists an exact-digest proposal and pauses before mutation. Auto may apply a schema-valid, policy-valid Simulate proposal; every Execute mutation pauses for review and then requires a fresh one-time Execute approval.

The deterministic planner supplies a request-specific `bluefire.ai-request.v2` envelope. It correlates the observed outcome with exactly one registered next edge and bounds any compatible behavior substitution, primitive parameter values, exact-profile registered action choice, and single retry. Independent allowlists cannot be cross-paired. The model cannot invent an edge for another outcome, command, path, capability, action ID, profile, scope, safety tier, approval, or cleanup policy. Every accepted choice is revalidated against immutable digests, the registry, profile inventory, budgets, and ordinary policy before it can affect a plan.

BlueFire ships a deterministic offline provider and an OpenAI-compatible Responses provider. The latter uses strict structured output, no tools, endpoint validation, timeouts, retries, response/token limits, key-based redaction, evidence-content exclusion by default, and deterministic fallback. Provider output and observed content remain untrusted. A configuration-health result is not proof that a real provider request succeeded or that a proposal is safe.

## Plugins

Plugin manifests are declarative. Loading a manifest does not import Python entry points or execute plugin code. Manifests must declare version, trust, SHA-256 integrity metadata, license, provenance, permissions, capabilities, and behavior/action IDs. Installation or execution of third-party code is outside this manifest loader and requires a separate reviewed mechanism.

A SHA-256 manifest field records expected bytes; it does not establish publisher identity by itself.

## API and UI

The packaged HTTP server accepts loopback bind addresses only. Static assets are public, while every API request requires a bounded local browser-session cookie. The CLI issues a 384-bit one-use URL-fragment capability only after bind; the browser strips it before any request and exchanges it once, while the server retains only its digest. The server also enforces exact Host and same-origin mutation requests, bounded JSON bodies, duplicate-key and non-finite-number rejection, fixed static-asset routes, and restrictive browser security headers.

The browser session is same-user local protection, not remote authentication, authorization, or multi-user identity. Do not expose the service through a reverse proxy, port forward, container publish rule, or tunnel without adding an independently reviewed remote authentication and authorization layer.

The UI is an adapter over the same service-side validation and policy path as the CLI. Browser controls do not directly dispatch runner actions.

## Evidence and detection honesty

Evidence records use one of these provenance values: synthetic, executed, observed, control_blocked, counterfactual, or unknown.

Executed means the runner reports that an action started. Observed means a separate observer/collector collected a declared artifact. Neither label is silently upgraded into the other. The built-in collectors are limited to bounded sandbox-file metadata/hashes and disposable JSONL fixture logs. Optional Sysmon/Event Log, auditd, packet-capture, and SIEM entries are readiness descriptors, not configured production collectors. Collector failure creates explicit `unknown` evidence rather than disappearing.

Detection candidates progress through explicit lifecycle states. Fixture exercise, observed exercise, and benign evaluation are different claims. The included internal matcher is not an authoritative external-language parser. Exact pinned pySigma parses one Sigma rule, the reviewed `pysigma-backend-sqlite==1.2.2` adapter converts it, and optional YARA-Python compiles YARA with includes disabled and warnings as errors; SPL structural checks deliberately remain hypotheses without an authoritative backend. Converted Sigma and native SQLite candidates execute only in a fresh fixed-schema in-memory database with query-only mode, an allowlisting authorizer, no extension loading, strict statement/schema checks, and VM/time/result/input caps. Dependency presence, source-intake metadata, and conversion do not prove execution: only a persisted bounded result with matching source/query/backend identities can set `source_rule_executed: true`. Review and validate candidate content with the target platform before deployment.

### Audited optional-dependency exception

The optional `pysigma==1.5.0` package currently requires `diskcache==5.6.3`, which is affected by [PYSEC-2026-2447 / GHSA-w8v5-vhqr-4h9v](https://github.com/advisories/GHSA-w8v5-vhqr-4h9v) and has no patched release. The issue requires a victim to deserialize cache data from a directory an attacker can write. BlueFire's current runtime path imports only `sigma.collection` for in-memory rule parsing; it does not import pySigma's `sigma.data.mitre_attack` or `sigma.data.mitre_d3fend` modules, instantiate `diskcache.Cache`, or accept a cache directory. The separately pinned SQLite backend declares pySigma as its only runtime dependency; adding its package record does not broaden this exception or authorize cache-backed modules. CI therefore carries one explicit `pip-audit` exception for the transitive optional dependency. Remove the exception when pySigma or DiskCache ships a patched dependency path; do not expand BlueFire's pySigma integration to those cache-backed modules while it remains in place.

## Product metadata and recovery

In addition to immutable-ish run bundles, the service maintains a migrated local SQLite product store under the run root by default. It stores secret-safe settings, content-addressed scenario versions, typed resource metadata, approval/job records, and a run index. Startup marks in-flight jobs and unfinalized bundles interrupted, then idempotently seeds reviewed built-ins.

The store rejects plaintext values under secret-shaped keys; provider and runner configuration retains environment-variable references. This does not encrypt other metadata at rest. Protect the database and run directory with operating-system access controls, external retention, and disk quotas. Product-store approval primitives do not turn the loopback service into a remotely authenticated multi-user system.

## Run-bundle security

Run IDs are generated internally. Bundle paths are restricted to fixed safe filenames, JSON writes are atomic, events are append-only, and finalized file hashes feed a bundle digest. bundle validate detects changed or missing files covered by the manifest.

Run bundles may still contain environment descriptions, scenario parameters, telemetry, filenames, or defensive observations. Apply appropriate access control and retention. Do not publish a bundle without reviewing it for sensitive data.

## Known limitations

- Compatible platform-specific wheels contain one manifest-bound native Rust runner artifact; they do not download executable content. Explicit bootstrap verifies and installs that artifact, while source-development overrides remain operator-controlled.
- Execute availability depends on verified bootstrap, active local enrollment, authenticated managed-host readiness, compatible inventory, profile/policy/preflight, and exact approval checks.
- The thirteen current actions are a bounded endpoint/sandbox pack, not general endpoint, cloud, identity, or enterprise-network emulation.
- Four `research.*` catalog entries remain metadata-only. A separate persistence-detection canary can Simulate or Execute one fixed non-executable marker inside a runner-owned sandbox under the dedicated restricted profile; it does not change host persistence.
- No configured remote telemetry collector, SIEM connector, or general network target support ships in the maintained baseline.
- Runner transport is a separately hosted same-user loopback service with local enrollment/revocation, TLS 1.3 mutual authentication, enrollment-bound task authentication, and a durable duplicate/cancellation/recovery ledger. Cross-host transport/enrollment, an external code-signing trust chain, and asymmetric signed task/profile/result artifacts are not implemented.
- Runtime AI proposals do not yet tune detections or create replay experiments, and graph edge choice is deliberately limited to the exact registered edge for the observed outcome.
- Bundle hashes and request/profile digests detect mismatch; they are not cryptographic identity signatures.
- Historical Git objects may contain unsupported direct-effect implementations; do not restore or invoke them as runner actions.

## Reporting a vulnerability

Use a private GitHub Security Advisory when possible. If that is unavailable, open a minimal issue asking maintainers for a private reporting channel; do not publish working exploit details.

The fuller design review, including malicious scenarios/plugins, compromised runners/control plane, model prompt injection, task replay, UI exposure, evidence tampering, cleanup loss, and research supply-chain risk, is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

Include:

- affected file and commit;
- affected platform and mode;
- whether the issue crosses the Python/Rust boundary;
- minimal reproduction steps using synthetic data;
- expected and observed policy, result, and evidence states;
- impact and any suggested mitigation.

Never include live credentials, customer data, or unauthorized target information.

## Verification for maintainers

Before release, run the active Python, Rust, frontend, browser, and security checks documented in README.md. Also inspect the built platform wheel to confirm that it contains only the intended `bluefire` package, catalog/config/scenario data, built UI assets, and the exact manifest-bound native runner artifact for that wheel tag—never repository tests, source build output, credentials, local paths, or unrelated executables.

Do not describe an action, platform, parser, detector, or isolation property as verified unless its applicable tests ran successfully in the release environment.
