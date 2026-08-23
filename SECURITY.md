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

**Execute** is explicit. It requires an Execute profile, a compatible runner inventory, a registered action, policy approval, and request-bound operator approval when required. Execute can create or transform sandbox files, inspect sandbox metadata, stage or locally export sandbox artifacts, send to an explicitly allowed loopback socket, and remove receipt-owned artifacts. Those are real local effects.

Changing an AI flag, scenario parameter, or UI control does not change these mode guarantees.

## Execution boundary

Python owns contracts, catalog lookup, graph validation, planning, policy evaluation, manifest construction, result normalization, evidence storage, detection lifecycle, replay, comparison, CLI, API, and UI.

Python does not implement behavior actions. SubprocessRustRunner may start only one preconfigured, existing absolute runner binary with a fixed argument grammar. The transport rejects executable-content fields such as generic commands, shells, scripts, payloads, interpreters, and binaries.

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

The example references BLUEFIRE_RUNNER_BINARY and BLUEFIRE_SANDBOX_ROOT by name. Set them in a protected local environment appropriate to your platform.

AI enablement is independent of execution mode. No AI provider dependency or credential is installed by the base package. Any future provider adapter must keep credentials out of plans and artifacts and must treat provider output as untrusted input.

## Plugins

Plugin manifests are declarative. Loading a manifest does not import Python entry points or execute plugin code. Manifests must declare version, trust, SHA-256 integrity metadata, license, provenance, permissions, capabilities, and behavior/action IDs. Installation or execution of third-party code is outside this manifest loader and requires a separate reviewed mechanism.

A SHA-256 manifest field records expected bytes; it does not establish publisher identity by itself.

## API and UI

The packaged HTTP server accepts loopback bind addresses only. It enforces same-origin mutation requests, bounded JSON bodies, duplicate-key and non-finite-number rejection, fixed static-asset routes, and restrictive browser security headers.

Loopback binding reduces exposure but is not authentication. Do not expose the service through a reverse proxy, port forward, container publish rule, or tunnel without adding an independently reviewed authentication and authorization layer.

The UI is an adapter over the same service-side validation and policy path as the CLI. Browser controls do not directly dispatch runner actions.

## Evidence and detection honesty

Evidence records use one of these provenance values: synthetic, executed, observed, control_blocked, counterfactual, or unknown.

Executed means the runner reports that an action started. Observed means a separate observer collected a declared sandbox artifact. Neither label is silently upgraded into the other. The included observer is filesystem-only and explicitly records that limitation.

Detection candidates progress through explicit lifecycle states. Fixture exercise, observed exercise, and benign evaluation are different claims. The included structured matcher is not an authoritative parser or backend for every detection language. Review and validate candidate content with the target platform before deployment.

## Run-bundle security

Run IDs are generated internally. Bundle paths are restricted to fixed safe filenames, JSON writes are atomic, events are append-only, and finalized file hashes feed a bundle digest. bundle validate detects changed or missing files covered by the manifest.

Run bundles may still contain environment descriptions, scenario parameters, telemetry, filenames, or defensive observations. Apply appropriate access control and retention. Do not publish a bundle without reviewing it for sensitive data.

## Known limitations

- The Python wheel does not contain or install the Rust runner.
- Execute availability depends on a locally built compatible runner and a passing inventory/preflight check.
- The current actions are a bounded sandbox slice, not general endpoint, cloud, identity, or enterprise-network emulation.
- Restricted research behaviors are metadata only and cannot be simulated or executed.
- No remote telemetry collector, SIEM connector, or general network target support ships in the maintained baseline.
- Bundle hashes and request/profile digests detect mismatch; they are not cryptographic identity signatures.
- Historical Git objects may contain unsupported direct-effect implementations; do not restore or invoke them as runner actions.

## Reporting a vulnerability

Use a private GitHub Security Advisory when possible. If that is unavailable, open a minimal issue asking maintainers for a private reporting channel; do not publish working exploit details.

Include:

- affected file and commit;
- affected platform and mode;
- whether the issue crosses the Python/Rust boundary;
- minimal reproduction steps using synthetic data;
- expected and observed policy, result, and evidence states;
- impact and any suggested mitigation.

Never include live credentials, customer data, or unauthorized target information.

## Verification for maintainers

Before release, run the active Python and Rust checks documented in README.md. Also inspect the built wheel to confirm that it contains only the bluefire package, catalog YAML, and UI assets.

Do not describe an action, platform, parser, detector, or isolation property as verified unless its applicable tests ran successfully in the release environment.
