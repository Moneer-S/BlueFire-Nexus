# Architecture

BlueFire Nexus separates planning from effects. The Python package is the control plane; the Rust crate is the execution authority. The boundary is intentional: scenario, AI, plugin, or UI data can select only registered IDs and typed values, never an arbitrary executable instruction.

## System view

~~~mermaid
flowchart LR
    operator[Operator] --> cli[CLI]
    operator --> ui[React workspace]
    ui --> api[Loopback API]
    cli --> service[Platform service]
    api --> service

    config[Versioned config] --> service
    scenario[Typed scenario DAG] --> service
    catalog[Behavior/action catalog] --> service
    service --> product[(SQLite product store)]
    service --> registry[Registry validation]
    registry --> planner[Deterministic planner]
    model[AI provider] --> proposal[Strict proposal validation]
    proposal --> planner
    planner --> simulation[Simulation adapter]
    planner --> policy[Deny-by-default policy]
    policy --> adapter[RunnerActionAdapter]
    adapter --> transport[Fixed local Rust transport]
    transport --> runner[Reviewed Rust action registry]

    simulation --> evidence[Evidence graph]
    runner --> evidence
    collectors[Independent collectors] --> evidence
    evidence --> store[Run bundle store]
    store --> replay[Replay]
    store --> compare[Comparison]
    evidence --> detections[Detection lifecycle]
~~~

The UI and CLI are adapters over the same service boundary. Neither browser state nor command-line parsing is an execution authority.

## Maintained components

| Component | Responsibility | Explicit non-responsibility |
|---|---|---|
| bluefire/cli.py and bluefire/service.py | Parse operator requests and expose one JSON-serializable application service to CLI and API adapters | Bypassing domain validation or policy |
| bluefire/orchestrator.py | Preflight, step dispatch, outcome routing, normalization, cleanup, detection preparation, and run finalization | Implementing action effects |
| bluefire/contracts.py | Versioned dataclasses and strict parsing for behaviors, actions, artifacts, parameters, and scenario graphs | Dispatch or effects |
| bluefire/registry.py | Catalog loading, duplicate/reference checks, action/profile compatibility, graph/type/DAG validation | Dynamic imports or plugin execution |
| bluefire/config.py | Exactly two modes, AI autonomy/providers, environment references, runner profiles, scopes, tiers, approval requirement, budgets, cleanup policy | Resolving secrets during parsing |
| bluefire/ai.py | Deterministic and OpenAI-compatible structured proposal providers, redaction, bounds, health, and fallback | Graph authority, policy, approval, or execution |
| bluefire/planner.py | Deterministic plan compilation, outcome-edge selection, budget state, and compatible-alternate compilation | Policy bypass or action creation |
| bluefire/policy.py | Deny-by-default Execute decisions and request-bound approval checks | Performing actions |
| RunnerActionAdapter | Sole mapping from logical parameters and artifact bindings to a known Rust action's sealed parameters | Generic commands, arbitrary paths, or unknown actions |
| bluefire/runner_client.py | Fixed invocation of one configured absolute runner binary and result-correlation checks | Shell execution or behavior implementation |
| runner/ | Strict manifest/profile validation and compiled sandbox actions | Simulation, planning, UI, or arbitrary execution |
| bluefire/evidence.py and bluefire/collectors.py | Provenance records, same-run evidence graph, bounded sandbox/fixture observation, health, and explicit gaps | Treating runner self-report as independent observation |
| bluefire/detections.py | Detection lifecycle, internal matcher, pySigma/YARA adapters, SPL structural checks, fields and baselines | Claiming target-language production validity |
| bluefire/run_store.py | Contained run directories, atomic JSON snapshots, append-only events, hashes, and bundle validation | Remote storage or digital signing |
| bluefire/product_store.py and bluefire/bootstrap.py | SQLite migrations, versioned scenarios, secret-safe settings/resources, approvals/jobs, run index, recovery, and idempotent built-in seeding | Replacing immutable evidence bundles or exposing a public persistence API |
| bluefire/research.py | Strict pinned source/version/license/relationship registry | Fetching or executing external research |
| bluefire/replay.py | Lineage, restart, and compatible behavior substitution | Mutating source runs through the replay API |
| bluefire/comparison.py | Normalized run summaries and deltas | Causal inference |
| bluefire/api.py and bluefire/ui/ | Loopback-only HTTP adapter and browser workspace | Authentication for remote exposure |
| bluefire/plugins.py | Strict declarative plugin manifest inventory | Importing or executing third-party code |

## Contract model

All maintained external documents carry a fixed schema version and reject unknown fields. Stable behavior and action IDs end in a version suffix such as .v1.

A behavior definition records purpose, execution state, safety tier, platforms, technique mappings, capabilities, typed inputs and outputs, logical parameters, simulation ID, action IDs, telemetry and detection hints, provenance, and limitations.

An action definition is the control-plane description of a reviewed capability. It mirrors the behavior's logical parameter and artifact contract and declares safety, platforms, capabilities, mutations, cleanup action, and provenance.

The Rust action descriptor is a different interface. It describes the strict executor parameters and effect capabilities used after artifacts have been materialized as bounded relative paths or receipts. This distinction prevents a scenario from supplying runner-internal path and process fields directly.

RunnerActionAdapter is the only translation point:

1. accept a validated plan step and typed artifact bindings;
2. select a hard-coded adapter for the registered action ID;
3. resolve only known prior artifacts;
4. construct the action-specific sealed parameter object;
5. reject unknown fields, unknown actions, missing artifacts, absolute paths, or traversal;
6. pass the result to manifest sealing.

No generic fallback is permitted.

## Scenario graph

A scenario contains a versioned ID, purpose, start node, steps, explicit outcome edges, provenance, and limitations.

Each step selects one behavior ID, typed parameters, input bindings, and optional contract-compatible alternates. Each edge binds exactly one source-step outcome to a destination step. Outcomes are success, partial, blocked, and failed.

Validation checks:

- schema version and unknown fields;
- stable and duplicate IDs;
- behavior and alternate registry membership;
- parameter types, enums, ranges, and required values;
- required and unknown input ports;
- producer output name, type, and multiplicity;
- source dominance, so an input exists on every path reaching its consumer;
- duplicate outcome routes;
- start node, cycles, and reachability.

Six sanitized scenarios ship. The canonical seven-node sandbox graph demonstrates a contract-compatible discovery alternate and a loopback block/failure route to local export before cleanup. The Linux/container and Windows-oriented graphs add bounded system/process/filesystem discovery and deterministic archive staging; detection-regression and AI-adaptive graphs support their named review workflows. A dedicated restricted scenario exercises only a fixed, non-executable persistence-detection canary and cleanup. A scenario title is not proof of dynamic validation on that platform.

## Planning and AI

Deterministic planning is authoritative. It compiles a validated graph into a versioned plan, applies declared defaults, selects only profile-enabled action IDs in Execute, follows registered outcome edges, and records state/budget decisions.

AI autonomy is `off`, `assist`, or `auto`. Off performs no provider call. After an observed step outcome, Assist or Auto may request a strict `bluefire.ai-proposal.v2` against a request-specific immutable option envelope. A proposal can confirm the exact registered next edge for that observed outcome, select a compatible registered behavior, change allowlisted primitive parameters, choose an action registered for the exact Execute profile, or consume one bounded retry. Correlated choices and digests prevent cross-pairing. Assist pauses at durable review. Auto may apply a policy-valid Simulate choice; every Execute mutation pauses and later requires a fresh one-time Execute approval. Provider failure or invalid output uses deterministic fallback or an explicit rejected record.

The runtime loop cannot create/reorder nodes, choose an edge for another outcome, issue commands or paths, add capabilities, change profile/scope/tier/policy, approve itself, tune detections, or create replays. See [AI Planner](AI_PLANNER.md).

AI enablement does not imply Execute, and Execute does not imply AI.

## Mode paths

### Simulate

Simulate is the default and stays within the Python control plane. It applies registered simulation transitions, follows explicit edges, and records synthetic provenance. If the planner models a continuation after a failure with no real alternate, the resulting evidence is counterfactual.

Simulation must never instantiate SubprocessRustRunner. It must not label output executed or observed.

### Execute

Execute requires an explicit Execute profile. The service validates the scenario, compiles a plan, checks runner inventory, evaluates policy, obtains any required request-bound approval, translates logical inputs through RunnerActionAdapter, seals the manifest, and invokes the Rust runner.

The transport uses an argument vector equivalent to:

~~~text
bluefire-runner execute --manifest MANIFEST --profile PROFILE --json
~~~

The binary path is configured rather than selected by a scenario. The child receives a bounded environment, fixed working directory, null standard input, time limit, and output-size limits. Result run, step, and action IDs must match the request.

The Rust runner then repeats the relevant validation. It recognizes only its compiled action inventory and refuses Simulate manifests. See [Execution model](EXECUTION_MODEL.md).

## Runner profiles

A control-plane runner profile records:

- mode and environment type;
- supported platforms;
- environment references for runner binary and sandbox root;
- semantic and effect capabilities;
- allowed safety tiers;
- enabled and blocked action IDs;
- logical scope and CIDR allowlist;
- approval requirement;
- step, time, artifact, and byte budgets;
- cleanup policy;
- environment references needed at a later boundary.

The canonical example contains a default Simulate profile and a separate Execute profile. Its only network entries are IPv4 and IPv6 loopback.

At the Rust boundary, the adapter produces the runner's sealed profile schema with a concrete current platform, canonical sandbox root, action/capability allowlists, target scope, hard limits, approval threshold, and policy digest. This is another explicit translation, not loose dictionary forwarding.

## Evidence

EvidenceRecord carries:

- run, step, behavior, action, and profile identity;
- provenance;
- producer and environment;
- timestamp and parent evidence IDs;
- content and content hash;
- record hash;
- confidence and limitations;
- target-scope reference.

The provenance vocabulary is:

| Value | Claim |
|---|---|
| synthetic | A simulation or fixture model produced the record |
| executed | The runner reports that an action started |
| observed | A separate observer collected a declared sandbox artifact |
| control_blocked | A control prevented the action |
| counterfactual | A modeled branch continued without execution |
| unknown | Provenance could not be established |

EvidenceGraph rejects missing and cross-run parents. SandboxObserver resolves normalized relative paths beneath one existing sandbox root, refuses symbolic-link paths, bounds bytes/time, detects concurrent file change, and hashes file content. The collector layer adds readiness and explicit `unknown` gap records. Built-in observation remains limited to declared sandbox files and disposable JSONL fixtures; auditd, Sysmon/Event Log, PCAP, and SIEM entries are unavailable descriptors until separately implemented/configured.

## Detections

Detection candidates begin as hypotheses. Their lifecycle distinguishes parsed, fixture_exercised, observed_exercised, benign_evaluated, and rejected states.

The included structured matcher supports deterministic internal fixtures only. Optional pySigma parses Sigma and optional YARA-Python compiles YARA with includes disabled and warnings as errors, then exercises bounded fixtures. SPL receives structural checks and remains a hypothesis without an authoritative backend. Production claims still require the target backend/version, environment-specific fixtures, observed evidence where appropriate, benign evaluation, known misses, false-positive notes, and tuning decisions.

Multiple renderings of the same hypothesis do not count as independent validation.

## Storage, recovery, replay, and comparison

RunStore creates internally named, contained run directories. It stores scenario, plan, policy, profile, result, evidence, and detection JSON, plus append-only events. Finalization hashes every covered file and hashes the resulting file table. Validation detects missing or changed covered files.

Hashes are tamper indicators, not signatures.

ProductStore is a separate migrated SQLite store under the run root by default. At startup the service migrates it, marks interrupted background jobs, recovers unfinalized run bundles, idempotently seeds six scenarios, thirteen actions, profiles, providers, six collector records, research sources, and three detection backends, backfills the run index, and exposes a safe storage/recovery summary in catalog metadata. Settings and resources are JSON documents that reject secret-shaped plaintext values; environment references remain declarative.

Replay reads a captured source scenario snapshot without writing it. It can prepare an exact replay, resume after prior artifacts, substitute a contract-compatible behavior, change typed parameters, select a registered action implementation, or record declared AI, profile, or defense changes. Each replay receives lineage with a source scenario digest and the exact declared overrides.

Comparison summarizes two or more runs and reports path and first-blocked differences, objective and cleanup changes, evidence and detection deltas, telemetry and control changes, and counterfactual steps. Interpretation remains the operator's responsibility.

## API and UI

The HTTP adapter binds only to loopback addresses and serves fixed packaged assets. It rejects malformed request paths, duplicate JSON keys, non-finite constants, oversized bodies, invalid Host values, cross-origin mutation requests, and unsupported methods. Responses include a restrictive content security policy and related browser headers.

The React workspace exposes Overview, Scenarios, Builder, Runs, Compare, Behaviors, Runner Profiles, Runners, Actions, Detection Lab, Research Sources, AI Planner, Settings, and Help. Canonical graph validation, preflight, run, replay, and comparison remain service-side. Controls explicitly labeled as local drafts/settings are not authority until represented in a service response and run bundle.

Loopback is not a substitute for authentication if an operator deliberately republishes the service. Remote exposure is outside the maintained threat model.

## Plugins

Plugin manifests are data. They describe identity, semantic version, enabled state, trust, SHA-256 integrity metadata, license, source provenance, permissions, capabilities, behavior IDs, and action IDs.

The loader has no entry-point discovery and no import hook. An inventory entry alone cannot add a behavior implementation or runner action.

## Packaging boundary

The Python distribution discovers only bluefire packages. It includes catalog YAML, canonical configuration, six scenario defaults, research registry, and built UI assets as package data. Checkout config/scenario copies are parity-tested against `bluefire/data`; BlueFireService prefers checkout scenarios when present and otherwise uses package resources. Optional detection parsers remain separately installable. Package metadata reads the platform version from `bluefire.__version__`; Python, frontend, and Rust currently use the 0.1.0 baseline.

The wheel does not include repository tests or the Rust runner binary. The runner is built and deployed separately so Execute availability remains explicit.

## Current limitations

- The maintained action catalog is a bounded thirteen-action endpoint/sandbox pack, not a general execution agent.
- The four `research.*` entries remain metadata-only. A separate persistence-detection behavior has one fixed non-executable marker action under a dedicated restricted profile; no host persistence mechanism is shipped.
- No configured remote telemetry collector, SIEM connector, cloud action, identity action, or general network target is part of the baseline.
- Sigma/YARA validation requires optional pinned packages; production SPL/backend validation is not included.
- Current runner transport is local subprocess only; remote enrollment/authentication/revocation and signed tasks are not implemented.
- Run hashes do not prove author identity.
- Execute depends on local Rust build, inventory parity, profile configuration, policy, and approval; it is unavailable when any prerequisite fails.
- Mutating runner actions durably record intent before effect, publish exact bytes without overwrite, and add a commit record after verification. Pending intents and staging files remain discoverable for tamper-safe cleanup after process interruption. Host or workspace loss can still destroy recovery state; preserve the runner-owned sandbox until reconciliation is complete.
