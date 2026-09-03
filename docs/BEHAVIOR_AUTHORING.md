# Behavior and scenario authoring

Behaviors describe **what** a security experiment does and should observe. Actions describe **how** a reviewed runner performs one implementation. Scenarios connect behavior contracts into a typed directed acyclic graph.

Use neutral technical names. Do not use actor, campaign, customer, or environment branding.

## Behavior contract

Every `bluefire.behavior.v1` entry declares:

- stable versioned `id`, title, and purpose;
- `execution_state`: `simulation`, `action`, or `metadata_only`;
- safety tier and supported platforms;
- technique mappings and capabilities;
- typed input/output artifact ports;
- typed bounded parameters;
- simulation ID and/or action IDs appropriate to readiness;
- expected telemetry and detection hints;
- source provenance and limitations.

Rules:

- `metadata_only` cannot declare a simulation or action.
- `simulation` requires a simulation ID.
- `action` requires at least one action ID; it may also have a simulation.
- capabilities and platforms cannot be empty.
- unknown fields and duplicate values are rejected.

Example:

```yaml
- schema_version: bluefire.behavior.v1
  id: endpoint.discovery.system.v1
  title: Discover bounded system identity
  purpose: Observe operating-system and architecture facts through compiled APIs.
  execution_state: action
  safety_tier: safe
  platforms: [windows, linux, macos]
  techniques: [T1082]
  capabilities: [endpoint.discovery, system.discovery]
  inputs: []
  outputs:
    - name: system
      type: artifact.endpoint.system-profile.v1
  parameters: []
  simulation_id: simulation.endpoint.discovery.system.v1
  action_ids: [endpoint.discovery.system.v1]
  telemetry: [endpoint.system.discovered]
  detection_hints:
    - Compare runner-reported facts with an independent platform collector.
  provenance:
    source: BlueFire Nexus reviewed catalog
    reference: canonical endpoint discovery contract
    license: MIT
    derived: false
    notes: Neutral cross-platform contract.
  limitations:
    - Reports a bounded fact set; it is not a full hardware or identity inventory.
```

## Artifacts

An artifact port has a lowercase snake-case name, a namespaced type, and optional `required`, `multiple`, and description fields. Types are exact: `artifact.sandbox.workspace.v1` is not compatible with `artifact.sandbox.fixture.v1`.

A scenario input binding names a prior step and one of its outputs:

```yaml
inputs:
  workspace:
    from_step: create_fixture
    artifact: workspace
```

The producer must dominate the consumer: the artifact must exist on every route that can reach the consuming step.

## Parameters

Supported types are `string`, `integer`, `number`, `boolean`, and `string_list`. A parameter may declare `required`, `default`, `minimum`, `maximum`, `enum`, and description where compatible with its type.

Prefer enums and small numeric bounds. Never model a command, script, executable, payload, URL, credential value, or filesystem path as a generic parameter. Use semantic choices and let a reviewed action adapter derive executor details.

## Simulation

A simulation transition must be deterministic for the same scenario/config seed and emit only synthetic or counterfactual evidence. It may model expected observables and declared outcome routes. It must not:

- instantiate runner transport;
- perform filesystem/process/network effects;
- label evidence executed or observed;
- simulate metadata-only behavior as if available;
- claim a defensive product fired without a fixture that explicitly models that outcome.

## Execute readiness

An action-ready behavior needs:

- a matching logical action contract;
- one or more compiled Rust action descriptors;
- an explicit `RunnerActionAdapter` mapping;
- action/profile/platform/capability/tier compatibility;
- target-scope semantics;
- receipt/cleanup behavior for mutations;
- runner and control-plane tests.

`execution_state: action` is catalog readiness, not proof that a runner is installed or that the action has been dynamically tested on every declared platform.

## Compatible alternates

Alternates must have the same input, output, and parameter signature. Use them for implementation choice—not for silently changing the behavior's contract or risk.

```yaml
- id: discover_records
  behavior_id: sandbox.discovery.list.v1
  alternates: [sandbox.discovery.metadata.v1]
  parameters: {record_limit: 25}
  inputs:
    fixture: {from_step: transform_fixture, artifact: fixture}
```

## Scenario graph

A `bluefire.scenario.v1` document contains `id`, `title`, `purpose`, `start`, `steps`, `edges`, provenance, and limitations.

Each edge binds one outcome to a destination:

```yaml
edges:
  - from_step: try_loopback
    outcome: success
    to_step: cleanup_workspace
  - from_step: try_loopback
    outcome: blocked
    to_step: export_locally
```

Supported edge outcomes are `success`, `partial`, `blocked`, and `failed`. No implicit next-step order exists.

## Cleanup design

Every route after a mutating action must converge on a cleanup behavior. Cleanup consumes a typed workspace in the logical graph, while the adapter supplies the outstanding runner-owned receipt IDs. Do not let the scenario choose deletion paths.

If a failure route cannot clean safely, terminate visibly with outstanding effects rather than presenting the objective as complete.

## Evidence and detection design

For each behavior, document:

- expected runner report;
- possible independent collectors;
- predicted canonical fields;
- control-block observable;
- at least one detection hypothesis or an explicit reason none applies;
- false-positive considerations and known telemetry dependencies.

Technique mappings provide research context; they do not make a behavior complete or executable.

## Provenance

Record whether source material was imported, adapted, inspired, or used comparatively in the research registry. Include a public reference, version/pin, retrieval date, license, and notes. Never copy a public command or rule blindly, and never claim independent observation from source metadata.

## Validation checklist

```bash
bluefire scenario validate path/to/scenario.yaml
bluefire scenario preview path/to/scenario.yaml
python -m pytest tests_platform/test_registry.py tests_platform/test_scenario.py tests_platform/test_simulation.py
```

Also test invalid parameters, wrong artifact types/multiplicity, non-dominating producers, incompatible alternates, duplicate outcomes, cycles, unreachable nodes, policy refusal, scope refusal, partial paths, control blocks, cleanup, deterministic simulation, and bundle replay.
