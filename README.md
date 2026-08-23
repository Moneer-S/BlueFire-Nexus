# BlueFire Nexus

BlueFire Nexus 0.1.0 is an evidence-first control plane for bounded security experiments. It validates typed scenario graphs, plans neutral behaviors, records provenance, and stores replayable run bundles. Python owns orchestration and policy; a separately built Rust runner is the only component allowed to perform reviewed actions.

The maintained product has exactly two modes:

| Mode | Default | Meaning |
|---|---:|---|
| **Simulate** | Yes | Models state transitions and emits explicitly synthetic or counterfactual evidence. It does not launch the Rust runner. |
| **Execute** | No | Dispatches only registered action IDs through an explicit runner profile after policy and approval checks. |

There is no generic command, shell, script, payload, identity-specific pack, or implicit plugin execution interface.

## Current scope

The active bluefire package provides:

- strict, versioned behavior, action, scenario, configuration, plugin, evidence, and planner contracts;
- a deterministic planner with typed artifact bindings and explicit outcome edges;
- deny-by-default Execute policy and approval binding;
- a Python-to-Rust transport with a fixed argument grammar;
- tamper-evident local run bundles, replay preparation, and run comparison;
- a loopback-only HTTP API and packaged browser UI;
- a detection-candidate lifecycle that keeps hypotheses distinct from exercised candidates;
- a neutral sandbox catalog and a seven-step fixture research scenario.

The Rust crate under runner/ contains eight bounded sandbox actions. It must be built and configured separately. A source checkout or a successful simulation does not prove that an Execute runner is installed, compatible, or authorized; check runner inventory and preflight first.

Four credential, persistence, lateral-movement, and defense-evasion research entries are intentionally metadata_only. They preserve neutral technique and observable concepts for detection research, but have no simulation adapter or executable action.

## Install

Python 3.10 or newer is required.

~~~bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
~~~

The Python runtime dependency is PyYAML. The wheel includes the neutral catalog, UI assets, canonical default configuration, and canonical sandbox scenario; checkout copies are parity-tested against those packaged defaults. The package does not install or download a runner, AI provider, browser, telemetry collector, or SIEM connector.

The path-based examples below assume a source checkout. In a standalone wheel installation, the service and UI fall back to the packaged configuration and scenario; provide your own scenario path to path-based CLI commands.

## Start safely

Validate and preview the included scenario:

~~~bash
bluefire scenario validate scenarios/sandbox_research_chain.yaml
bluefire scenario preview scenarios/sandbox_research_chain.yaml
~~~

Run it in the default Simulate mode and inspect the resulting local history:

~~~bash
bluefire --runs-dir runs scenario run scenarios/sandbox_research_chain.yaml
bluefire --runs-dir runs runs list
bluefire --runs-dir runs bundle validate RUN_ID
~~~

Start the local UI:

~~~bash
bluefire --runs-dir runs ui --host 127.0.0.1 --port 8765
~~~

The server refuses non-loopback bind addresses. The UI, CLI, and API are adapters over the same control-plane service and policy path.

Use bluefire --help and the help for each subcommand as the authoritative option reference.

The command groups are deliberately small:

| Command | Purpose |
|---|---|
| bluefire scenario validate | Parse and validate a scenario without running it |
| bluefire scenario preview | Compile and preflight a Simulate or Execute plan |
| bluefire scenario run | Create a run through the same validated service path |
| bluefire runner status | Inspect configured runner availability and inventory parity |
| bluefire runs list or detail | Inspect normalized local run records |
| bluefire replay | Prepare a lineage-linked exact or declared variant replay |
| bluefire compare | Compare two or more normalized runs |
| bluefire bundle validate | Verify a finalized run bundle's file table and hashes |
| bluefire plugins inventory | Show declarative plugin inventory; it does not load code |
| bluefire research status | Show which behaviors are executable, simulated, or metadata only |
| bluefire ui | Start the loopback-only browser workspace |

## Execute mode

Execute is deliberately not a more permissive form of Simulate. It requires all of the following:

1. A locally built, compatible bluefire-runner binary.
2. An existing sandbox root owned for the experiment.
3. An explicit Execute runner profile whose platform, action allowlist, capabilities, safety tiers, network scope, cleanup policy, and resource budgets permit the request.
4. A registered behavior/action pair and a successful runner inventory compatibility check.
5. A fresh approval bound to the exact request, action, profile, and target-scope digest when the profile requires it.

Build the runner with a local Rust toolchain:

~~~bash
cargo build --release --manifest-path runner/Cargo.toml
~~~

Set BLUEFIRE_RUNNER_BINARY and BLUEFIRE_SANDBOX_ROOT to local paths, then use the Execute profile in config/bluefire.example.yaml as a template. Environment values are resolved only at the boundary that needs them; configuration objects retain environment-variable references rather than secret or path values.

Before any Execute request:

~~~bash
bluefire --config config/bluefire.example.yaml runner status --profile sandbox-execute.v1
bluefire --config config/bluefire.example.yaml scenario preview \
  scenarios/sandbox_research_chain.yaml --mode execute --profile sandbox-execute.v1
~~~

Only after reviewing that preflight should an operator use scenario run --mode execute with the explicit profile and approval options. The runner independently revalidates the sealed manifest and profile. A Python policy decision cannot force the runner to accept an invalid request.

The logical catalog parameters and typed artifact bindings are intentionally distinct from the Rust executor's sealed parameter objects. RunnerActionAdapter is the sole translation point. It maps only known action IDs and validated relative artifact references; arbitrary fields and unknown actions are refused.

See [the execution model](docs/EXECUTION_MODEL.md) for the complete boundary and refusal model.

## Scenario and catalog model

scenarios/sandbox_research_chain.yaml demonstrates:

- seven registered steps;
- typed artifact propagation;
- an interchangeable discovery behavior with an identical logical contract;
- explicit success, partial, blocked, and failed edges;
- a blocked loopback step that falls back to local export;
- cleanup bound to the original runner-owned workspace.

Validation rejects unknown fields, unversioned IDs, duplicate steps or outcome routes, cycles, unreachable nodes, incompatible alternates, type mismatches, and bindings whose source is not guaranteed on every incoming path.

The eight reviewed action IDs are:

~~~text
sandbox.fixture.create.v1
sandbox.fixture.transform.v1
sandbox.discovery.list.v1
sandbox.discovery.metadata.v1
sandbox.collection.stage.v1
sandbox.network.loopback.v1
sandbox.export.local.v1
sandbox.cleanup.v1
~~~

They are sandbox actions, not a claim of general host or network emulation. Network scope in the example profile is limited to 127.0.0.1/32 and ::1/128.

## Evidence, detections, replay, and comparison

Evidence provenance is explicit:

- synthetic: produced by a model or fixture simulation;
- executed: reported by a runner after an action started;
- observed: independently collected from a declared sandbox artifact;
- control_blocked: evidence that a control prevented the requested action;
- counterfactual: a modeled continuation after a blocked or failed branch;
- unknown: retained when provenance cannot be established.

These labels are not interchangeable. Synthetic telemetry is not proof of execution, runner output is not independent observation, and a blocked request is not a successful action.

Detection candidates move through explicit lifecycle states. The included structured matcher can exercise declared fixtures and observed evidence, but it is not an authoritative parser for every target detection language. Generated hypotheses still require the relevant external parser/backend and environment-specific evaluation before production use.

Finalized run bundles capture scenario, plan, policy, profile, result, evidence, and detection snapshots; an append-only event stream; and a file table with hashes and a bundle digest. bundle validate checks those hashes. A digest detects modification but is not a digital signature or proof of authorship.

Replay creates lineage-linked variants without mutating the source snapshot. It supports exact replay, restart from a node, compatible behavior swaps, and declared profile, AI, or defense changes. Comparison reports path divergence, blocked controls, evidence-provenance deltas, detection-state deltas, telemetry changes, objective state, and cleanup state. It does not by itself establish scientific causality.

## Plugins and AI

Plugin support is declarative inventory only. Manifests carry version, trust, integrity, license, provenance, permissions, capability IDs, behavior IDs, and action IDs. Loading a manifest does not import Python entry points or execute plugin code.

AI enablement is independent of Simulate/Execute mode. AI decisions are untrusted proposals and must pass the same strict planner schema, registered-ID, parameter, edge, budget, and forbidden-field validation as any other proposal. AI cannot create an action, expand runner scope, or bypass policy and approval.

## Repository boundaries

- bluefire/: maintained Python package and packaged UI/catalog data.
- bluefire/data/: packaged configuration and scenario defaults used when checkout copies are absent.
- runner/: separately built Rust execution authority.
- config/bluefire.example.yaml: canonical configuration example.
- scenarios/sandbox_research_chain.yaml: canonical neutral scenario.
- tests_platform/: active Python verification suite.

Superseded Python effects, compatibility modes, identity-specific wrappers, and stale scenarios have been retired from the working tree. Their Git history is migration reference only and does not define a supported runner action.

## Development

~~~bash
python -m pytest
python -m ruff check bluefire tests_platform
python -m build

cargo fmt --check --manifest-path runner/Cargo.toml
cargo clippy --manifest-path runner/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path runner/Cargo.toml
~~~

See [the architecture](docs/ARCHITECTURE.md), [the execution model](docs/EXECUTION_MODEL.md), [the migration guide](docs/MIGRATION.md), and [the security policy](SECURITY.md) before extending the execution boundary.

## Responsible use

Use BlueFire Nexus only in environments you own or are explicitly authorized to test. The default catalog is intentionally bounded, but configuration, local deployment, and operator authorization remain your responsibility. Report vulnerabilities through the process in [SECURITY.md](SECURITY.md).

BlueFire Nexus is licensed under the [MIT License](LICENSE).
