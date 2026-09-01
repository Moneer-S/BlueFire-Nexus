# BlueFire Nexus

**A local-first workspace for designing, executing, observing, and comparing bounded purple-team experiments.**

**Design -> execute -> observe -> change defense -> replay -> compare.** BlueFire preserves the
graph, authorization, execution, observation, and lineage needed to examine what changed without
turning a model proposal or runner report into stronger evidence than it is.

> BlueFire Nexus is a pre-1.0 technical preview for systems, accounts, networks, and labs you own
> or are explicitly authorized to test. It is not a production endpoint-management, cloud-
> administration, identity, or enterprise-network agent. Read the [current limitations](#current-limitations)
> before using Execute.

- Build typed behavior graphs whose success, partial, blocked, and failed paths remain explicit.
- Run safely in Simulate or cross an approval-gated boundary to registered Rust runner actions.
- Keep predicted, executed, observed, blocked, and counterfactual evidence distinct through replay
  and comparison.

![BlueFire Nexus Scenario Builder showing a typed behavior graph](docs/assets/screenshots/builder.png)

Start with the [minimal local demo](#minimal-local-demo), then follow the
[operator guide](docs/OPERATOR_GUIDE.md) before using Execute.

## Minimal local demo

Python 3.10 or newer is required. From a source checkout, create an environment and install the
project. Docker and a runner are not required for Simulate.

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

Run the packaged sandbox scenario. Simulate is the default and writes a local run bundle.

```bash
bluefire --runs-dir .bluefire-runs scenario run \
  --scenario-id scenario.sandbox.research.chain.v1
```

Launch the product UI against the same run directory:

```bash
bluefire --runs-dir .bluefire-runs ui --host 127.0.0.1 --port 8765
```

Open the one-use URL printed after the listener is ready. The UI is a same-user loopback service,
not a remotely authenticated application; do not expose it through a proxy, tunnel, or port
forward. A successful Simulate run proves graph validation and simulation, not that a runner
action or defensive control executed.

## Product loop

1. **Design** a versioned graph from registered behaviors, typed artifacts, and explicit outcome
   edges.
2. **Execute** the experiment safely in Simulate, or select Execute mode with an exact profile, scope, budgets,
   readiness record, and one-time approval.
3. **Observe** through separately attributed collectors; action output remains `executed`, while
   independent collection is `observed`.
4. **Change defense** by recording the control or detection change rather than rewriting the
   baseline result.
5. **Replay** the immutable scenario exactly or as a declared, lineage-linked variant.
6. **Compare** paths, controls, detections, evidence, cleanup, budgets, and implementation identity
   without claiming that a difference proves causality.

## Modes and authority

BlueFire has two effect modes. AI autonomy is a separate choice and never widens runner authority.

| | Simulate | Execute |
|---|---|---|
| External effects | None | Registered and approved effects only |
| Runner | Not used | Required and independently enforcing the selected profile |
| Scope | Modeled | Explicit operator scope bounded by policy and profile |
| Evidence | Synthetic or counterfactual | Executed, blocked, or unknown; observed only from a collector |
| Approval and cleanup | Modeled | Exact approval and receipt-bound cleanup |

| AI level | What it can do | What it cannot do |
|---|---|---|
| `off` | Use the deterministic planner only | No model call |
| `assist` | Draft a typed graph or registered choice for review | Apply an actionable runtime mutation without exact-digest review |
| `auto` | Apply a policy-valid registered choice where mode and policy permit | Invent actions, expand scope, raise a tier, change the runner profile, or bypass Execute approval |

The included offline provider makes planner behavior reproducible without a live model account. A
configured OpenAI-compatible provider remains only a proposal boundary: schema validation,
allowlists, policy, runner enforcement, and approval still apply. See [AI Planner](docs/AI_PLANNER.md).

## A concrete defense-frontier workflow

The bounded defense-frontier journey exercises the full product loop against disposable,
runner-owned fixtures:

1. Builder defines an objective with a primary behavior and a semantically compatible registered
   alternate.
2. The baseline reaches a declared block and records that block as evidence instead of converting
   it to success or a generic error.
3. Auto selects only the registered alternate permitted by the typed graph and current policy.
4. Execute pauses for fresh authorization, dispatches the approved action through the Rust runner,
   and reconciles receipt-owned cleanup.
5. Independent collection is stored separately from the runner's own result.
6. The operator records the defense change and starts a controlled, lineage-linked replay.
7. Compare explains path, prevention and detection state, telemetry, objective, cleanup, budgets,
   and improvement or regression signals. It does not label a delta as causal proof.

This journey is exercised by offline release acceptance without a live provider key. It proves the
bounded registered-choice workflow, not model quality, production detector coverage, or arbitrary
adaptive execution.

## Product proof

### Run review

Run review exposes the canonical plan, completed graph path, event timeline, profile and scope,
evidence provenance, detections, approval state, and cleanup result. Synthetic expected evidence
does not become observed evidence merely because it appears in the same run.

![BlueFire Nexus Run Review showing the completed graph path and evidence timeline](docs/assets/screenshots/live-run.png)

### Replay and compare

Exact replay retains the source scenario snapshot. A declared variant records changes such as a
restart node, compatible behavior, typed parameters, action implementation, profile, autonomy, or
defense note while preserving lineage.

```bash
bluefire --runs-dir .bluefire-runs replay RUN_ID --exact
bluefire --runs-dir .bluefire-runs compare BASELINE_RUN_ID CANDIDATE_RUN_ID
```

Comparison reports supported differences across graph path, objective state, evidence provenance,
observed artifacts, detections, controls, cleanup, telemetry, budgets, planner decisions, and
implementation identity. See [Replay and compare](docs/REPLAY_COMPARE.md).

![BlueFire Nexus Compare showing baseline and lineage-linked replay lanes](docs/assets/screenshots/compare.png)

### Evidence and Detection Lab

Every evidence record has a producer and a provenance class:

| Class | Meaning |
|---|---|
| `synthetic` | Modeled or fixture-generated |
| `executed` | Reported by a runner after an action started |
| `observed` | Independently collected by a declared collector |
| `control_blocked` | A policy or defensive control prevented the action |
| `counterfactual` | Modeled continuation after a real path stopped |
| `unknown` | The requested observation could not be established |

Detection candidates progress through evidence-backed hypothesis, parse, fixture, observed, and
benign-evaluation stages, or are rejected. BlueFire supports pinned pySigma-to-SQLite conversion,
bounded evaluation for converted Sigma and native SQLite candidates, and YARA compilation and
fixture execution when the optional pinned packages are installed. SPL remains structural only.
See the [evidence model](docs/EVIDENCE_MODEL.md) and [Detection Lab](docs/DETECTION_LAB.md).

### Bounded execution

The Python control plane resolves only registered behaviors and action implementations. Execute
crosses a strict adapter into a separately built Rust runner, which revalidates inventory, profile,
request, platform, capabilities, tier, scope, limits, approval lifetime, and cleanup binding.

The runner exposes bounded compiled operations for runner-owned fixture work, platform discovery,
staging and archive, authenticated loopback transfer, reversible comparison canaries, and cleanup.
It does not expose a generic command, shell, script, arbitrary program, dynamic library, URL, proxy,
redirect, or caller-selected hostname. Consult the [action SDK](docs/ACTION_SDK.md),
[execution model](docs/EXECUTION_MODEL.md), and [runner deployment and protocol](docs/RUNNER_DEPLOYMENT.md)
for the detailed boundary.

Execute is opt-in. Before using it, prepare a disposable authorized target, verify the compatible
runner artifact, select an Execute profile, bind exact scope and collectors, inspect preflight, and
issue the one-time approval. The [operator guide](docs/OPERATOR_GUIDE.md) and
[runner profiles](docs/RUNNER_PROFILES.md) contain the focused procedure.

### Reviewed source intake

One reviewed declarative source is vendored: the MITRE ATT&CK Enterprise T1082 metadata record
`bluefire/data/mitre_attack_t1082_v19_2.json`, pinned to `mitre/cti` commit
`8543c5b05bd9bbcace9fc37f30bba96b675b6f33`. Intake verifies the exact source and projects only
neutral metadata; descriptions, procedures, citations, command examples, and unrelated references
are discarded. The mapped runner action is independently implemented, and no MITRE endorsement is
implied. See [source intake](docs/SOURCE_INTAKE.md) and [third-party notices](THIRD_PARTY_NOTICES.md).

### Machine-verifiable release evidence

The release authority runs the committed, ordered acceptance contract against a clean checkout and
persists hashed gate receipts. Documentation is never accepted as gate proof, and an incomplete or
failed receipt remains a failed gate.

```bash
bluefire acceptance run --release
bluefire acceptance verify --result path/to/acceptance-result.json
```

The verifier rechecks the locked contract, canonical run bundles, and referenced evidence bytes.
See [development and complete testing](docs/DEVELOPMENT.md) for the full local verification matrix;
the [pre-release baseline](docs/PRE_RELEASE_BASELINE.md) records historical scope and non-claims but
does not satisfy a release gate.

## Supported platforms

| Surface | Current boundary |
|---|---|
| Python control plane | Python 3.10+ on Windows, Linux, and macOS-compatible environments |
| Rust runner | Verified native Windows x86_64 wheel; commit-bound Linux x86_64 musl artifact for disposable validation; source builds for development |
| Linux proof | Native dynamic execution in a fresh disposable WSL2 environment during release acceptance |
| macOS proof | Structural when no macOS host is available |
| Network actions | Literal loopback addresses in shipped actions and profiles |
| Managed runner | Separate same-user loopback process with local enrollment; no cross-host runner is shipped |
| Cloud identity | One reversible AWS identity lab with deterministic local proof; real-account smoke is manual and separately confirmed |

## Current limitations

- BlueFire is local-first and pre-1.0. Its browser API has same-user loopback session protection,
  not remote or multi-user authentication.
- The managed runner is a per-user process, not an operating-system service. Linux acceptance proves
  the commit-bound artifact in a disposable WSL2 environment, not a general Linux installer;
  dynamic macOS execution has not been validated.
- Remote and cross-host runner transport, enrollment, and validation are not shipped.
- The native action boundary is intentionally narrow and has no generic shell or arbitrary program
  execution.
- Built-in independent observation covers declared sandbox files, one exactly authorized child
  process on Windows/Linux, and authenticated bindings from a managed loopback receiver. Host audit,
  cloud audit, packet capture, EDR, and SIEM adapters remain unavailable readiness contracts.
- The AWS identity surface is one reversible disposable-role tagging lab. Automated proof uses a
  deterministic backend; real-account smoke requires an operator-supplied named profile and exact
  manual confirmation. It is not general cloud administration.
- Detection Lab is a bounded local evaluator, not a production SIEM connector. SPL is structural
  only, and public rules are provenance-retaining baselines rather than automatic evasion targets.
- Live model endpoint connectivity and model quality are outside offline acceptance. The
  deterministic provider proves orchestration and authority boundaries only.
- Bundle and event hashes detect modification but are not digital signatures or proof of who
  produced a bundle.
- Comparison reports supported deltas and coarse signals; it does not prove that a declared defense
  change caused them or that a detector was bypassed.

Unavailable or structural integrations stay labeled that way. See the
[release capability classification](docs/RELEASE_CAPABILITIES.md) for the authoritative shipped,
fixture-only, structural, and unavailable boundaries.

## Focused documentation

- **Architecture:** [system architecture](docs/ARCHITECTURE.md) and
  [execution model](docs/EXECUTION_MODEL.md)
- **API:** [local API](docs/API.md) and [CLI reference](docs/CLI.md)
- **Runner protocol:** [deployment, enrollment, transport, receipts, and cleanup](docs/RUNNER_DEPLOYMENT.md)
- **Security internals:** [security policy](SECURITY.md), [threat model](docs/THREAT_MODEL.md), and
  [responsible use](docs/RESPONSIBLE_USE.md)
- **Complete testing:** [development and verification](docs/DEVELOPMENT.md) and
  [contributing](CONTRIBUTING.md)
- **Deep reference:** [operator guide](docs/OPERATOR_GUIDE.md),
  [evidence model](docs/EVIDENCE_MODEL.md), [behavior authoring](docs/BEHAVIOR_AUTHORING.md),
  [source intake](docs/SOURCE_INTAKE.md), and [third-party notices](THIRD_PARTY_NOTICES.md)

Additional focused guides cover [installation](docs/INSTALLATION.md),
[configuration](docs/CONFIGURATION.md), [troubleshooting](docs/TROUBLESHOOTING.md),
[AI planning](docs/AI_PLANNER.md), [Detection Lab](docs/DETECTION_LAB.md), and
[replay and compare](docs/REPLAY_COMPARE.md).

## Responsible use and license

Use BlueFire Nexus only on systems, accounts, networks, and labs you own or are explicitly
authorized to test. Start in Simulate, use least-privilege runner profiles, prefer disposable
targets, review every Execute plan, and verify cleanup.

Report security issues privately as described in the [security policy](SECURITY.md). BlueFire Nexus
is licensed under the [MIT License](LICENSE).
