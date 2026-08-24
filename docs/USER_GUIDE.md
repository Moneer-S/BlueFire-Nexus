# User guide

This guide covers normal local operation. Begin with Simulate. Use Execute only after reading [Runner deployment](RUNNER_DEPLOYMENT.md), [Runner profiles](RUNNER_PROFILES.md), and [Responsible use](RESPONSIBLE_USE.md).

## Start the application

From an installed development checkout:

```bash
bluefire --runs-dir .bluefire-runs ui --host 127.0.0.1 --port 8765
```

Open `http://127.0.0.1:8765`. The UI, CLI, and HTTP API use the same `BlueFireService`, scenario validation, planner, policy, runner adapter, and run store.

## Product areas

| Area | Use it for |
|---|---|
| Overview | Readiness, recent runs, evidence mix, and next actions |
| Scenarios | Browse the six packaged graphs and open one for editing/running |
| Builder | Edit typed nodes, parameters, bindings, outcomes, alternates, and layout |
| Runs | Configure, preflight, start, and review run records |
| Compare | Select a baseline and one or more candidate runs |
| Behaviors | Inspect contracts, readiness, observables, provenance, and limitations |
| Runner Profiles / Runners | Inspect scope and capability policy or runner readiness |
| Actions | Inspect logical actions and the Rust inventory boundary |
| Detection Lab | Review lifecycle state, fixtures, fields, and baseline notes |
| Research Sources | Inspect pins, licenses, relationships, and cache policy |
| AI Planner | Select autonomy/provider and review planner decisions |
| Settings | Manage browser-side defaults, theme, and declarative import/export |
| Help | Concepts and common readiness failures |

Management resources and saved scenario versions are durable local backend records. The unsaved working graph remains a browser draft until it is validated and saved. A control is authoritative only when it appears in backend preflight and the finalized run bundle. The browser never writes an arbitrary local path or plaintext secret value.

## Choose and validate a scenario

The packaged graphs are listed in the README. For a first run, choose `scenario.sandbox.research.chain.v1`.

Before running:

1. Confirm the purpose and limitations.
2. Inspect every behavior and alternate.
3. Check that typed input ports come from an earlier producer.
4. Verify explicit routes for `partial`, `blocked`, or `failed` outcomes where continuation is intended.
5. Verify every mutating path reaches cleanup.
6. Run validation, then preflight.

CLI equivalents:

```bash
bluefire scenario validate scenarios/sandbox_research_chain.yaml
bluefire scenario preview scenarios/sandbox_research_chain.yaml
```

Validation rejects unknown fields/IDs, invalid parameters, incompatible bindings or alternates, duplicate outcome routes, cycles, unreachable nodes, and an artifact producer that does not dominate its consumer.

## Configure a run

### Effect mode

- **Simulate**: no runner and no external effects. Evidence is synthetic or counterfactual.
- **Execute**: explicit profile, scope, runner, approval, and cleanup. Effects are real but limited to registered actions.

### AI autonomy

- **Off**: deterministic planner; no model call.
- **Assist**: the provider may propose the exact observed next edge, a compatible behavior, bounded primitive parameters, an exact-profile action, or one retry; every actionable proposal pauses at durable exact-digest review.
- **Auto**: a schema-valid, policy-valid choice may be applied automatically in Simulate. Every Execute mutation still pauses for proposal review and a fresh exact Execute approval.

Autonomy does not alter effect mode.

### Runner profile and scope

Execute requires one Execute profile and explicit scope references. Select only the references required by the graph. The shipped profile uses:

- `sandbox.workspace`
- `network.loopback`
- `export.local`

The profile is a maximum. The operator's run scope can be narrower, never broader.

The restricted canary scenario requires `sandbox-restricted-owned.v1`. That profile has no network scope and can dispatch only `sandbox.restricted.persistence-marker.v1` plus cleanup. The action writes `restricted/persistence-marker.json` inside the bound runner workspace; it does not create operating-system persistence.

### Approval

Review the exact plan, target scope, actions, tiers, capabilities, budgets, expected effects, and cleanup before approval. Changing an action, parameter, profile, or scope changes the bound request.

The local approval identity is an audit label for the current OS user, not organizational authorization or authentication.

## Preflight

Do not interpret the presence of a Run button as readiness. Preflight reports:

- selected mode/profile and runner readiness;
- graph and action compatibility;
- required capabilities and maximum tier;
- requested target scope;
- approval state;
- cleanup policy/action;
- AI autonomy/provider metadata;
- refusal findings.

Resolve a refusal by fixing the graph, environment, or least-privilege profile—not by broadly enabling actions or scope.

## Run and review

During a run, keep these states separate:

1. planner decision;
2. model proposal and application state;
3. policy decision;
4. runner dispatch/result;
5. independent evidence arrival;
6. detection lifecycle transition;
7. cleanup result.

A blocked step may follow an explicit alternate real path or an explicitly counterfactual continuation. A failed implementation, policy refusal, and defensive prevention are different outcomes.

After completion, review:

- objective reached or prevented;
- path and first block/refusal;
- actions, targets, profile, and policy reasons;
- evidence graph and provenance counts;
- predicted versus observed fields;
- detection states and matches;
- cleanup and outstanding receipt count;
- provider/model/fallback metadata;
- limitations and bundle digest.

Validate the bundle before sharing or comparison:

```bash
bluefire --runs-dir .bluefire-runs bundle validate RUN_ID
```

## Replay and compare

Exact replay:

```bash
bluefire --runs-dir .bluefire-runs replay RUN_ID --exact
```

Variant replay:

```bash
bluefire --runs-dir .bluefire-runs replay RUN_ID \
  --from-step-id discover_records \
  --autonomy off \
  --defense-change "Enabled reviewed detection revision 2"
```

Comparison:

```bash
bluefire --runs-dir .bluefire-runs compare BASELINE_RUN_ID CANDIDATE_RUN_ID
```

The first run is the baseline. Treat `improved`, `regressed`, and `mixed` as summary signals, not scientific causality. See [Replay and compare](REPLAY_COMPARE.md).

## Detection workflow

1. Start with a behavior-linked hypothesis.
2. Parse Sigma with pySigma or compile YARA with YARA-Python.
3. Exercise deterministic malicious fixtures.
4. Link only independently `observed` evidence for observed exercise.
5. Evaluate benign fixtures and record false-positive notes.
6. Compare with attributed public baselines.
7. Retain field drift, known misses, and tuning decisions.

The UI can create and inspect local drafts. Backend parser/compiler functionality is provided by `ExternalDetectionValidator`; a disabled UI button is not evidence that validation ran. See [Detection Lab](DETECTION_LAB.md).

## Common problems

### Runner unavailable

Confirm the environment references, binary existence, sandbox root, host platform, inventory schema, and profile/action parity:

```bash
bluefire --config config/bluefire.example.yaml runner status --profile sandbox-execute.v1
```

### Scope refused

The graph's adapted action needs a scope reference missing from the operator request, or the request exceeds the profile. Add only a profile-authorized reference that is part of the approved objective.

### Approval required

Run preflight, review the exact request, and approve that request. Do not reuse an old approval after changing parameters, action, profile, or scope.

### Provider unavailable

Use AI Off for deterministic operation. Check the configured provider ID, endpoint policy, environment-variable reference, timeout, and provider health. Never paste a token into scenario YAML or a browser field.

### Observed evidence missing

Runner output is `executed`, not `observed`. Check collector readiness and limits. BlueFire records unavailable collection as `unknown`; it should not be relabeled.

### Cleanup incomplete

Stop further runs in that sandbox. Preserve the runner's receipt state, inspect retained paths and mismatch reasons, and clean only after confirming ownership. A modified receipt-owned object is intentionally retained.

### Interrupted job

Do not treat an interrupted Execute job as resumable authority. Startup first reconciles the exact privately bound workspace and publishes a recovery audit record. Once recovery is settled, use Retry to create a new job; Execute retry always repeats preflight and requires a fresh one-time approval.
