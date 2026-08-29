# User guide

This guide covers normal local operation. Begin with Simulate. Use Execute only after reading [Runner deployment](RUNNER_DEPLOYMENT.md), [Runner profiles](RUNNER_PROFILES.md), and [Responsible use](RESPONSIBLE_USE.md). For exact command syntax and JSON request-file contracts, see the [command-line reference](CLI.md).

## Start the application

From an installed development checkout:

```bash
bluefire --runs-dir .bluefire-runs ui --host 127.0.0.1 --port 8765
```

Open the exact one-use URL printed after the listener is ready. Its fragment capability is stripped before request dispatch and exchanged for a bounded HttpOnly local API session. Do not log or share that URL. A bare URL is accepted only when the browser already holds the session; otherwise relaunch with `bluefire ui`. The UI, CLI, and HTTP API use the same `BlueFireService`, scenario validation, planner, policy, runner adapter, and run store.

## Product areas

| Area | Use it for |
|---|---|
| Overview | Readiness, recent runs, evidence mix, and next actions |
| Getting Started | Follow live readiness checks from scenario selection through durable review |
| Scenarios | Browse the six seeded versioned graphs and open the authoritative active definition for editing/running |
| Builder | Edit typed nodes, parameters, bindings, outcomes, alternates, and route-depth layout; use focus mode and commands |
| Runs | Configure, preflight, start, and open durable run history or deep links |
| Compare | Select a baseline and one or more candidate runs |
| Behaviors | Inspect contracts, readiness, observables, provenance, and limitations |
| Runner Profiles / Runners | Inspect scope and capability policy or runner readiness |
| Actions | Inspect logical actions and the Rust inventory boundary |
| Detection Lab | Create, clone, tune, exercise, reject, and compare immutable candidate revisions |
| Research Sources | Inspect pins, licenses, source-intake classifications, attribution, and cache policy |
| AI Planner | Select autonomy/provider and review planner decisions |
| Settings | Manage theme plus browser-side effect/autonomy preferences; inspect backend settings authority |
| Help | Concepts and common readiness failures |

Management resources and saved scenario versions are durable local backend records. The unsaved working graph remains a browser draft until it is validated and saved. A control is authoritative only when it appears in backend preflight and the finalized run bundle. The browser never writes an arbitrary local path or plaintext secret value.

## Getting started

Open **Getting Started** from the navigation or the Overview empty state. It reads live service, scenario, run-history, and Detection Lab readiness rather than presenting a static success checklist. Follow its four links in order:

1. choose a scenario and read its purpose, limitations, and provenance;
2. open Builder and validate typed nodes, routes, artifact bindings, and cleanup;
3. configure a deterministic Simulate preflight with AI Off and resolve every finding;
4. open the durable result and review evidence, limitations, and cleanup.

The walkthrough does not claim that Execute is ready merely because Simulate works. Execute remains unavailable until a current runner identity, inventory, platform, sandbox probe, profile, scope, policy, and exact approval all bind successfully.

## Work in Builder

Builder edits the browser's unsaved working graph. Drag or select registered behaviors, connect typed artifact ports and outcome routes, inspect node parameters, and validate before saving a durable scenario version. Metadata-only behaviors remain labeled and cannot imply Execute support.

For a large graph:

- use **Auto layout** to arrange nodes by outcome-route depth;
- use **Fit graph** or **Fit selection** to restore context;
- collapse the behavior palette or inspector independently;
- enter graph focus mode and press `Esc` to leave it;
- open **Commands** or press `Ctrl+K` / `Cmd+K` for layout, panel, focus, validation, undo, and redo actions;
- review the confirmation before deleting selected nodes or edges; a confirmed change can be undone.

Graph export downloads a local JSON copy. It does not save, validate, authorize, or execute the graph.

The Runs page repeats a compact **Builder handoff** summary before preflight. Treat it as a bridge, not authority: it identifies whether the graph is still an unsaved browser draft, shows node/route counts, reports Execute action overrides and local review state, and names the next required move. Backend preflight remains the only authorization boundary for a specific run.

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

### Real loopback primary path

The canonical sandbox research chain's network step has a real, bounded primary path. Before an authorized Execute run that uses `sandbox.network.loopback.v1`, start the built-in receiver in a separate unprivileged terminal:

```bash
bluefire receiver --host 127.0.0.1 --port 4317 \
  --max-requests 1 --max-connections 16 \
  --max-body-bytes 5242880 --idle-timeout 300
```

It loads only the active managed enrollment, issues an authenticated one-time challenge, and accepts only the exact loopback artifact route. The challenge, request, and acknowledgement bind the task, ephemeral session, nonce, listener, length, and SHA-256; the runner verifies each HMAC in constant time and treats the body as opaque bytes. `--max-requests` counts verified artifacts while `--max-connections` separately bounds accepted and refused connections and must be at least twice the accepted-artifact limit. Default operation transiently buffers at most the configured body limit and does not persist the body. `--storage-dir` is an explicit opt-in to an empty, dedicated, receiver-owned directory with content-addressed filenames. The default idle window is a bounded 300 seconds and remains explicitly configurable. This authenticates the same-user managed receiver session, but it is not remote transport or a general HTTP server. Without a ready receiver, the primary network action can fail and the scenario may follow only its declared alternate; do not report that alternate as a successful primary-path exercise. See [Runner deployment](RUNNER_DEPLOYMENT.md#provision-the-loopback-receiver) and the [CLI reference](CLI.md#loopback-artifact-receiver).

For `scenario.endpoint.deep-behavior-lab.v1`, use the separate-terminal command `bluefire receiver --host 127.0.0.1 --port 4317 --max-requests 1 --disposable-peer`. This one-shot mode is always memory-only, tolerates only a bounded eight total connections, limits each connection to five seconds, and has 240-second idle and absolute lifetime caps. It exits after the single accepted artifact. The v2/v3 peer protocol binds the receiver PID and declared lifecycle into authentication, while acceptance must independently confirm the distinct PID and its exit; a receipt field alone is not process observation.

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

The Runs page stores history in the backend, not only in browser memory. Open `/runs/RUN_ID` for a durable review link; it can be bookmarked or reloaded as long as the same product database and run store are available. The page keeps modeled evidence separate from real runner output, shows human-readable summary rows, and leaves raw JSON collapsed for detailed inspection. A missing run returns a real not-found state rather than reconstructing a browser demo.

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
2. Parse and convert Sigma through the pinned SQLite backend, parse a bounded native SQLite query, or compile YARA with YARA-Python.
3. Exercise deterministic malicious fixtures.
4. Link only independently `observed` evidence for observed exercise.
5. Evaluate benign fixtures and record false-positive notes.
6. Clone an immutable candidate when a new editable revision should retain the same semantics, or tune it when selection/log-source semantics change.
7. Compare revisions from the same lineage and review source, rule, fields, lifecycle, malicious-fixture, observed-evidence, and benign-fixture deltas.
8. Compare with attributed public baselines.
9. Retain field drift, known misses, and tuning decisions.

The Detection Lab UI creates strict hypotheses, exposes clone/tune as new content-addressed revisions, and compares siblings without overwriting their parents. Its public-baseline selector uses only registered pinned Research Source records and preserves the digest of the validated registered metadata document, pin, version, license review, relationship, source-intake classification, and comparison use. That digest is not a hash of fetched external bytes; BlueFire does not fetch the reference. The CLI exposes the same lifecycle through `bluefire detections ...`; see the [detection command reference](CLI.md#detection-lab) and [Source intake](SOURCE_INTAKE.md).

Backend parser/compiler functionality is provided by `ExternalDetectionValidator`; rendered source or an enabled browser button is not evidence that validation ran. Trust the persisted candidate state, backend name/version, ordered lifecycle history, and immutable definition/lineage digests. See [Detection Lab](DETECTION_LAB.md).

The optional detection dependency set pins `pysigma-backend-sqlite==1.2.2`. The pin and its Research Source record do not mean a candidate was converted or executed. A parsed Sigma response retains the conversion backend, versions, source/query identity, mapping, and unsupported fields while explicitly recording `source_rule_executed: false`; malicious-fixture or immutable observed-evidence evaluation must execute the freshly reconverted query before that claim becomes true. Native SQLite candidates use the same bounded executor.

## Settings authority

The Settings page controls three browser concerns: theme, the preferred effect mode, and preferred AI autonomy. Theme is applied and restored in the browser; all three preferences can hydrate from and save to the secret-safe `ui.preferences` backend setting. Effect/autonomy values are only starting choices for a run.

Settings do not control safety tier, target scope, runner profile policy, capabilities, action allowlists, approvals, cleanup, budgets, runner endpoint, identity, inventory, or readiness. Those values come from validated backend resources and the selected profile, and the exact effective values must appear in preflight and the run bundle. Browser preferences are not substitutes for canonical configuration.

Use `bluefire settings list` to inspect durable records and `bluefire settings set ui.preferences document.json` for the exact versioned preference object. Other setting keys and authority fields are rejected. Never store credentials or local secret values there.

## Common problems

### Runner unavailable

Read status first; it is inert and never repairs readiness implicitly. If the runner is unbootstrapped, explicitly bootstrap the compatible packaged artifact and local enrollment. If it is stopped, explicitly start the authenticated host. A stale process record must be reconciled with `runner stop`, not with upgrade. Then confirm host platform, artifact/inventory compatibility, active enrollment, authenticated transport, selected profile, and action parity:

```bash
bluefire --config config/bluefire.example.yaml runner status --profile sandbox-execute.v1
bluefire --config config/bluefire.example.yaml runner bootstrap --profile sandbox-execute.v1
bluefire --config config/bluefire.example.yaml runner start --profile sandbox-execute.v1
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

## Current boundaries

BlueFire is local-first and pre-1.0. Keep these limits visible when interpreting a successful workflow:

- the browser API and artifact receiver bind loopback; the artifact receiver uses active managed enrollment and per-task HMAC, while neither surface is remote transport;
- the runner action pack is bounded and has no general shell or arbitrary program execution;
- only the narrow sandbox persistence-detection canary and authorized same-host disposable peer exercise are available under dedicated profiles; real host persistence plus broad credential, remote lateral-movement, and defense-evasion `research.*` Execute families remain unavailable;
- built-in independent observation is limited to declared sandbox files and disposable JSONL fixtures; optional audit/SIEM collectors remain unavailable until separately implemented and configured;
- plugins are declarative metadata only and do not load Python entry points or add connector capabilities;
- Detection Lab provides bounded local Sigma/SQLite execution but no SIEM deployment connector, production SPL validation, or automatic public-corpus synchronization;
- hashes establish bundle consistency, not a digital signature or producer identity.

See the README's [current limitations](../README.md#current-limitations), [Threat model](THREAT_MODEL.md), and [Responsible use](RESPONSIBLE_USE.md) before broadening any lab.
