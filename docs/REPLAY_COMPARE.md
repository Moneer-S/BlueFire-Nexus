# Replay and compare

Replay answers “what happens if I repeat or declare one controlled change?” Comparison summarizes the resulting differences. Neither feature establishes causality by itself.

## Replay invariants

- The source run and its scenario snapshot are never mutated.
- Every replay has a new run ID, timestamps, events, evidence, detections, and bundle digest.
- Restored material keeps its source lineage; replay does not upgrade provenance merely because the prefix was recreated and verified.
- Execute replay still requires current runner availability, target scope, policy, and approval.
- A defense-change note is metadata; BlueFire does not deploy the defense change.

## Exact replay

```bash
bluefire --runs-dir .bluefire-runs replay RUN_ID --exact
```

Exact replay retains the immutable scenario snapshot and source autonomy/provider/profile selection. “Exact” describes the declared BlueFire inputs. Time, host state, collector readiness, provider response, and defenses can still differ, so an Execute result is not guaranteed byte-for-byte identical.

`--exact` cannot be combined with variant options.

## Variant replay

Supported declared variants are:

- restart from a step;
- swap one step to a declared or contract-compatible behavior;
- merge partial typed parameter changes into one step through the UI/API;
- change autonomy (`off`, `assist`, `auto`);
- change AI provider;
- change runner profile;
- override a registered per-step Execute action implementation;
- record a defense-change note.

```bash
bluefire --runs-dir .bluefire-runs replay RUN_ID \
  --from-step-id discover_records \
  --swap-step-id discover_records \
  --swap-behavior-id sandbox.discovery.metadata.v1 \
  --action-implementation discover_records=sandbox.discovery.metadata.v1 \
  --autonomy off \
  --defense-change "Detection candidate revision 2 enabled"
```

For an Execute replay, also supply the current explicit scope and approval as required.

The local UI and API expose typed parameter replay through `parameter_overrides`; the current CLI does not have a parameter-override flag. Each step object is a partial change merged into the source parameters, and the complete merged object is validated against the selected behavior before planning.

Execute replay preserves every untouched source action choice. An explicit action override must belong to the replayed step behavior and be enabled by the current exact profile. When a compatible behavior swap has no explicit action override, BlueFire drops only that step's obsolete source action and deterministically resolves the replacement behavior's enabled action. The resulting full map is recorded in lineage and receives a fresh exact approval.

### Restart from node

Execute restart selects a trusted content-addressed materialized checkpoint captured before the requested node.
The manifest binds the source run, scenario and plan, executed prefix, material file hashes,
artifacts, profile, scope, catalog authority, runner identity and inventory, collector lineage, and
successful cleanup state. A fresh Execute workspace deterministically recreates the prefix and
verifies its material and artifact hashes before continuing. It never reuses source receipts or
approval; current authority is revalidated and a new exact approval and cleanup receipts are
required. Corrupt, missing, cross-profile, out-of-scope, or prefix-mutating checkpoints are
refused before continuation.

### Node substitution

The replacement must be listed as an alternate or have the same input/output/parameter signature according to the registry. Existing parameters are validated against the replacement. Replay cannot use substitution to introduce an unknown action or different risk contract.

## Lineage

`bluefire.replay-lineage.v1` records:

- source run ID and source scenario digest;
- exact/variant flag;
- restart and substitution IDs;
- complete validated parameter overrides;
- autonomy before/after and whether changed;
- provider before/after and whether changed;
- whether profile changed;
- source, explicit override, reselected-step, and resolved action-implementation maps;
- defense-change note.

Lineage should accompany any report or comparison built from a replay.

## Comparison

Compare at least two unique run IDs. The first is the baseline:

```bash
bluefire --runs-dir .bluefire-runs compare BASELINE_RUN_ID CANDIDATE_RUN_ID [MORE_RUN_IDS...]
```

The result contains normalized summaries and one delta from the baseline to each candidate.

### Summary fields

- mode and runner profile;
- target-scope count/digest and sanitized replay lineage;
- path, per-step outcomes, and outcome counts;
- first blocked/refused step and objective state;
- evidence counts by provenance, independent producer counts, observed artifact identities, and hashed evidence gaps;
- detection lifecycle counts, malicious matches, and benign matches;
- telemetry and policy/control states;
- cleanup success;
- autonomy, provider, proposal count, and application states;
- remaining planner budgets and duration;
- counterfactual steps.

### Delta fields

- first path-divergence index;
- block, objective, and cleanup changes;
- evidence, observed artifact, evidence-gap, detection, match, benign-match, and outcome deltas;
- telemetry/control additions and removals;
- target-scope, replay-lineage, autonomy/provider/proposal/duration changes;
- coarse signals and `improved`, `regressed`, `mixed`, or `no_material_change` assessment.

Replay lineage summaries include the source run, source scenario digest, declared Variant labels, restart/substitution IDs, parameter override step/name lists, action-implementation override/reselection steps, AI/provider/profile change flags, and a hash of any defense-change note. They do not echo the raw defense-change text or raw target-scope references into comparison output.

The assessment is a transparent heuristic. More observed evidence is not always better; more detection matches can accompany more benign matches; a shorter path may indicate prevention or missing telemetry. Read the underlying summaries.

## Detection-regression workflow

1. Run `scenarios/detection_regression.yaml` in Simulate or an authorized disposable Execute lab.
2. Validate and preserve the baseline bundle.
3. Change a detection/control outside BlueFire, or record the planned change for a synthetic exercise.
4. Replay exactly with a `defense_change` note, or use one deliberate variant.
5. Compare baseline and candidate.
6. Inspect path/control differences before detection counts.
7. Inspect evidence provenance and predicted/observed fields.
8. Inspect malicious and benign match deltas.
9. Record limitations and whether the defense change was actually deployed or only modeled.

## Reproducibility checklist

- Are source and candidate bundles valid?
- Is the source scenario digest preserved?
- Is exactly one intended variable changed?
- Are mode, profile, scope, action inventory, autonomy, and provider recorded?
- Is model fallback visible?
- Are fixture seeds and collector readiness stable?
- Are executed and observed evidence separated?
- Is cleanup complete for both runs?
- Are environmental changes outside BlueFire documented?
- Does the conclusion avoid causal language unsupported by the design?
