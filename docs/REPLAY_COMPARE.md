# Replay and compare

Replay answers “what happens if I repeat or declare one controlled change?” Comparison summarizes the resulting differences. Neither feature establishes causality by itself.

## Replay invariants

- The source run and its scenario snapshot are never mutated.
- Every replay has a new run ID, timestamps, events, evidence, detections, and bundle digest.
- Restored material keeps its source lineage; replay does not upgrade provenance merely because the prefix was recreated and verified.
- Execute replay still requires current runner availability, target scope, policy, and approval.
- A defense-change note is metadata; BlueFire does not deploy the defense change.

## Prepare a replay for review

`POST /api/v1/runs/{run_id}/replay-preparations` accepts the existing exact or
variant replay options, without `approval`. It returns the actual prospective
`scenario`, resolved `lineage`, and canonical `preflight`, including the full
Execute approval binding and envelope when applicable. It does not create a run,
job, approval, execution workspace, or effect. Execute preparation probes current
runner readiness; it does not claim readiness when that probe is unavailable.

The response declares `replay_extent: "full"` or `"from_step"` to match the
requested restart position. Execute from-step review includes the validated
restoration plan in `binding.resolution.restoration_plan`, with its hash in the
lineage. Both restoration and restart position are bound into fresh approval.
Simulate from-step replay retains only validated synthetic prefix artifacts.

After review, submit the returned `replay_request` unchanged to
`POST /api/v1/runs/{run_id}/replays`, adding the returned `preparation_id` and
`preparation_context`. Execute also requires its normal explicit operator
`approval`. Both preparation fields must be present together. The context is
limited to 64 KiB of ordinary public readiness metadata. It is not approval or
a secret capability and should be passed through from the server response.

Submission revalidates the source bundle and the resolved graph, plan, profile,
provider, scope, catalog and collectors. Execute independently probes all live
readiness identities against the reviewed snapshot and checks its freshness;
the original snapshot is retained only when these checks succeed, preserving
the exact displayed approval digest. Changed, expired, or invalid review state
requires preparing and reviewing again before effects. Repeated preparation
may refresh the readiness timestamp and therefore produce a new preparation ID.
Legacy replay clients that omit both preparation fields retain their current
explicit approval flow.

### Durable replay jobs

`POST /api/v1/runs/{run_id}/replay-jobs` accepts the same prepared replay
submission plus a canonical UUID `submission_id`. Inline `approval` is refused.
Keep that UUID for retries of the same HTTP submission: the same bound intent
returns the existing job; reusing it with changed source, options or preparation
is refused. A new intended replay needs a new UUID.

The endpoint returns HTTP 202 with `job`, `preflight`, `preparation`, and a
nonce-free `approval_request`. Jobs use the existing `bluefire.job.v1` schema and
`kind: "scenario.replay"`. Execute waits for the existing separate
`POST /api/v1/jobs/{job_id}/approve` operation with `approved_by`; it revalidates
the exact preparation and consumes the existing one-time approval before the
worker can claim it. Submission and worker dispatch independently revalidate
the preparation too.

Use the existing jobs inventory and job detail, pause, resume and cancel
operations. The immutable stored request has
`schema_version: "bluefire.replay-job-request.v1"`, `source_run_id`, derived
`mode`, `scenario_id`, `runner_profile_id`, `autonomy` and `ai_provider_id`,
plus `replay_request` and `replay_preparation`. Execute also retains the exact
`target_scope`; Simulate has no effect scope in the request wrapper. Recover the
review display from `job.request.replay_preparation.preflight`. The server also
stores its approval reference and submission receipt; callers cannot supply
either as authority.

`result_ref` links to the saved replay run. Check the job lifecycle and the
saved run's finalized status before treating that reference as completion; an
AI proposal review can pause a job with a saved intermediate run. After a
service restart, unfinished jobs become interrupted and are never automatically
re-executed. The existing retry operation first requires settled Execute
workspace cleanup, then creates a fresh preparation, submission UUID and
approval. Replay lineage is retained. From-step replay uses this same saved-job
path: its preparation reports `replay_extent: "from_step"`, and Execute binds
the validated checkpoint restoration plan and restart step into both the review
identity and fresh approval. The runner recreates the earlier steps in a new
workspace, verifies their material against the checkpoint, then continues.
Source receipts are never reused. The legacy synchronous endpoint remains
available for existing clients.

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

### Guided method test

In Compare, open **Test a different method**. Select a finalized run with independent observations, a step with a registered compatible alternative, and a saved SQLite or Sigma rule. State the question you want to test. Off sends no model request. Assist presents the proposed method for review; Auto may accept a valid bounded option. Both modes stop an Execute replay for a separate fresh approval in Runs.

The operation repeats the full experiment with one method substitution. It preserves the original scope, profile and explicit observer configuration, and sets runtime AI Off so no additional adaptive method change is introduced. Review the displayed change from the original autonomy setting. The model selects only an option prepared by the service; it cannot choose a new scope, profile, command or detector.

After the replay finalizes and cleanup settles, BlueFire evaluates the same saved detector against the original and replay observations and retains both reports with the run comparison. **Same detector, two methods** shows measured matches, missing evidence, query execution and cleanup separately. A synthetic replay without observations remains insufficient evidence. The source informs method selection, so this is exploratory development work; use separate benign and withheld cases before drawing a coverage conclusion.

The method-test link survives reload. An uncertain submission retains its exact request identity. A saved acceptance recovers its reserved replay job, while Execute still needs its own approval. If analysis fails after a replay result exists, **Recover comparison only** verifies and evaluates the existing runs; it never repeats their effects. Stop cancels the current operation while preserving recorded results. A later explicit analysis retry cannot reopen stopped replay publication.

The result view reads the retained comparison and evaluations and verifies their bound identities. **Download saved run comparison** exports that existing run report; the detector evaluation records remain available in the result's evidence details.

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
