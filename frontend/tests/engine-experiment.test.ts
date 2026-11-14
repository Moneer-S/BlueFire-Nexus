import { describe, expect, it } from "vitest";
import { checkedEngineExperiment } from "../src/lib/engine-experiment";

const digest = (character: string) => `sha256:${character.repeat(64)}`;
const id = (prefix: string, character: string, length = 32) => `${prefix}-${character.repeat(length)}`;
const run = (character: string, second: string) => `run-20261104T1200${second}Z-${character.repeat(16)}`;

const experimentId = id("experiment", "a");
const experimentDigest = digest("1");
const targetBefore = digest("2");
const targetAfter = digest("3");
const mechanism = digest("4");
const packageDigest = digest("5");
const scopeRef = digest("6");
const changeId = id("defense-change", "b");

const records = [
  { kind: "attempt" as const, role: "baseline" as const, owner: id("engine-attempt", "1"), job: id("job", "1"), run: run("1", "01"), evidence: id("evidence", "1", 20), assessment: "unauthorized_disclosure" as const },
  { kind: "attempt" as const, role: "adaptive_search" as const, owner: id("engine-attempt", "2"), job: id("job", "2"), run: run("2", "02"), evidence: id("evidence", "2", 20), assessment: "authorization_denied" as const },
  { kind: "check" as const, role: "retained_reproducer" as const, owner: id("controller-check", "3"), job: id("job", "3"), run: run("3", "03"), evidence: id("evidence", "3", 20), assessment: "authorization_denied" as const },
  { kind: "check" as const, role: "legitimate_use" as const, owner: id("controller-check", "4"), job: id("job", "4"), run: run("4", "04"), evidence: id("evidence", "4", 20), assessment: "legitimate_use_succeeded" as const },
] as const;

function projectedAttempt(index: 0 | 1) {
  const record = records[index];
  return {
    role: record.role, attempt_id: record.owner, job_id: record.job, run_id: record.run,
    state: "completed", completeness: "complete",
    engine: { id: "strix", version: "0.3.0-fixture", revision: "a".repeat(40), package_digest: packageDigest },
    model: { provider: "fixture.provider", id: "controlled-fixture", data_destination: "attempt-local fixture gateway" },
    target_snapshot_ref: index === 0 ? targetBefore : targetAfter, delegation_digest: digest(index === 0 ? "b" : "c"),
    execution_approval_id: id("approval", index === 0 ? "7" : "8"),
    execution_approval_digest: digest(index === 0 ? "7" : "8"),
    cleanup: { state: "verified_absent", receipt_ref: digest(index === 0 ? "9" : "a") },
    engine_evidence_count: 1, limitations: ["Labeled fixture evidence only."],
  };
}

function projectedCheck(index: 2 | 3) {
  const record = records[index];
  return {
    role: record.role, check_id: record.owner, job_id: record.job, run_id: record.run,
    state: "completed", performer: index === 2 ? "bluefire.controller" : "bluefire.trusted-client",
    mechanism_ref: mechanism, target_snapshot_ref: targetAfter,
    input_digest: digest(index === 2 ? "b" : "c"), result_digest: digest(index === 2 ? "d" : "e"),
    independent_evidence_refs: [record.evidence],
    cleanup: { state: "verified_absent", receipt_ref: digest(index === 2 ? "f" : "0") },
  };
}

function selectedBaseline() {
  const record = records[0];
  const artifactId = id("artifact", "1");
  const engineEvidenceId = id("engine-evidence", "1", 24);
  return {
    attempt_id: record.owner, role: record.role, job_id: record.job, run_id: record.run,
    upstream_session_id: "fixture-session-baseline", state: "completed", completeness: "complete",
    exit_reason: "Fixture engine completed.", started_at: "2026-11-04T12:00:01Z", finished_at: "2026-11-04T12:01:01Z",
    usage: { duration_ms: 60_000, model_requests: 2, input_tokens: 100, output_tokens: 40, tool_calls: 3, cost_microusd: 0 },
    findings: [{ finding_id: id("engine-finding", "1", 24), attempt_id: record.owner, title: "Fixture path", severity: "medium", mechanism_digest: mechanism, status: "reported", summary: "Controlled fixture finding.", source_artifact_id: artifactId, evidence_ids: [engineEvidenceId] }],
    observations: [{ evidence_id: engineEvidenceId, attempt_id: record.owner, category: "engine_assertion", provenance: "engine_reported", summary: "Fixture engine assertion.", producer: "fixture.engine", timestamp: "2026-11-04T12:00:30Z", limitations: ["Not independent evidence."] }],
    artifacts: [{ artifact_id: artifactId, attempt_id: record.owner, name: "fixture-report.json", sha256: digest("1"), bytes: 120, media_type: "application/json", access: "reviewable" }],
    cleanup: { state: "verified_absent", receipt_ref: digest("9"), finished_at: "2026-11-04T12:02:01Z", limitations: [] },
    resume_supported: false,
  };
}

function selectedReproducer() {
  const record = records[2];
  return {
    check_id: record.owner, role: record.role, job_id: record.job, run_id: record.run,
    performer: "bluefire.controller", mechanism_ref: mechanism, target_snapshot_ref: targetAfter,
    input_digest: digest("b"), result_digest: digest("d"), state: "completed",
    independent_evidence_refs: [record.evidence], created_at: "2026-11-04T12:02:01Z", settled_at: "2026-11-04T12:03:01Z",
    observations: [{ evidence_id: record.evidence, check_id: record.owner, category: "independent_security_outcome", provenance: "observed", summary: "The exact fixture mechanism was denied.", producer: "fixture.controller", timestamp: "2026-11-04T12:02:30Z", limitations: [] }],
    cleanup: { state: "verified_absent", receipt_ref: digest("f"), finished_at: "2026-11-04T12:04:01Z", limitations: [] },
  };
}

export function engineExperimentFixture(): Record<string, any> {
  const attempts = [projectedAttempt(0), projectedAttempt(1)];
  const checks = [projectedCheck(2), projectedCheck(3)];
  const observations = records.map(record => ({
    evidence_id: record.evidence, run_id: record.run,
    attempt_id: record.kind === "attempt" ? record.owner : null,
    check_id: record.kind === "check" ? record.owner : null,
    mechanism_ref: mechanism, target_snapshot_ref: record === records[0] ? targetBefore : targetAfter,
    assessment: record.assessment, record_hash: digest(record.owner.at(-1) ?? "1"),
  }));
  return {
    schema_version: "bluefire.engine-experiment-workspace.v1", workspace_digest: digest("f"),
    experiment_id: experimentId, revision: 7, experiment_digest: experimentDigest,
    objective: { objective_ref: digest("a"), title: "Controlled tenant-record defense fixture", summary: "Fixture attack, reviewed defense, exact retest, adaptive search and legitimate-use check." },
    environment: { environment_ref: digest("b"), environment_id: "fixture-lab-01", display_name: "Disposable tenant lab", platform: "linux", disposable: true },
    current_target: { snapshot_ref: targetAfter, display_name: "Generated tenant record target", captured_at: "2026-11-04T12:02:00Z" },
    engine_setup: {
      engine: { id: "strix", display_name: "Strix", version: "0.3.0-fixture", revision: "a".repeat(40), package_digest: packageDigest, sandbox_image_digest: digest("c") },
      model: { provider: "fixture.provider", id: "controlled-fixture", data_destination: "attempt-local fixture gateway", authorization_digest: digest("d"), test_provider: true },
    },
    authorization: { scope_ref: scopeRef, scope_version: "bluefire.engine-capability-delegation.v1", wall_clock_seconds: 600, action_limit: 40, artifact_byte_limit: 16_777_216, cost_limit_microunits: 0 },
    defensive_change: { change_id: changeId, state: "retained", kind: "identity", summary: "Removed the generated service identity from the fixture reader group.", mechanism_ref: mechanism, before_target_snapshot_ref: targetBefore, after_target_snapshot_ref: targetAfter, rollback_digest: digest("e"), applied_at: "2026-11-04T12:02:30Z" },
    projection: {
      schema_version: "bluefire.engine-experiment-projection.v1", experiment_id: experimentId, revision: 7,
      experiment_digest: experimentDigest, projection_digest: digest("0"), workflow_state: "complete",
      conclusion: {
        headline: "original_blocked_no_remaining_path_observed_within_limits",
        original_mechanism: { status: "established", run_id: records[0].run, support_refs: [records[0].evidence] },
        retained_reproducer: { status: "blocked", run_id: records[2].run, support_refs: [records[2].evidence] },
        adaptive_search: { status: "no_path_observed_within_limits", run_id: records[1].run, support_refs: [records[1].evidence], limit_qualified: true },
        legitimate_use: { status: "passed", run_id: records[3].run, support_refs: [records[3].evidence] },
        telemetry_health: { status: "complete", expected_sources: ["baseline", "retained_reproducer", "adaptive_search", "legitimate_use"], verified_sources: ["baseline", "retained_reproducer", "adaptive_search", "legitimate_use"], missing_sources: [] },
        cleanup: { status: "verified_absent", items: [
          { kind: "engine_attempt", id: records[0].owner, state: "verified_absent", receipt_ref: digest("9") },
          { kind: "engine_attempt", id: records[1].owner, state: "verified_absent", receipt_ref: digest("a") },
          { kind: "controller_check", id: records[2].owner, state: "verified_absent", receipt_ref: digest("f") },
          { kind: "controller_check", id: records[3].owner, state: "verified_absent", receipt_ref: digest("0") },
        ] },
        defense: { state: "retained", change_id: changeId, mechanism_ref: mechanism, before_target_snapshot_ref: targetBefore, after_target_snapshot_ref: targetAfter, current_target_snapshot_ref: targetAfter, application_receipt_ref: digest("1"), reconciliation_receipt_ref: null, rollback_operation_ref: null, rollback_receipt_ref: null },
        unknowns: ["Bounded search cannot establish that no other path exists."],
      },
      attempts, checks, observations,
      run_integrity: records.map(record => ({ run_id: record.run, terminal: true, state: "verified", detail: "Finalized fixture run and exact fixture observations verified." })),
    },
    actions: [{ kind: "open_comparison", label: "Open comparison", enabled: true, reason: "Review the bounded conclusion and supporting runs.", primary: true }],
    selected_context: { kind: "engine_attempt", attempt: selectedBaseline() },
    limitations: ["Controlled fixture responses do not establish live-model decision quality."],
  };
}

describe("engine experiment workspace parser", () => {
  it("accepts the exact workspace presenter and nested evidence-derived projection", () => {
    const parsed = checkedEngineExperiment(engineExperimentFixture(), experimentId, { kind: "engine_attempt", id: records[0].owner });
    expect(parsed.projection.attempts.map(item => item.role)).toEqual(["baseline", "adaptive_search"]);
    expect(parsed.projection.attempts.map(item => item.execution_approval_id)).toEqual([id("approval", "7"), id("approval", "8")]);
    expect(parsed.projection.attempts.every(item => item.delegation_digest !== parsed.authorization.scope_ref)).toBe(true);
    expect(parsed.projection.checks.map(item => item.role)).toEqual(["retained_reproducer", "legitimate_use"]);
    expect(parsed.selected_context?.kind).toBe("engine_attempt");
    expect(parsed.projection.conclusion.adaptive_search.limit_qualified).toBe(true);
  });

  it.each([
    ["unknown workflow state", (value: any) => { value.projection.workflow_state = "paused"; }],
    ["unsupported resume", (value: any) => { value.selected_context.attempt.resume_supported = true; }],
    ["engine assertion with independent provenance", (value: any) => { value.selected_context.attempt.observations[0].provenance = "observed"; }],
    ["invalid calendar timestamp", (value: any) => { value.selected_context.attempt.started_at = "2026-02-31T12:00:01Z"; }],
    ["engine-only fields on a controller check", (value: any) => { value.projection.checks[0].engine = { id: "strix" }; }],
    ["missing execution approval identity", (value: any) => { delete value.projection.attempts[0].execution_approval_id; }],
    ["malformed execution approval identity", (value: any) => { value.projection.attempts[0].execution_approval_id = "approval-invalid"; }],
    ["reused execution approval identity", (value: any) => { value.projection.attempts[1].execution_approval_id = value.projection.attempts[0].execution_approval_id; }],
    ["reused execution approval binding", (value: any) => { value.projection.attempts[1].execution_approval_digest = value.projection.attempts[0].execution_approval_digest; }],
    ["reused per-attempt delegation", (value: any) => { value.projection.attempts[1].delegation_digest = value.projection.attempts[0].delegation_digest; }],
    ["duplicate durable job identity", (value: any) => { value.projection.checks[0].job_id = value.projection.attempts[0].job_id; }],
    ["mismatched projection experiment identity", (value: any) => { value.projection.experiment_id = id("experiment", "f"); }],
    ["mismatched selected context", (value: any) => { value.selected_context.attempt.job_id = value.projection.attempts[1].job_id; }],
    ["observation assigned to two owners", (value: any) => { value.projection.observations[0].check_id = value.projection.checks[0].check_id; }],
    ["unqualified bounded adaptive result", (value: any) => { value.projection.conclusion.adaptive_search.limit_qualified = false; }],
    ["telemetry status inconsistent with its sources", (value: any) => { value.projection.conclusion.telemetry_health.verified_sources.pop(); value.projection.conclusion.telemetry_health.missing_sources.push("legitimate_use"); }],
    ["conclusion inconsistent with verified observation", (value: any) => { value.projection.observations[2].assessment = "unauthorized_disclosure"; }],
    ["observation attached to an unavailable run", (value: any) => { value.projection.run_integrity[0].state = "unavailable"; }],
    ["workflow state inconsistent with lifecycle records", (value: any) => { value.projection.workflow_state = "adaptive_search_active"; }],
    ["unverified selected controller observation", (value: any) => { const extra = id("evidence", "9", 20); value.selected_context = { kind: "controller_check", check: selectedReproducer() }; value.selected_context.check.independent_evidence_refs.push(extra); value.selected_context.check.observations.push({ ...value.selected_context.check.observations[0], evidence_id: extra }); value.projection.checks[0].independent_evidence_refs.push(extra); }],
    ["duplicate workspace actions", (value: any) => { value.actions.push(structuredClone(value.actions[0])); }],
  ] as const)("refuses %s", (_name, mutate) => {
    const value = structuredClone(engineExperimentFixture());
    mutate(value);
    expect(() => checkedEngineExperiment(value)).toThrow();
  });

  it("refuses route and selected-record identities that do not match the response", () => {
    expect(() => checkedEngineExperiment(engineExperimentFixture(), id("experiment", "f"))).toThrow(/identity changed/i);
    expect(() => checkedEngineExperiment(engineExperimentFixture(), experimentId, { kind: "controller_check", id: records[2].owner })).toThrow(/selected workspace context changed/i);
  });

  it("accepts only reconciliation when a defensive operation leaves current state unknown", () => {
    const value = structuredClone(engineExperimentFixture());
    value.current_target = null;
    value.defensive_change.state = "unknown";
    value.projection.conclusion.defense.state = "unknown";
    value.projection.conclusion.defense.current_target_snapshot_ref = null;
    value.projection.workflow_state = "reconcile_defense";
    value.actions = [{ kind: "reconcile_defense", label: "Reconcile defensive change", enabled: true, reason: "Inspect the target before continuing.", primary: true }];

    const parsed = checkedEngineExperiment(value);
    expect(parsed.current_target).toBeNull();
    expect(parsed.actions.filter(action => action.enabled).map(action => action.kind)).toEqual(["reconcile_defense"]);

    value.actions[0].kind = "start_adaptive_search";
    expect(() => checkedEngineExperiment(value)).toThrow(/recovery changed/i);
  });
});
