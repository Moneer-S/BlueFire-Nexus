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

const unverifiedExecutionProof = () => ({
  status: "unverified", controller_receipt_ref: null, runtime_identity_ref: null, image_identity_ref: null, runtime_activation_ref: null, runtime_closure_ref: null, fixed_exec_receipt_ref: null, startup_overlay_ref: null, target_response_receipt_ref: null,
  installed_service_started: false, native_worker_started: false, tool_execution_proven: false, target_response_proven: false,
  model: { kind: "unverified", live_model_proof: false, lease_revocation_receipt_ref: null, bearer_redaction_attested: false },
  protocol_provider: { kind: "unverified", identity_ref: null, live_caido_proof: false }, limitations: ["Installed execution proof unavailable."],
});
const installedExecutionProof = (toolExecution: boolean) => ({
  status: toolExecution ? "tool_executed" : "runtime_started", controller_receipt_ref: digest("a"), runtime_identity_ref: digest("b"), image_identity_ref: digest("c"), runtime_activation_ref: digest("d"), runtime_closure_ref: digest("e"), fixed_exec_receipt_ref: digest("f"), startup_overlay_ref: digest("0"), target_response_receipt_ref: null,
  installed_service_started: true, native_worker_started: true, tool_execution_proven: toolExecution, target_response_proven: false,
  model: { kind: "test", live_model_proof: false, lease_revocation_receipt_ref: digest("1"), bearer_redaction_attested: true },
  protocol_provider: { kind: "test_caido_protocol", identity_ref: digest("2"), live_caido_proof: false }, limitations: ["Controlled providers do not establish live services."],
});
const toolEvents = (count: number) => Array.from({ length: count }, (_, index) => ({ event_id: id("engine-tool-event", String(index + 1), 24), tool_name: `fixture_tool_${index + 1}`, state: "completed", receipt_ref: digest(String(index + 3)), occurred_at: `2026-11-04T12:00:${String(index + 2).padStart(2, "0")}Z` }));

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
    exit_reason: null, started_at: "2026-11-04T12:00:01Z", finished_at: "2026-11-04T12:01:01Z",
    usage: { duration_ms: 60_000, model_requests: 2, input_tokens: 100, output_tokens: 40, tool_calls: 3, cost_microusd: 0 },
    execution_proof: installedExecutionProof(true), tool_events: toolEvents(3),
    findings: [{ finding_id: id("engine-finding", "1", 24), attempt_id: record.owner, title: "Fixture path", severity: "medium", mechanism_digest: mechanism, status: "reported", summary: "Controlled fixture finding.", source_artifact_id: artifactId, evidence_ids: [engineEvidenceId] }],
    observations: [{ evidence_id: engineEvidenceId, attempt_id: record.owner, category: "engine_assertion", provenance: "engine_reported", summary: "Fixture engine assertion.", producer: "fixture.engine", timestamp: "2026-11-04T12:00:30Z", limitations: ["Not independent evidence."] }],
    artifact_manifest_ref: digest("2"), artifacts: [{ artifact_id: artifactId, attempt_id: record.owner, name: "fixture-report.json", sha256: digest("1"), bytes: 120, media_type: "application/json", access: "reviewable" }],
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

  it("keeps unavailable attempt usage and collections distinct from zero", () => {
    const value = engineExperimentFixture();
    value.selected_context.attempt.usage = { duration_ms: 60_000, model_requests: null, input_tokens: null, output_tokens: null, tool_calls: null, cost_microusd: null };
    value.selected_context.attempt.execution_proof = unverifiedExecutionProof();
    value.selected_context.attempt.tool_events = null;
    value.selected_context.attempt.findings = null;
    value.selected_context.attempt.artifacts = null;

    const parsed = checkedEngineExperiment(value);

    expect(parsed.selected_context?.kind).toBe("engine_attempt");
    if (parsed.selected_context?.kind !== "engine_attempt") throw new Error("Fixture selection changed.");
    expect(parsed.selected_context.attempt.usage.tool_calls).toBeNull();
    expect(parsed.selected_context.attempt.findings).toBeNull();
    expect(parsed.selected_context.attempt.artifacts).toBeNull();
    expect(parsed.selected_context.attempt.artifact_manifest_ref).toBe(digest("2"));
  });

  it("preserves established zero usage and empty collections", () => {
    const value = engineExperimentFixture();
    value.selected_context.attempt.usage = { duration_ms: 0, model_requests: 0, input_tokens: 0, output_tokens: 0, tool_calls: 0, cost_microusd: 0 };
    value.selected_context.attempt.finished_at = value.selected_context.attempt.started_at;
    value.selected_context.attempt.execution_proof = installedExecutionProof(false);
    value.selected_context.attempt.tool_events = [];
    value.selected_context.attempt.findings = [];
    value.selected_context.attempt.artifacts = [];
    value.selected_context.attempt.artifact_manifest_ref = null;

    const parsed = checkedEngineExperiment(value);

    if (parsed.selected_context?.kind !== "engine_attempt") throw new Error("Fixture selection changed.");
    expect(parsed.selected_context.attempt.usage).toEqual({ duration_ms: 0, model_requests: 0, input_tokens: 0, output_tokens: 0, tool_calls: 0, cost_microusd: 0 });
    expect(parsed.selected_context.attempt.findings).toEqual([]);
    expect(parsed.selected_context.attempt.artifacts).toEqual([]);
  });

  it("retains the response receipt only with an independently observed target result", () => {
    const value = engineExperimentFixture();
    value.selected_context.attempt.execution_proof.status = "target_observed";
    value.selected_context.attempt.execution_proof.target_response_proven = true;
    value.selected_context.attempt.execution_proof.target_response_receipt_ref = digest("9");
    value.selected_context.attempt.observations.push({ evidence_id: records[0].evidence, attempt_id: records[0].owner, category: "independent_security_outcome", provenance: "observed", summary: "Target response independently observed.", producer: "fixture.controller", timestamp: "2026-11-04T12:00:31Z", limitations: [] });

    const parsed = checkedEngineExperiment(value);

    if (parsed.selected_context?.kind !== "engine_attempt") throw new Error("Fixture selection changed.");
    expect(parsed.selected_context.attempt.execution_proof.target_response_receipt_ref).toBe(digest("9"));
  });

  it.each([
    ["unknown workflow state", (value: any) => { value.projection.workflow_state = "paused"; }],
    ["unsupported resume", (value: any) => { value.selected_context.attempt.resume_supported = true; }],
    ["engine assertion with independent provenance", (value: any) => { value.selected_context.attempt.observations[0].provenance = "observed"; }],
    ["invalid calendar timestamp", (value: any) => { value.selected_context.attempt.started_at = "2026-02-31T12:00:01Z"; }],
    ["unavailable duration despite complete timing", (value: any) => { value.selected_context.attempt.usage.duration_ms = null; }],
    ["exit reason on a completed attempt", (value: any) => { value.selected_context.attempt.exit_reason = "Unexpected completed reason."; }],
    ["missing reason on an incomplete terminal attempt", (value: any) => { value.selected_context.attempt.state = "failed"; value.selected_context.attempt.completeness = "partial"; value.selected_context.attempt.exit_reason = null; value.projection.attempts[0].state = "failed"; value.projection.attempts[0].completeness = "partial"; }],
    ["engine-only fields on a controller check", (value: any) => { value.projection.checks[0].engine = { id: "strix" }; }],
    ["missing execution approval identity", (value: any) => { delete value.projection.attempts[0].execution_approval_id; }],
    ["malformed execution approval identity", (value: any) => { value.projection.attempts[0].execution_approval_id = "approval-invalid"; }],
    ["reused execution approval identity", (value: any) => { value.projection.attempts[1].execution_approval_id = value.projection.attempts[0].execution_approval_id; }],
    ["reused execution approval binding", (value: any) => { value.projection.attempts[1].execution_approval_digest = value.projection.attempts[0].execution_approval_digest; }],
    ["reused per-attempt delegation", (value: any) => { value.projection.attempts[1].delegation_digest = value.projection.attempts[0].delegation_digest; }],
    ["duplicate durable job identity", (value: any) => { value.projection.checks[0].job_id = value.projection.attempts[0].job_id; }],
    ["mismatched projection experiment identity", (value: any) => { value.projection.experiment_id = id("experiment", "f"); }],
    ["mismatched selected context", (value: any) => { value.selected_context.attempt.job_id = value.projection.attempts[1].job_id; }],
    ["live proof under a configured test provider", (value: any) => { value.selected_context.attempt.execution_proof.model.kind = "live"; value.selected_context.attempt.execution_proof.model.live_model_proof = true; }],
    ["tool execution without a completed invocation", (value: any) => { value.selected_context.attempt.tool_events.forEach((event: any) => { event.state = "failed"; }); }],
    ["target proof without a response receipt", (value: any) => { value.selected_context.attempt.execution_proof.status = "target_observed"; value.selected_context.attempt.execution_proof.target_response_proven = true; }],
    ["target proof without an independent observation", (value: any) => { value.selected_context.attempt.execution_proof.status = "target_observed"; value.selected_context.attempt.execution_proof.target_response_proven = true; value.selected_context.attempt.execution_proof.target_response_receipt_ref = digest("9"); }],
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
