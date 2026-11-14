import { render, screen } from "@testing-library/react";
import { expect, it } from "vitest";
import { EngineAttemptEvidence } from "../src/components/EngineAttemptEvidence";
import type { EngineAttempt, EngineEvidenceCategory } from "../src/lib/engine-experiment";

const digest = (character: string) => `sha256:${character.repeat(64)}`;
const attemptId = `engine-attempt-${"4".repeat(32)}`;

const unverifiedExecutionProof = (): EngineAttempt["execution_proof"] => ({
  status: "unverified", controller_receipt_ref: null, runtime_identity_ref: null, image_identity_ref: null, runtime_activation_ref: null, runtime_closure_ref: null, fixed_exec_receipt_ref: null, startup_overlay_ref: null, target_response_receipt_ref: null,
  installed_service_started: false, native_worker_started: false, tool_execution_proven: false, target_response_proven: false,
  model: { kind: "unverified", live_model_proof: false, lease_revocation_receipt_ref: null, bearer_redaction_attested: false },
  protocol_provider: { kind: "unverified", identity_ref: null, live_caido_proof: false }, limitations: ["Installed execution proof unavailable."],
});
const installedExecutionProof = (): EngineAttempt["execution_proof"] => ({
  status: "tool_executed", controller_receipt_ref: digest("a"), runtime_identity_ref: digest("b"), image_identity_ref: digest("c"), runtime_activation_ref: digest("d"), runtime_closure_ref: digest("e"), fixed_exec_receipt_ref: digest("f"), startup_overlay_ref: digest("0"), target_response_receipt_ref: null,
  installed_service_started: true, native_worker_started: true, tool_execution_proven: true, target_response_proven: false,
  model: { kind: "test", live_model_proof: false, lease_revocation_receipt_ref: digest("1"), bearer_redaction_attested: true },
  protocol_provider: { kind: "test_caido_protocol", identity_ref: digest("2"), live_caido_proof: false }, limitations: ["Controlled providers do not establish live services."],
});
const toolEvents = (): NonNullable<EngineAttempt["tool_events"]> => Array.from({ length: 4 }, (_, index) => ({ event_id: `engine-tool-event-${String(index + 1).repeat(24)}`, tool_name: `fixture_tool_${index + 1}`, state: "completed", receipt_ref: digest(String(index + 3)), occurred_at: `2026-11-04T12:00:${String(index + 2).padStart(2, "0")}Z` }));

function evidence(category: EngineEvidenceCategory, character: string, summary = `Controlled ${category} fixture.`): EngineAttempt["observations"][number] {
  return {
    evidence_id: `engine-evidence-${character.repeat(24)}`, attempt_id: attemptId, category,
    provenance: category === "engine_assertion" ? "engine_reported" : category === "tool_result" ? "runner_reported" : "observed",
    summary, producer: category === "engine_assertion" ? "strix.fixture" : "fixture.observer", timestamp: "2026-11-04T12:01:00Z", limitations: ["Fixture data only."],
  };
}

function attempt(observations: EngineAttempt["observations"] = []): EngineAttempt {
  return {
    attempt_id: attemptId, role: "adaptive_search", job_id: `job-${"4".repeat(32)}`, run_id: `run-20261104T120001Z-${"4".repeat(16)}`, upstream_session_id: "fixture-session",
    state: "budget_exhausted", completeness: "partial", exit_reason: "Fixture search limit reached.", started_at: "2026-11-04T12:00:00Z", finished_at: "2026-11-04T12:01:00Z",
    usage: { duration_ms: 60_000, model_requests: 2, input_tokens: 100, output_tokens: 50, tool_calls: 4, cost_microusd: 0 },
    execution_proof: installedExecutionProof(), tool_events: toolEvents(),
    findings: [{ finding_id: `engine-finding-${"5".repeat(24)}`, attempt_id: attemptId, title: "Fixture-reported path", severity: "medium", mechanism_digest: digest("5"), status: "reported", summary: "Engine-reported fixture content.", source_artifact_id: `artifact-${"5".repeat(32)}`, evidence_ids: [`engine-evidence-${"1".repeat(24)}`] }],
    observations, artifact_manifest_ref: digest("8"), artifacts: [{ artifact_id: `artifact-${"5".repeat(32)}`, attempt_id: attemptId, name: "fixture-report.json", sha256: digest("5"), bytes: 256, media_type: "application/json", access: "reviewable" }],
    cleanup: { state: "verified_absent", receipt_ref: digest("9"), finished_at: "2026-11-04T12:02:00Z", limitations: [] }, resume_supported: false,
  };
}

it("keeps all evidence categories and provenance boundaries distinct", () => {
  render(<EngineAttemptEvidence attempt={attempt([
    evidence("engine_assertion", "1"), evidence("tool_result", "2"), evidence("independent_target_effect", "3"), evidence("independent_security_outcome", "4"), evidence("legitimate_use", "6"),
  ])} />);
  for (const label of ["Engine assertion", "Tool result", "Independent target effect", "Checked security outcome", "Legitimate-use result"]) expect(screen.getByText(label)).toBeInTheDocument();
  expect(screen.getByText("3 independent")).toBeInTheDocument();
  expect(screen.getByText("Engine-reported")).toBeInTheDocument();
  expect(screen.queryByText("Engine assertion", { selector: ".engine-finding .badge" })).not.toBeInTheDocument();
});

it("renders upstream strings as inert text and retains exact identities in details", () => {
  const value = attempt([evidence("engine_assertion", "1", "<img src=x onerror=alert(1)> fixture text")]);
  render(<EngineAttemptEvidence attempt={value} />);
  expect(screen.getByText("<img src=x onerror=alert(1)> fixture text")).toBeInTheDocument();
  expect(document.querySelector("img")).toBeNull();
  expect(screen.getByText(value.findings![0]!.finding_id)).toBeInTheDocument();
  expect(screen.getAllByText(value.artifacts![0]!.artifact_id)).toHaveLength(2);
});

it("labels zero findings and missing independent observation as inconclusive", () => {
  const value = attempt([evidence("tool_result", "2")]); value.findings = [];
  render(<EngineAttemptEvidence attempt={value} />);
  expect(screen.getByText(/Absence of a finding is inconclusive/i)).toBeInTheDocument();
  expect(screen.getByText(/security outcome remain unverified/i)).toBeInTheDocument();
});

it("distinguishes unavailable collections from verified zero and preserves the manifest identity", () => {
  const value = attempt();
  value.execution_proof = unverifiedExecutionProof();
  value.tool_events = null;
  value.usage.tool_calls = null;
  value.findings = null;
  value.artifacts = null;
  render(<EngineAttemptEvidence attempt={value} />);
  expect(screen.getByText("Normalized findings are unavailable")).toBeInTheDocument();
  expect(screen.getByText("Artifact inventory is unavailable")).toBeInTheDocument();
  expect(screen.getByText(value.artifact_manifest_ref!)).toBeInTheDocument();
  expect(screen.queryByText("No finding recorded in this attempt")).not.toBeInTheDocument();
  expect(screen.queryByText("No bounded source artifact was recorded for this attempt.")).not.toBeInTheDocument();
});

it("keeps missing installed execution proof distinct from zero tool activity", () => {
  const value = attempt();
  value.execution_proof = unverifiedExecutionProof();
  value.tool_events = null;
  value.usage.tool_calls = null;
  render(<EngineAttemptEvidence attempt={value} />);
  expect(screen.getByText("Tool execution is unverified")).toBeInTheDocument();
  expect(screen.queryByText("No tool invocation was recorded")).not.toBeInTheDocument();
});

it("keeps established empty collections as actual zero", () => {
  const value = attempt();
  value.findings = [];
  value.artifacts = [];
  value.artifact_manifest_ref = null;
  render(<EngineAttemptEvidence attempt={value} />);
  expect(screen.getByText("No finding recorded in this attempt")).toBeInTheDocument();
  expect(screen.getByText("No bounded source artifact was recorded for this attempt.")).toBeInTheDocument();
  expect(screen.queryByText("Normalized findings are unavailable")).not.toBeInTheDocument();
});

it("uses unique heading identities for repeated evidence regions", () => {
  const { container } = render(<><EngineAttemptEvidence attempt={attempt()} /><EngineAttemptEvidence attempt={attempt()} /></>);
  const ids = [...container.querySelectorAll("h3[id]")].map(node => node.id);
  expect(new Set(ids).size).toBe(ids.length);
});
