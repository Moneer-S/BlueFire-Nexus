import { render, screen } from "@testing-library/react";
import { expect, it } from "vitest";
import { EngineAttemptEvidence } from "../src/components/EngineAttemptEvidence";
import type { EngineAttempt, EngineEvidenceCategory } from "../src/lib/engine-experiment";

const digest = (character: string) => `sha256:${character.repeat(64)}`;
const attemptId = `engine-attempt-${"4".repeat(32)}`;

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
    findings: [{ finding_id: `engine-finding-${"5".repeat(24)}`, attempt_id: attemptId, title: "Fixture-reported path", severity: "medium", mechanism_digest: digest("5"), status: "reported", summary: "Engine-reported fixture content.", source_artifact_id: `artifact-${"5".repeat(32)}`, evidence_ids: [`engine-evidence-${"1".repeat(24)}`] }],
    observations, artifacts: [{ artifact_id: `artifact-${"5".repeat(32)}`, attempt_id: attemptId, name: "fixture-report.json", sha256: digest("5"), bytes: 256, media_type: "application/json", access: "reviewable" }],
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
  expect(screen.getByText(value.findings[0]!.finding_id)).toBeInTheDocument();
  expect(screen.getAllByText(value.artifacts[0]!.artifact_id)).toHaveLength(2);
});

it("labels zero findings and missing independent observation as inconclusive", () => {
  const value = attempt([evidence("tool_result", "2")]); value.findings = [];
  render(<EngineAttemptEvidence attempt={value} />);
  expect(screen.getByText(/Absence of a finding is inconclusive/i)).toBeInTheDocument();
  expect(screen.getByText(/security outcome remain unverified/i)).toBeInTheDocument();
});

it("uses unique heading identities for repeated evidence regions", () => {
  const { container } = render(<><EngineAttemptEvidence attempt={attempt()} /><EngineAttemptEvidence attempt={attempt()} /></>);
  const ids = [...container.querySelectorAll("h3[id]")].map(node => node.id);
  expect(new Set(ids).size).toBe(ids.length);
});
