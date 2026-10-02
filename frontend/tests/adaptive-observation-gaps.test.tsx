import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { AdaptiveRunPath } from "../src/components/AdaptiveRunPath";
import { demoCatalog } from "../src/lib/demo";
import type { RunRecord } from "../src/types";
import producerContract from "./fixtures/adaptive-observation-contract.json";

// Software display fixtures only; no host, live provider, or installed journey is exercised.
function fixture(observations: Record<string, unknown> = producerContract.projection): RunRecord {
  const source = producerContract.source_step;
  return {
    run_id: producerContract.run_id, mode: "execute", status: "completed",
    steps: [{ ...source, planner_decision_id: "authored-gap-decision" }],
    evidence: { records: producerContract.evidence },
    ai_proposals: [{
      schema_version: "bluefire.ai-proposal-record.v4", run_id: producerContract.run_id,
      current_step_id: source.step_id, deterministic_decision_id: "authored-gap-decision",
      outcome: source.status, provider_called: false, planner_state: { observations },
    }],
  };
}

function authoredAttempt(failure: unknown, stepId = producerContract.source_step.step_id) {
  return { step_id: stepId, failure, evidence: [] };
}

async function showDecision(value: RunRecord) {
  render(<AdaptiveRunPath run={value} catalog={demoCatalog} />);
  await userEvent.setup().click(screen.getByText("Decision, observations and limits", { selector: "summary" }));
  return screen.getByRole("region", { name: "Recorded adaptive decision" });
}

function expectCoverage(decision: HTMLElement, label: string) {
  const row = within(decision).getByText("Observation coverage", { selector: "dt" }).parentElement!;
  expect(within(row).getByText(label, { selector: "dd" })).toBeVisible();
  expect(within(decision).queryByText(/all observations (?:are )?available|observations (?:are )?complete|complete observation coverage|no observation gaps/i)).not.toBeInTheDocument();
}

function expectTimeout(decision: HTMLElement) {
  const row = within(decision).getByText("Failure classification", { selector: "dt" }).parentElement!;
  expect(within(row).getByText("Execution timeout", { selector: "dd" })).toBeVisible();
}

describe("recorded observation coverage (software fixtures)", () => {
  it("shows the unchanged producer's true gap beside its timeout classification without mutating the record", async () => {
    const sourceBefore = JSON.stringify(producerContract);
    const value = fixture();
    const recordBefore = JSON.stringify(value.ai_proposals![0]);
    const decision = await showDecision(value);

    expectCoverage(decision, "Some observations are unavailable.");
    expectTimeout(decision);
    expect(JSON.stringify(value.ai_proposals![0])).toBe(recordBefore);
    expect(JSON.stringify(producerContract)).toBe(sourceBefore);
  });

  it.each([
    { name: "legacy absent flag", failure: { classification: "execution_timeout" }, expected: "Not recorded." },
    { name: "strict false", failure: { classification: "execution_timeout", telemetry_gap: false }, expected: "Completeness not established." },
    { name: "string true", failure: { classification: "execution_timeout", telemetry_gap: "true" }, expected: "Not recorded." },
    { name: "integer one", failure: { classification: "execution_timeout", telemetry_gap: 1 }, expected: "Not recorded." },
    { name: "null", failure: { classification: "execution_timeout", telemetry_gap: null }, expected: "Not recorded." },
  ])("handles $name conservatively while preserving classification", async ({ failure, expected }) => {
    const value = fixture({ attempts: [authoredAttempt(failure)] });
    const before = JSON.stringify(value);
    const decision = await showDecision(value);

    expectCoverage(decision, expected);
    expectTimeout(decision);
    expect(within(decision).queryByText("Some observations are unavailable.")).not.toBeInTheDocument();
    expect(JSON.stringify(value)).toBe(before);
  });

  it.each([
    { name: "legacy missing observations", observations: {} },
    { name: "missing failure", observations: { attempts: [{ step_id: "inspect", evidence: [] }] } },
    { name: "malformed failure", observations: { attempts: [authoredAttempt(null)] } },
    { name: "no matching current attempt", observations: { attempts: [authoredAttempt({ telemetry_gap: true }, "other-step")] } },
  ])("does not infer coverage from $name", async ({ observations }) => {
    const decision = await showDecision(fixture(observations));
    expectCoverage(decision, "Not recorded.");
    expect(within(decision).queryByText("Some observations are unavailable.")).not.toBeInTheDocument();
  });

  it("keeps an earlier different step's gap out of the current false coverage", async () => {
    const value = fixture({ attempts: [
      authoredAttempt({ classification: "execution_failure", telemetry_gap: true }, "earlier-step"),
      authoredAttempt({ classification: "execution_timeout", telemetry_gap: false }),
    ] });
    const before = JSON.stringify(value);
    const decision = await showDecision(value);

    expectCoverage(decision, "Completeness not established.");
    expectTimeout(decision);
    expect(within(decision).queryByText("Some observations are unavailable.")).not.toBeInTheDocument();
    expect(JSON.stringify(value)).toBe(before);
  });

  it("uses the latest matching attempt when the same step was retried", async () => {
    const decision = await showDecision(fixture({ attempts: [
      authoredAttempt({ classification: "execution_failure", telemetry_gap: true }),
      authoredAttempt({ classification: "execution_timeout", telemetry_gap: false }),
      authoredAttempt({ classification: "execution_failure", telemetry_gap: true }, "other-step"),
    ] }));

    expectCoverage(decision, "Completeness not established.");
    expectTimeout(decision);
    expect(within(decision).queryByText("Some observations are unavailable.")).not.toBeInTheDocument();
  });
});
