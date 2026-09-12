import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { demoCatalog, demoRuns } from "../src/lib/demo";
import { DetectionDetail, EvidenceDetail } from "../src/pages/Runs";
import type { RunRecord } from "../src/types";

describe("canonical run records", () => {
  it("renders canonical evidence content and provenance metadata with legacy compatibility", async () => {
    const run: RunRecord = {
      ...demoRuns[0]!,
      evidence: {
        records: [{
          evidence_id: "evidence-canonical-test",
          step_id: "observe",
          behavior_id: "endpoint.discovery.system.v1",
          action_id: "endpoint.discovery.system.execute.v1",
          provenance: "observed",
          producer: "runner-observer.v1",
          confidence: 0.93,
          limitations: ["Host clock skew was not independently measured."],
          content: { observed_value: 7, source: "bounded fixture" },
        }],
      },
    };

    const catalog = { ...demoCatalog, actions: [...demoCatalog.actions, { ...demoCatalog.actions[0]!, id: "endpoint.discovery.system.execute.v1", title: "Read system details" }] };
    const original = structuredClone(run);
    render(<EvidenceDetail run={run} catalog={catalog} />);
    const card = screen.getByText("Read system details").closest("article")!;
    expect(within(card.querySelector("header")!).getByText("Collect bounded system facts")).toBeVisible();
    expect(within(card).getByText("Observed")).toBeVisible();
    expect(screen.getByText("endpoint.discovery.system.execute.v1")).not.toBeVisible();
    await userEvent.click(screen.getByText("Evidence identity and provenance"));
    expect(screen.getByText("runner-observer.v1")).toBeVisible();
    expect(screen.getAllByText("endpoint.discovery.system.v1").length).toBeGreaterThan(0);
    expect(screen.getByText("endpoint.discovery.system.execute.v1")).toBeVisible();
    expect(screen.getByText(/Reported confidence: 93%/)).toBeVisible();
    expect(screen.getByText("Host clock skew was not independently measured.")).toBeVisible();
    expect(screen.getByLabelText("Evidence content evidence-canonical-test")).toHaveTextContent('"observed_value": 7');
    expect(run).toEqual(original);
  });

  it("prefers the canonical detection target language", () => {
    const run: RunRecord = {
      ...demoRuns[0]!,
      detections: { candidates: [{ candidate_id: "candidate-language-test", state: "parsed", target_language: "yara-l", language: "legacy-language" }] },
    };
    render(<DetectionDetail run={run} />);
    expect(screen.getByText("yara-l")).toBeVisible();
    expect(screen.queryByText("legacy-language")).not.toBeInTheDocument();
  });
});
