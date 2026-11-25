import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { Stages } from "../src/components/PairStages";
import { stageSide } from "../src/lib/pair-stage";
import type { Recording, RuleLevel } from "../src/live/recording";
import { alert, event, recording, step } from "./live-fixture";

// One step drawn on the two stages of a comparison's page, before and after,
// from two small recordings. Each stage's chip calls a match what analyse mode
// calls it.

function run(level: RuleLevel): Recording {
  return recording({
    steps: [step("1", 1, 2, { outcome: "seen", visibility: { answer: "telemetry only", basis: "1 event", events: 1 } })],
    events: [event("1-1", "1", 1.5)],
    alerts: [alert("m1", "1", 1.5, ["1-1"], { counts: false, rule: { id: "5715", title: "sshd: authentication success.", level, origin: "pinned" } })],
  });
}

function draw(before: Recording, after: Recording) {
  const sides = { before: stageSide(before, "1"), after: stageSide(after, "1") };
  if (!sides.before || !sides.after) throw new Error("Both recordings hold the step.");
  const links = { play: "/runs", playWords: "Play it" };
  render(<MemoryRouter><Stages before={sides.before} after={sides.after} words={{ before: "before", after: "after" }} runs={{ before: null, after: null }} links={{ before: links, after: links }} newRules={new Set()} judged /></MemoryRouter>);
}

describe("the stages of a moved step", () => {
  it("call a match at informational level informational, and one at low or medium level a match for review", () => {
    draw(run("informational"), run("medium"));
    const before = screen.getByRole("article", { name: /^Before/ });
    const after = screen.getByRole("article", { name: /^After/ });
    expect(within(before).getByText("informational", { exact: true })).toBeVisible();
    expect(before).not.toHaveTextContent(/review · informational/i);
    expect(within(after).getByText("review · medium", { exact: true })).toBeVisible();
  });
});
