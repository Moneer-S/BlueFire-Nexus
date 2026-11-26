import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LiveView } from "../src/live/LiveView";
import type { LiveViewProps } from "../src/live/LiveView";
import { readRecording } from "../src/live/recording";
import type { Recording } from "../src/live/recording";
import { alert, event, recording, step } from "./live-fixture";

afterEach(() => {
  vi.restoreAllMocks();
});

function shipped(name: string): Recording {
  return readRecording(JSON.parse(readFileSync(resolve(process.cwd(), `../bluefire/data/recordings/${name}.json`), "utf-8")));
}

function open(value: Recording, initial: LiveViewProps["initial"]) {
  vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockReturnValue(1440);
  vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockReturnValue(420);
  return render(<LiveView recording={value} initial={initial} />);
}

describe("the column of rules matched in analyse mode", () => {
  it("counts the rules of step 1 of the attack path, as the step's sentence does, not their 1,364 matches", () => {
    // Step s01: one published rule alerted, six published rules below alert level matched 1,361 times, and two informational rules once each.
    const view = open(shipped("lab-range-one-path"), { mode: "analyse", select: "s01" });
    const cell = view.container.querySelector('tr[data-step="s01"] td.is-rules');
    expect(cell?.textContent).toBe("1 alert 6 review 2 info");
  }, 60_000);
});

describe("the line of the map that counts the rest of an engine's matches", () => {
  it("says in a few words that the launcher line's match is not counted, where one rule matched it", () => {
    // Test 1 of the run on one Linux machine (step 4): two published rules for review, one informational, and one on its launcher line.
    const view = open(shipped("lab-linux-host"), { step: "4", at: 1.5, paused: true });
    const lines = [...view.container.querySelectorAll(".lv-match--more")].map((line) => line.textContent);
    expect(lines).toContain("+ 1 more informational · launcher line, not counted");
  }, 60_000);

  it("says \"more\" once, at the head of the line, where rules for review and informational ones are counted beside the launcher line", () => {
    // Step id 47 of the run on one Linux machine: three more rules for review, one informational, and one on its launcher line.
    const view = open(shipped("lab-linux-host"), { step: "47", at: 1.5, paused: true });
    const lines = [...view.container.querySelectorAll(".lv-match--more")].map((line) => line.textContent);
    expect(lines).toContain("+ 3 more for review · 1 informational · launcher line, not counted");
  }, 60_000);

  it("says how many rules matched the launcher line, where more than one did", () => {
    // No shipped step has this: three rules for review and two rules on the launcher line.
    const rule = (id: string, level: "low" | "medium") => ({ id, title: `Rule ${id}`, level, origin: "pinned" as const });
    const run = recording({
      steps: [step("1", 1, 2, { outcome: "seen", visibility: { answer: "telemetry only", basis: "events", events: 3 } })],
      events: [event("e1", "1", 1.1), event("e2", "1", 1.2), event("e3", "1", 1.3)],
      alerts: [
        alert("a", "1", 1.1, ["e1"], { counts: false, rule: rule("a", "medium") }),
        alert("b", "1", 1.2, ["e2"], { counts: false, rule: rule("b", "medium") }),
        alert("c", "1", 1.3, ["e3"], { counts: false, rule: rule("c", "low") }),
        alert("x", "1", 1.0, [], { counts: false, launcher_only: true, rule: rule("x", "medium") }),
        alert("y", "1", 1.0, [], { counts: false, launcher_only: true, rule: rule("y", "low") }),
      ],
    });
    const view = open(run, { step: "1", at: 1.5, paused: true });
    const lines = [...view.container.querySelectorAll(".lv-match--more")].map((line) => line.textContent);
    expect(lines).toContain("+ 1 more for review · launcher line (2 rules), not counted");
  }, 60_000);
});
