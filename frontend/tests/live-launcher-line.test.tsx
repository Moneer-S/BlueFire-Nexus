import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { fixHint, groupMatches } from "../src/live/analyse";
import { seenWords } from "../src/live/format";
import { LiveView } from "../src/live/LiveView";
import type { LiveViewProps } from "../src/live/LiveView";
import { readRecording } from "../src/live/recording";
import type { Recording } from "../src/live/recording";
import { alert, event, recording, step } from "./live-fixture";

afterEach(() => {
  vi.restoreAllMocks();
});

const shipped = readRecording(JSON.parse(readFileSync(resolve(process.cwd(), "../bluefire/data/recordings/lab-linux-host.json"), "utf-8")));

function open(value: Recording, initial: LiveViewProps["initial"]) {
  vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockReturnValue(1440);
  vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockReturnValue(420);
  return render(<LiveView recording={value} initial={initial} />);
}

const text = (root: ParentNode, selector: string) => root.querySelector(selector)?.textContent?.trim() ?? null;

/** The step's sentence and its hint as watch mode shows them at the step's end, with the text a screen reader is given, and as analyse mode's detail shows them. */
function told(id: string) {
  const watch = open(shipped, { step: id, at: 1.5, paused: true });
  const said = { sentence: text(watch.container, ".lv-why"), hint: text(watch.container, ".lv-fix-hint"), spoken: text(watch.container, ".lv-caption .lv-sr") };
  watch.unmount();
  const analyse = open(shipped, { mode: "analyse", select: id });
  const detail = { sentence: text(analyse.container, ".lv-dt-why"), hint: text(analyse.container, ".lv-dt-hint") };
  analyse.unmount();
  return { ...said, detail };
}

function events(id: string): number {
  const found = shipped.steps.find((item) => item.id === id);
  if (found?.visibility.events === undefined) throw new Error(`The shipped run has no events count for step ${id}.`);
  return found.visibility.events;
}

describe("a seen test whose only published match is on the line that started it, in the run on one Linux machine", () => {
  it.each([
    ["7", "1 rule"],
    ["10", "2 rules"],
  ])("step %s says that %s matched only the launcher line, and that no rule matched what the step itself did", (id, rules) => {
    const sentence = `${events(id)} events recorded, ${rules} matched only the launcher line, which never counts.`;
    const hint = "No rule matched what the step itself did: start by writing one.";
    const seen = told(id);
    expect(seen.sentence).toBe(sentence);
    expect(seen.hint).toBe(hint);
    expect(seen.spoken).toBe(`Seen, no alert: ${sentence}`);
    expect(seen.detail).toEqual({ sentence, hint });
  }, 60_000);

  it("says of test 4 (step 7), in so many words, that its 7 events were matched by 1 rule on the launcher line only", () => {
    expect(told("7").sentence).toBe("7 events recorded, 1 rule matched only the launcher line, which never counts.");
  }, 60_000);

  it("keeps saying that no rule matched a step nothing matched at all", () => {
    const sentence = `${events("11")} events recorded, no rule matched.`;
    const seen = told("11");
    expect(seen.sentence).toBe(sentence);
    expect(seen.hint).toBe("No rule matched this step: start by writing one.");
    expect(seen.detail).toEqual({ sentence, hint: "No rule matched this step: start by writing one." });
  }, 60_000);

  it("keeps the words of a step with a match for review beside a launcher match", () => {
    // Test 1 (step 4): matched for review by two published rules and at informational level by one, and on its launcher line.
    const sentence = `${events("4")} events recorded, 2 rules matched for review, 1 informational rule matched, none at alert level.`;
    const seen = told("4");
    expect(seen.sentence).toBe(sentence);
    expect(seen.hint).toMatch(/^To alert here, start from the rule "System /);
    expect(seen.detail.sentence).toBe(sentence);
    expect(seen.detail.hint).toBe(seen.hint);
  }, 60_000);

  it("keeps the words of a step one of the lab's own rules alerted on, beside a launcher match", () => {
    // Test 11 (step 14): a lab alert, a published rule for review, and a published match on its launcher line.
    const sentence = `${events("14")} events recorded, 1 rule matched for review, none of the rules in this defense at alert level.`;
    const hint = "The score counts rules in this defense only, and none of those alerted.";
    const seen = told("14");
    expect(seen.sentence).toBe(sentence);
    expect(seen.hint).toBe(hint);
    // The detail names the lab's rule after the same sentence.
    expect(seen.detail.sentence).toBe(`${sentence} An ad hoc lab rule alerted, which the score does not count: Systemd Unit File Written By A Shell.`);
    expect(seen.detail.hint).toBe(hint);
  }, 60_000);
});

describe("the words of a launcher match beside a lab alert", () => {
  it("say that a published rule matched only the launcher line, and give the lab's hint", () => {
    // No shipped step has this: a lab alert and a published match on the launcher line, and nothing else.
    const run = recording({
      steps: [step("1", 1, 2, { outcome: "seen", outcome_with_lab_rules: "alerted" })],
      events: [event("e1", "1", 1.1)],
      alerts: [
        alert("lab", "1", 1.1, ["e1"], { detector: "lab", rule: { id: "r-lab", title: "Ours", level: "high", origin: "lab" } }),
        alert("launch", "1", 1, [], { counts: false, launcher_only: true }),
      ],
    });
    const only = run.steps[0];
    if (!only) throw new Error("fixture");
    expect(seenWords(1, run.alerts)).toBe("1 event recorded, 1 rule in this defense matched only the launcher line, which never counts.");
    expect(fixHint(run, only, groupMatches(run.alerts))).toBe("The score counts rules in this defense only, and none of those alerted.");
  });
});
