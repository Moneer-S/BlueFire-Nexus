import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { runFacts } from "../src/live/moment";
import { buildTimeline } from "../src/live/playback";
import { judgedBy, readRecording } from "../src/live/recording";
import { RunSummary } from "../src/live/RunSummary";

function shipped(name: string) {
  return readRecording(JSON.parse(readFileSync(resolve(process.cwd(), `../bluefire/data/recordings/${name}.json`), "utf-8")));
}

describe("the whole run, in analyse mode", () => {
  it("keeps the shipped repository-authored ordered alert counted without calling it published", () => {
    const recording = judgedBy(shipped("lab-range-one-path"), "ordered-credential");
    const timeline = buildTimeline(recording);

    expect(recording.score.alerted).toBe(1);
    expect(recording.steps.find((step) => step.id === "s08")?.outcome).toBe("alerted");
    render(<RunSummary recording={recording} timeline={timeline} facts={runFacts(recording, timeline)} judge="Ordered credential activity on host logs" onSelect={() => undefined} />);

    const summary = screen.getByRole("article", { name: "The whole run" });
    expect(summary).toHaveTextContent("1 of 11 steps alerted");
    expect(summary).toHaveTextContent("10 were recorded with no alert");
    expect(summary.querySelector(".lv-dt-facts")?.textContent).not.toMatch(/published rule/i);
    const ordinary = screen.getByText(/What the rules in this defense said/).closest("section");
    expect(ordinary?.textContent).not.toMatch(/published rule/i);
  });

  it.each([
    // The run on one Linux machine: 17 tests alerted once ad hoc lab rules count too, 15 of them on a lab rule's alert and 2 on rules in the scored defense alone.
    ["lab-linux-host", "17"],
    ["lab-rule-history-truncated-head", "19"],
  ])("%s: says how many tests alerted with ad hoc lab rules too, and never credits the lab rules with all of them", (name, alerted) => {
    const recording = shipped(name);
    const timeline = buildTimeline(recording);
    render(<RunSummary recording={recording} timeline={timeline} facts={runFacts(recording, timeline)} onSelect={() => undefined} />);
    const row = screen.getByText("Lab rules").nextElementSibling;
    expect(row).toHaveTextContent(`with ad hoc lab rules too, ${alerted} of 60 tests alerted not scored`);
    expect(row).not.toHaveTextContent("lab alerts on");
  });

  it("keeps the two words of \"not scored\" together, so the row never breaks between them", () => {
    const recording = shipped("lab-linux-host");
    const timeline = buildTimeline(recording);
    render(<RunSummary recording={recording} timeline={timeline} facts={runFacts(recording, timeline)} onSelect={() => undefined} />);
    const row = screen.getByText("Lab rules").nextElementSibling;
    // A no-break space joins them: where the row wraps, both go to the next line as one.
    expect(row?.textContent?.endsWith("alerted not\u00a0scored")).toBe(true);
  });
});
