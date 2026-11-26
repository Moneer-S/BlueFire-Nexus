import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { runFacts } from "../src/live/moment";
import { buildTimeline } from "../src/live/playback";
import { readRecording } from "../src/live/recording";
import { RunSummary } from "../src/live/RunSummary";

function shipped(name: string) {
  return readRecording(JSON.parse(readFileSync(resolve(process.cwd(), `../bluefire/data/recordings/${name}.json`), "utf-8")));
}

describe("the whole run, in analyse mode", () => {
  it.each([
    // The run on one Linux machine: 17 tests alerted once the lab's own rules count too, 15 of them on a lab rule's alert and 2 on published rules alone.
    ["lab-linux-host", "17"],
    ["lab-rule-history-truncated-head", "19"],
  ])("%s: says how many tests alerted with the lab's own rules too, and never credits the lab's rules with all of them", (name, alerted) => {
    const recording = shipped(name);
    const timeline = buildTimeline(recording);
    render(<RunSummary recording={recording} timeline={timeline} facts={runFacts(recording, timeline)} onSelect={() => undefined} />);
    const row = screen.getByText("Lab rules").nextElementSibling;
    expect(row).toHaveTextContent(`with the lab's own rules too, ${alerted} of 60 tests alerted not scored`);
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
