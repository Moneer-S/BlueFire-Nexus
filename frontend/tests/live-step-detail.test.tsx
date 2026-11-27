import { render, screen, within } from "@testing-library/react";
import { expect, it } from "vitest";
import { StepDetail } from "../src/live/StepDetail";
import { stepRows } from "../src/live/analyse";
import { stepShortName } from "../src/live/format";
import { buildTimeline } from "../src/live/playback";
import { timeOf } from "../src/live/recording";
import { alert, at, event, recording, step } from "./live-fixture";

it("times a step's first alert from when it was raised, as the rest of the detail does", () => {
  // The test starts at 10 s and ends at 11 s, its event is at 10.5 s and its alert is raised live at 25 s.
  const value = recording({
    when: "live",
    steps: [step("1", 10, 11, { outcome: "alerted", first_alert: at(10.5) }), step("2", 20, 21)],
    events: [event("1-1", "1", 10.5)],
    alerts: [alert("a", "1", 10.5, ["1-1"], { raised: at(25) })],
  });
  const row = stepRows(value, buildTimeline(value))[0];
  if (!row) throw new Error("no row");
  const ignore = () => undefined;
  render(<StepDetail recording={value} row={row} colours={new Map()} testNumber={1} testsTotal={2} origin={timeOf(at(10))} onSelect={ignore} onWatch={ignore} onClose={ignore} takeFocus={false} />);
  expect(screen.getByText(/, first alert 15(\.0)? s after the start$/)).toBeTruthy();
  expect(screen.getByText("Raised 14 s after the step ended.")).toBeTruthy();
});

it("says that a rule's alerts on ordinary activity are one false alert, its events counted as events, as the score counts it", () => {
  const base = recording({
    steps: [step("1", 10, 11, { outcome: "alerted" })],
    events: [event("1-1", "1", 10.5)],
    alerts: [alert("a", "1", 10.5, ["1-1"])],
  });
  const value = { ...base, ordinary: { events: 100, matches: [{ rule: "Rule a", level: "high" as const, count: 3 }] } };
  const row = stepRows(value, buildTimeline(value))[0];
  if (!row) throw new Error("no row");
  const ignore = () => undefined;
  render(<StepDetail recording={value} row={row} colours={new Map()} testNumber={1} testsTotal={1} origin={timeOf(at(10))} onSelect={ignore} onWatch={ignore} onClose={ignore} takeFocus={false} />);
  expect(screen.getByText("The same rule also alerted on 3 events of ordinary activity, outside every step: one false alert.")).toBeTruthy();
});

it("shows every cross-step correlation event in evidence order without moving earlier events into the terminal step", () => {
  const title = "Ordered credential search and remote archive";
  const evidenceIds = ["s06-1", "s07-1", "s08-1"] as const;
  const value = recording({
    steps: [step("6", 10, 11), step("7", 20, 21), step("8", 30, 31, { outcome: "alerted", first_alert: at(30.5) })],
    events: [event(evidenceIds[0], "6", 10.5), event(evidenceIds[1], "7", 20.5), event(evidenceIds[2], "8", 30.5)],
    alerts: [
      alert("sequence", "8", 30.5, [...evidenceIds], {
        rule: { id: "ordered-credential", title, level: "high", origin: "pinned" },
      }),
    ],
  });
  const row = stepRows(value, buildTimeline(value))[2];
  if (!row) throw new Error("no terminal row");
  expect(row.events.map((item) => item.id)).toEqual(["s08-1"]);
  expect(row.matches.alert[0]?.step).toBe("8");
  expect(row.matches.alert[0]?.events).toEqual(evidenceIds);

  const ignore = () => undefined;
  render(<StepDetail recording={value} row={row} colours={new Map()} testNumber={3} testsTotal={3} origin={timeOf(at(10))} onSelect={ignore} onWatch={ignore} onClose={ignore} takeFocus={false} />);

  const evidence = screen.getByRole("region", { name: `Correlation evidence for ${title}` });
  const items = within(evidence).getAllByRole("listitem");
  expect(items.map((item) => item.querySelector(".lv-dt-cstep")?.textContent)).toEqual(value.steps.map((item) => stepShortName(value, item)));
  expect(items.map((item) => item.querySelector("time")?.getAttribute("datetime"))).toEqual([at(10.5), at(20.5), at(30.5)]);
  expect(items.map((item) => item.querySelector(".lv-dt-ctext")?.textContent)).toEqual(evidenceIds.map((id) => `run ${id}`));
  expect(screen.getByText(/^3 events ·/)).toBeTruthy();
  const terminalLog = document.querySelector(".lv-dt-log")?.textContent;
  expect(terminalLog).toContain("run s08-1");
  expect(terminalLog).not.toContain("run s06-1");
  expect(terminalLog).not.toContain("run s07-1");
});
