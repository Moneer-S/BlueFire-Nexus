import { render, screen } from "@testing-library/react";
import { expect, it } from "vitest";
import { StepDetail } from "../src/live/StepDetail";
import { stepRows } from "../src/live/analyse";
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
  const row = stepRows(value)[0];
  if (!row) throw new Error("no row");
  const ignore = () => undefined;
  render(<StepDetail recording={value} row={row} colours={new Map()} testNumber={1} testsTotal={2} origin={timeOf(at(10))} onSelect={ignore} onWatch={ignore} onClose={ignore} takeFocus={false} />);
  expect(screen.getByText(/, first alert 15(\.0)? s after the start$/)).toBeTruthy();
  expect(screen.getByText("Raised 14 s after the step ended.")).toBeTruthy();
});
