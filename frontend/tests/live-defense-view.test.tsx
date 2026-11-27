import { fireEvent, render, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { momentFromSearch, momentSearch } from "../src/lib/recorded-runs";
import { LiveView } from "../src/live/LiveView";
import type { LiveMoment, LiveViewProps } from "../src/live/LiveView";
import type { Defense, Recording, Step, StepVerdict } from "../src/live/recording";
import { alert, at, event, recording, step } from "./live-fixture";

function verdictOf(value: Step): StepVerdict {
  return {
    visibility: value.visibility,
    outcome: value.outcome,
    ...(value.first_event ? { first_event: value.first_event } : {}),
    ...(value.first_alert ? { first_alert: value.first_alert } : {}),
  };
}

function judgedTwice(): Recording {
  const first = step("1", 1, 2, {
    outcome: "alerted",
    visibility: { answer: "alert", basis: "the stock rule matched", events: 1 },
    first_event: at(1.1),
    first_alert: at(1.2),
  });
  const second = step("2", 3, 4, {
    outcome: "seen",
    visibility: { answer: "telemetry only", basis: "the sensor recorded it", events: 1 },
    first_event: at(3.1),
  });
  const base = recording({
    steps: [first, second],
    events: [event("e1", "1", 1.1), event("e2", "2", 3.1)],
    alerts: [alert("a1", "1", 1.2, ["e1"])],
  });
  const detector = base.network.detectors.find((item) => item.id === "pinned");
  if (!detector) throw new Error("fixture");
  const score = { steps: 2, took_effect: 2, alerted: 1, seen: 1, unseen: 0, stopped: 0, first_alert_seconds: 0.2, goal_seconds: 10, false_alerts: 0 };
  const stock: Defense = {
    id: "stock",
    name: "Wazuh with its stock rules",
    sensors: ["sysmon"],
    detectors: ["pinned"],
    steps: { "1": verdictOf(first), "2": verdictOf(second) },
    ordinary: { events: 12, matches: [] },
    score,
  };
  const quietSteps = {
    "1": { visibility: { answer: "telemetry only" as const, basis: "the sensor recorded it", events: 1 }, outcome: "seen" as const, first_event: at(1.1) },
    "2": verdictOf(second),
  };
  const quiet: Defense = {
    id: "quiet",
    name: "Host sensors with no alerting rule set",
    sensors: ["sysmon"],
    detectors: [],
    steps: quietSteps,
    ordinary: { events: 12, matches: [] },
    score: { ...score, alerted: 0, seen: 2 },
  };
  delete quiet.score.first_alert_seconds;
  return {
    ...base,
    kind: "attack path",
    attacker: { kind: "scripted", description: "A two-step path", goal: "read the planted goal" },
    network: { ...base.network, detectors: [detector] },
    ordinary: stock.ordinary,
    score,
    defenses: [stock, quiet],
  };
}

function open(value: Recording, initial: LiveViewProps["initial"], onMoment?: (moment: LiveMoment) => void) {
  vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockReturnValue(1440);
  vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockReturnValue(420);
  return render(<LiveView recording={value} initial={initial} onMoment={onMoment} />);
}

describe("one run judged by several defenses", () => {
  it("leads with the outcome, switches every visible verdict, and keeps the exact moment", async () => {
    const onMoment = vi.fn<(moment: LiveMoment) => void>();
    const { container, unmount } = open(judgedTwice(), { step: "1", at: 1.2, paused: true }, onMoment);
    expect(container.querySelector(".lv-outcome")?.textContent).toContain("The attacker has not reached its goal");
    const choices = within(container).getByRole("group", { name: "The defenses that judge this run" });
    const stock = within(choices).getByRole("button", { name: /Wazuh with its stock rules/ });
    expect(stock.getAttribute("aria-pressed")).toBe("true");
    expect(within(choices).getByLabelText("Key 1. Step 1: alerted")).toBeTruthy();
    expect(within(choices).getByLabelText("Key 2. Step 1: seen, no alert")).toBeTruthy();
    expect(container.querySelector(".lv-word")?.textContent).toBe("alerted");
    const clock = container.querySelector(".lv-clock b")?.textContent;

    fireEvent.keyDown(document, { key: "2" });

    const quiet = within(choices).getByRole("button", { name: /Host sensors with no alerting rule set/ });
    expect(quiet.getAttribute("aria-pressed")).toBe("true");
    expect(container.querySelector(".lv-word")?.textContent).toBe("seen");
    expect(container.querySelector(".lv-clock b")?.textContent).toBe(clock);
    expect(container.textContent).toContain("Host sensors with no alerting rule set has not alerted yet.");
    await waitFor(() => expect(onMoment.mock.calls.at(-1)?.[0].defense).toBe("quiet"));
    unmount();
  });

  it("shows every defense's recounted run in Analyse and a row chooses the judge", () => {
    const { container, unmount } = open(judgedTwice(), { mode: "analyse", defense: "quiet" });
    const table = within(container).getByRole("group", { name: "The defenses side by side" });
    const rows = within(table).getAllByRole("button");
    expect(rows).toHaveLength(2);
    expect(rows[0]?.textContent).toContain("11");
    expect(rows[1]?.textContent).toContain("02");
    fireEvent.click(within(table).getByRole("button", { name: /Wazuh with its stock rules/ }));
    expect(within(table).getByRole("button", { name: /Wazuh with its stock rules/ }).getAttribute("aria-pressed")).toBe("true");
    unmount();
  });

  it("names the chosen defense in Analyse when it did not see a step", () => {
    const value = judgedTwice();
    const defense = value.defenses?.[1];
    if (!defense) throw new Error("fixture");
    defense.sensors = [];
    defense.steps["2"] = { visibility: { answer: "no telemetry", basis: "none of its sensors recorded the step", events: 0 }, outcome: "unseen" };
    defense.score = { ...defense.score, seen: 1, unseen: 1 };
    const { container, unmount } = open(value, { mode: "analyse", defense: defense.id });
    const summary = within(container).getByRole("article", { name: "The whole run" });
    expect(summary.textContent).toContain("Host sensors with no alerting rule set did not see the step:");
    expect(summary.textContent).not.toContain("nobody saw");
    unmount();
  });

  it("keeps the legacy screen when a recording names no defenses", () => {
    const value = recording({ steps: [step("1", 1, 2)] });
    const { container, unmount } = open(value, { step: "1", at: 1.2, paused: true });
    expect(container.querySelector(".lv-score")).toBeTruthy();
    expect(container.querySelector(".lv-outcome")).toBeNull();
    expect(within(container).queryByRole("group", { name: "The defenses that judge this run" })).toBeNull();
    unmount();
  });

  it("keeps a valid 200-character defense name whole behind the compact label", () => {
    const value = judgedTwice();
    const long = `Defense ${"x".repeat(192)}`;
    const defense = value.defenses?.[1];
    if (!defense) throw new Error("fixture");
    defense.name = long;
    const { container, unmount } = open(value, { step: "1", at: 1.2, paused: true });
    const choices = within(container).getByRole("group", { name: "The defenses that judge this run" });
    const row = within(choices).getAllByRole("button")[1];
    expect(long).toHaveLength(200);
    expect(row?.textContent).toContain(long);
    expect(row?.getAttribute("title")).toContain(long);
    expect(row?.querySelector(".lv-ds-rname")?.getAttribute("title")).toBe(long);
    unmount();
  });

  it("keeps the score header for a test list judged by several defenses", () => {
    const value = judgedTwice();
    value.kind = "test list";
    value.attacker = { ...value.attacker, goal: null };
    const { container, unmount } = open(value, { step: "1", at: 1.2, paused: true });
    expect(container.querySelector(".lv-score")).toBeTruthy();
    expect(container.querySelector(".lv-outcome")).toBeNull();
    expect(within(container).getByRole("group", { name: "The defenses that judge this run" })).toBeTruthy();
    unmount();
  });

  it("round-trips the selected defense in the address", () => {
    const query = momentSearch({ step: "2", at: 1.125, paused: true, mode: "watch", defense: "quiet" });
    expect(query.get("defense")).toBe("quiet");
    expect(momentFromSearch(query)).toMatchObject({ step: "2", at: 1.125, paused: true, defense: "quiet" });
  });
});
