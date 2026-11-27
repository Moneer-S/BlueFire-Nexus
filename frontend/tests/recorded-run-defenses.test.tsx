import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { api, type RecordingSummary } from "../src/lib/api";
import type { Recording } from "../src/live/recording";
import { RecordedRunPage } from "../src/pages/RecordedRun";
import { alert, at, event, recording, step } from "./live-fixture";

// A recording that holds one run judged by two defenses keeps the canonical
// run, while each selectable defense decides which sensors, rules and verdict
// recount it.

const seen = { visibility: { answer: "telemetry only", basis: "one event", events: 1 }, outcome: "seen" } as const;
const alerted = { visibility: { answer: "alert", basis: "two events and a rule", events: 2 }, outcome: "alerted", first_alert: at(10.6) } as const;
const base = recording({
  steps: [step("1", 10, 11, seen)],
  events: [event("1-1", "1", 10.5), { ...event("1-2", "1", 10.6), sensor: "capture", kind: "packet", text: "a packet the capture kept" }],
  alerts: [alert("on-the-packet", "1", 10.6, ["1-2"], { detector: "sigma", rule: { id: "s1", title: "Sigma rule on a packet", level: "high", origin: "pinned" } })],
});
const score = { ...base.score, took_effect: 1, seen: 1 };

/** The first defense has Sysmon and the published rules, and saw the step; the second has a packet capture and Sigma's rules too, and alerted on it. */
const value: Recording = {
  ...base,
  network: {
    ...base.network,
    sensors: [...base.network.sensors, { id: "capture", name: "Packet capture", host: "target", records: "packets" }],
    detectors: [...base.network.detectors, { id: "sigma", name: "Sigma rules", rules: 3, when: "after the run" }],
  },
  score,
  defenses: [
    { id: "sysmon-alone", name: "Sysmon with the published rules", sensors: ["sysmon"], detectors: ["pinned"], steps: { "1": seen }, score },
    { id: "with-capture", name: "Sysmon, a packet capture and Sigma's rules", sensors: ["sysmon", "capture"], detectors: ["sigma"], steps: { "1": alerted }, score: { ...score, seen: 0, alerted: 1 } },
  ],
};

const summary: RecordingSummary = {
  id: value.id,
  title: value.title,
  kind: value.kind,
  source: { engine: value.source.engine, environment: value.source.environment, started: at(0), finished: at(600) },
  score: value.score,
  counts: { steps: 1, events: 2, alerts: 1 },
  origin: { kind: "imported", note: "Imported. BlueFire cannot confirm that the steps ran." },
  running: false,
};

describe("the page of a recorded run that several defenses judged", { timeout: 20_000 }, () => {
  it("keeps the whole run and lets either defense judge it", async () => {
    vi.spyOn(api, "recording").mockResolvedValue({ summary, recording: JSON.parse(JSON.stringify(value)) });
    vi.spyOn(api, "recordingDeltas").mockResolvedValue({ deltas: [], unreadable_count: 0, omitted_count: 0 });
    vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockReturnValue(1440);
    vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockReturnValue(420);
    // The table looks again for the chosen row once the page's font has loaded, which this test's document has no word of.
    Object.defineProperty(document, "fonts", { value: { ready: Promise.resolve() }, configurable: true });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/runs/recorded/${value.id}?mode=analyse&select=1`]}>
      <Routes>
        <Route path="/runs/recorded/:recordingId" element={<RecordedRunPage />} />
      </Routes>
    </MemoryRouter></QueryClientProvider>);

    const detail = await screen.findByRole("article", { name: /Test 1/ }, { timeout: 8_000 });
    // The first defense's own: its sensor's one event, and its verdict, seen.
    expect(within(detail).getByText("run 1-1")).toBeVisible();
    expect(detail).toHaveTextContent(/seen/i);
    // The map and comparison keep the other defense visible without mixing its
    // event into the selected defense's recount.
    const choices = screen.getByRole("group", { name: "The defenses side by side" });
    expect(within(choices).getByRole("button", { name: /Sysmon with the published rules/ })).toHaveAttribute("aria-pressed", "true");
    expect(within(choices).getByRole("button", { name: /Sysmon, a packet capture and Sigma's rules/ })).toBeVisible();
    expect(screen.getAllByText(/packet capture/i).length).toBeGreaterThan(0);
    expect(screen.queryAllByText(/a packet the capture kept/)).toEqual([]);
    expect(detail).not.toHaveTextContent(/alerted/i);

    fireEvent.click(within(choices).getByRole("button", { name: /Sysmon, a packet capture and Sigma's rules/ }));

    await waitFor(() => expect(detail).toHaveTextContent(/alerted/i));
    expect(within(detail).getByText("a packet the capture kept")).toBeVisible();
    expect(within(choices).getByRole("button", { name: /Sysmon, a packet capture and Sigma's rules/ })).toHaveAttribute("aria-pressed", "true");
  });
});
