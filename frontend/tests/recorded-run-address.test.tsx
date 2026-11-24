import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HashRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { api, type RecordingSummary } from "../src/lib/api";
import { RecordedRunPage } from "../src/pages/RecordedRun";
import { at, event, recording, step } from "./live-fixture";

// A recorded run's address names a step that its recording does not hold: a
// mistyped or stale link. The live view says so in one line and opens at the
// start of the run; the page that writes its moment into the address must not
// put the step the view fell back to in place of the one that was asked for.

const value = recording({ steps: [step("1", 10, 11), step("2", 20, 21)], events: [event("1-1", "1", 10.5), event("2-1", "2", 20.5)] });

const summary: RecordingSummary = {
  id: value.id,
  title: value.title,
  kind: value.kind,
  source: { engine: value.source.engine, environment: value.source.environment, started: at(0), finished: at(600) },
  score: value.score,
  counts: { steps: 2, events: 2, alerts: 0 },
  origin: { kind: "imported", note: "Imported. BlueFire cannot confirm that the steps ran." },
  running: false,
};

function open(query: string) {
  vi.spyOn(api, "recording").mockResolvedValue({ summary, recording: value });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  window.history.replaceState(null, "", `#/runs/recorded/${value.id}?${query}`);
  render(<QueryClientProvider client={client}><HashRouter>
    <Routes>
      <Route path="/runs/recorded/:recordingId" element={<RecordedRunPage />} />
    </Routes>
  </HashRouter></QueryClientProvider>);
  return userEvent.setup();
}

/** Longer than the page waits before it writes its moment into the address. */
const settle = () => new Promise((resolve) => setTimeout(resolve, 700));

const shown = { timeout: 8_000 };

describe("a recorded run's address that names a step the recording does not hold", { timeout: 20_000 }, () => {
  it.each([
    ["in watch mode", "step=gone&at=0.5&paused=1", 'Step "gone" is not in this recording.'],
    ["in analyse mode", "mode=analyse&select=gone", 'Step "gone" is not in this recording.'],
    ["playing", "step=gone", 'Step "gone" is not in this recording.'],
  ])("keeps that step in the address and the line that says so, %s, until the viewer moves", async (_case, query, line) => {
    const user = open(query);
    expect(await screen.findByText(line, {}, shown)).toBeVisible();
    await settle();
    // The address still names the step that was asked for, and the line is still there.
    expect(window.location.hash).toBe(`#/runs/recorded/${value.id}?${query}`);
    expect(screen.getByText(line)).toBeVisible();

    // Once the viewer moves, the address follows them, and the line stays for the visit.
    if (query.startsWith("mode=analyse")) await user.click(screen.getByRole("button", { name: /^Watch$/ }));
    else await user.click(screen.getByRole("button", { name: /^(Play|Pause)$/ }));
    await settle();
    expect(window.location.hash).not.toContain("gone");
    expect(screen.getByText(line)).toBeVisible();
  });
});
