import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { api, type DeltaSummary, type RecordingSummary } from "../src/lib/api";
import { RecordedRunPage } from "../src/pages/RecordedRun";
import { at, event, recording, step } from "./live-fixture";

// The runs of a comparison often carry the same title as a run of their own.
// The line above the live view says which run of which comparison a file is.

const value = recording({ steps: [step("1", 10, 11)], events: [event("1-1", "1", 10.5)] });
const TITLE = "60 published tests on one Linux host";

const summary = (id: string): RecordingSummary => ({
  id,
  title: TITLE,
  kind: "test list",
  source: { engine: "bluefire-lab", environment: "GitHub-hosted runner", started: at(0), finished: at(600) },
  score: value.score,
  counts: { steps: 1, events: 1, alerts: 0 },
  origin: { kind: "shipped", run_url: "https://github.com/example/lab/actions/runs/1", note: "Shipped with BlueFire." },
  running: false,
});

const counts = { paired: 91, same: 90, better: 1, worse: 0, changed: 0, "not attributable": 0, "without cause": 0, "no verdict": 0, new: 0, gone: 0 };
const side = (id: string, sha: string) => ({ id, sha256: sha.repeat(64), environment: "GitHub-hosted runner", started: at(0) });

/** Two runs side by side, before and after new auditd settings. */
const WATCH: DeltaSummary = {
  id: "0000000000000001", claim: "one pair of runs", declared_change: "sensors:auditd", runners: 2, comparable: true, refused_because: [], counts,
  before: side("watch-before", "a"), after: side("watch-after", "b"),
  recordings: { before: summary("watch-before"), after: summary("watch-after") },
  origin: { kind: "shipped", run_url: "https://github.com/example/lab/actions/runs/2", note: "Shipped." },
};

/** One run evaluated with the lab's rules before and after a new rule: one id, two files. */
const RULE: DeltaSummary = {
  ...WATCH, id: "0000000000000002", claim: "one run evaluated with two rule sets", declared_change: "detectors:lab", runners: null, one_run: true,
  lab_rules: [{ rule: "r1", title: "Shell History File Truncated In Place", change: "new", before: null, after: { accepted: true, reason: "it alerted on every run" } }],
  before: side("rule-run", "c"), after: side("rule-run", "d"),
  recordings: { before: summary("rule-run"), after: summary("rule-run") },
};

function open(address: string, id: string, sha256: string) {
  vi.spyOn(api, "recording").mockResolvedValue({ summary: summary(id), recording: { ...value, id, title: TITLE }, sha256 });
  vi.spyOn(api, "recordingFile").mockResolvedValue({ summary: summary(id), recording: { ...value, id, title: TITLE } });
  vi.spyOn(api, "recordingDeltas").mockResolvedValue({ deltas: [RULE, WATCH], unreadable_count: 0, omitted_count: 0 });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[address]}>
    <Routes>
      <Route path="/runs/recorded/:recordingId" element={<RecordedRunPage />} />
      <Route path="/runs/recorded/:recordingId/:file" element={<RecordedRunPage />} />
    </Routes>
  </MemoryRouter></QueryClientProvider>);
  return screen.findByRole("navigation", { name: "Recorded run" });
}

describe("the line above a recorded run", { timeout: 20_000 }, () => {
  it.each([
    ["the before run of a pair", "/runs/recorded/watch-before/" + "a".repeat(64), "watch-before", "a", "Before against after: New auditd settings · the run before", WATCH.id],
    ["the after run of a pair", "/runs/recorded/watch-after/" + "b".repeat(64), "watch-after", "b", "Before against after: New auditd settings · the run after", WATCH.id],
    ["the first file of an id, which the service names", "/runs/recorded/watch-after", "watch-after", "b", "Before against after: New auditd settings · the run after", WATCH.id],
    ["one run with the rules before", "/runs/recorded/rule-run/" + "c".repeat(64), "rule-run", "c", "Before against after: A new rule · with the rules before", RULE.id],
    ["one run with the rules after", "/runs/recorded/rule-run/" + "d".repeat(64), "rule-run", "d", "Before against after: A new rule · with the rules after", RULE.id],
  ])("says which run of its comparison it is: %s", async (_case, address, id, sha, words, pair) => {
    const line = await open(address, id, sha.repeat(64));
    const named = await within(line).findByText((_, element) => element?.classList.contains("recorded-run-side") === true && element.textContent === words);
    expect(named).toBeVisible();
    expect(within(named).getByRole("link")).toHaveAttribute("href", `/runs/compared/${pair}`);
    // The recording keeps its own title beside it.
    expect(within(line).getByText(TITLE)).toBeVisible();
  });

  it("names no comparison for a run that is a side of none", async () => {
    const line = await open("/runs/recorded/own-run", "own-run", "e".repeat(64));
    expect(await within(line).findByText(TITLE)).toBeVisible();
    // The list of comparisons has been read, and none names this file.
    await vi.waitFor(() => expect(api.recordingDeltas).toHaveBeenCalled());
    expect(line).not.toHaveTextContent("Before against after");
  });
});
