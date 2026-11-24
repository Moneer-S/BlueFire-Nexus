import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { api, ApiError, type DeltaSummary, type RecordingSummary } from "../src/lib/api";
import { demoCatalog, demoRuns, demoScenario } from "../src/lib/demo";
import { RunsPage } from "../src/pages/Runs";
import { ProductProvider } from "../src/state/ProductContext";

const shipped: RecordingSummary = {
  id: "lab-run-1",
  title: "60 published tests on one Linux host",
  kind: "test list",
  source: { engine: "bluefire-lab", environment: "GitHub-hosted runner", started: "2026-11-23T17:25:50Z", finished: "2026-11-23T17:36:23Z" },
  score: { steps: 60, took_effect: 60, alerted: 3, seen: 56, unseen: 1, stopped: 8 },
  counts: { steps: 91, events: 1931, alerts: 233 },
  origin: { kind: "shipped", run_url: "https://github.com/example/bluefire/actions/runs/1", note: "Shipped with BlueFire." },
  running: false,
};

const running: RecordingSummary = {
  id: "path-run-2",
  title: "Two steps toward a secrets file",
  kind: "attack path",
  source: { engine: "range", environment: "containers on a developer machine", started: "2026-11-24T10:00:00Z" },
  score: { steps: 2, took_effect: 2, alerted: 1, seen: 1, unseen: 0, stopped: 0, first_alert_seconds: 0.5, goal_seconds: 63 },
  counts: { steps: 2, events: 2, alerts: 1 },
  origin: { kind: "imported", note: "Imported. BlueFire cannot confirm that the steps ran." },
  running: true,
};

function Address() {
  const location = useLocation();
  return <output aria-label="Address">{location.pathname}</output>;
}

function mount({ runs = demoRuns, deltas = [] as DeltaSummary[] } = {}) {
  vi.spyOn(api, "recordingDeltas").mockResolvedValue({ deltas, unreadable_count: 0, omitted_count: 0 });
  vi.spyOn(api, "catalog").mockResolvedValue(structuredClone(demoCatalog));
  vi.spyOn(api, "runs").mockResolvedValue({ runs: structuredClone(runs), unavailable_run_count: 0 });
  vi.spyOn(api, "scenarios").mockResolvedValue({ scenarios: [structuredClone(demoScenario)] });
  vi.spyOn(api, "activeJobs").mockResolvedValue({ schema_version: "bluefire.active-job-list.v1", jobs: [] });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter initialEntries={["/runs"]}>
    <Routes>
      <Route path="/runs" element={<RunsPage />} />
      <Route path="/runs/recorded/:recordingId" element={<p>Recorded run page</p>} />
    </Routes>
    <Address />
  </MemoryRouter></ProductProvider></QueryClientProvider>);
  return userEvent.setup();
}

function recordingFile(value: unknown, name = "recording.json") {
  return new File([typeof value === "string" ? value : JSON.stringify(value)], name, { type: "application/json" });
}

describe("the Runs screen's recorded runs", () => {
  it("lists recorded runs first, each saying what it is, where it comes from and its score in words", async () => {
    vi.spyOn(api, "recordings").mockResolvedValue({ recordings: [shipped, running], unreadable_count: 0, omitted_count: 0 });
    mount();
    const recorded = await screen.findByRole("region", { name: "Recorded runs" });
    const older = await screen.findByRole("heading", { name: "Experiment runs" });
    expect(recorded.compareDocumentPosition(older) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();

    const items = within(recorded).getAllByRole("listitem");
    // Newest first: the run that is still going started a day later.
    expect(items.map((item) => within(item).getByRole("link").textContent)).toEqual(["Two steps toward a secrets file", "60 published tests on one Linux host"]);
    const [path, list] = items;
    expect(within(list!).getByRole("link")).toHaveAttribute("href", "/runs/recorded/lab-run-1");
    expect(within(list!).getByText("Test list")).toBeVisible();
    expect(within(list!).getByText("Recorded on a GitHub-hosted runner, 23 Nov 2026")).toBeVisible();
    expect(within(list!).getByText("Shipped with BlueFire")).toBeVisible();
    expect(within(list!).getByText("3 of 60 tests alerted, 56 seen, 1 unseen")).toBeVisible();
    expect(within(list!).queryByText("Still running")).not.toBeInTheDocument();

    expect(within(path!).getByText("Attack path")).toBeVisible();
    expect(within(path!).getByText("Recording on containers on a developer machine, started 24 Nov 2026")).toBeVisible();
    expect(within(path!).getByText("Imported")).toBeVisible();
    expect(within(path!).getByText("Still running")).toBeVisible();
    expect(within(path!).getByText("1 of 2 tests alerted, 1 seen, 0 unseen so far")).toBeVisible();
    expect(within(path!).getByText("First alert after 500 ms, the goal after 1 min 3 s")).toBeVisible();

    // The older engine's runs stay listed below, as they were.
    expect(await screen.findAllByRole("link", { name: /^Review run / })).toHaveLength(demoRuns.length);
  });

  it("lists each pair of compared runs under its own heading: the change, the two dates and one line of the result", async () => {
    vi.spyOn(api, "recordings").mockResolvedValue({ recordings: [shipped], unreadable_count: 0, omitted_count: 0 });
    const counts = { paired: 91, same: 90, better: 1, worse: 0, changed: 0, "not attributable": 0, "without cause": 0, "no verdict": 0, new: 0, gone: 0 };
    const side = (id: string, started: string) => ({ sha256: "a".repeat(64), id, environment: "GitHub-hosted runner", started });
    const pair: DeltaSummary = {
      id: "0000000000000001", claim: "one pair of runs", declared_change: "sensors:auditd", comparable: true, refused_because: [], counts,
      before: side("lab-run-1", "2026-11-23T17:25:50Z"), after: side("lab-run-2", "2026-11-24T09:00:00Z"),
      recordings: { before: shipped, after: { ...shipped, id: "lab-run-2" } },
      origin: { kind: "imported", note: "Imported." },
    };
    const refused: DeltaSummary = { ...pair, id: "0000000000000002", declared_change: null, comparable: false, refused_because: ["the before recording has no source.setup, so what it was made with is not known", "also differed: the kernel of host `target`"] };
    mount({ deltas: [pair, refused] });

    const list = await screen.findByRole("region", { name: "Before against after" });
    const [changed, noVerdict] = within(list).getAllByRole("listitem");
    if (!changed || !noVerdict) throw new Error("Both pairs should be listed.");
    expect(within(changed).getByRole("link", { name: "The settings of sensor auditd" })).toHaveAttribute("href", "/runs/compared/0000000000000001");
    expect(within(changed).getByText("Before 23 Nov 2026, after 24 Nov 2026")).toBeVisible();
    expect(within(changed).getByText("1 better, 0 worse, 0 changed without a cause, of 91 paired steps")).toBeVisible();
    expect(within(noVerdict).getByRole("link", { name: "Nothing declared as changed" })).toBeVisible();
    expect(within(noVerdict).getByText("No verdict: the before recording has no source.setup, so what it was made with is not known (and 1 more reason)")).toBeVisible();
    // Each run of a pair opens from its pair, and is not listed again as a run of its own.
    expect(within(changed).getByRole("link", { name: /^Play the before run/ })).toHaveAttribute("href", "/runs/recorded/lab-run-1");
    expect(within(changed).getByRole("link", { name: /^Play the after run/ })).toHaveAttribute("href", "/runs/recorded/lab-run-2");
    const recorded = screen.getByRole("region", { name: "Recorded runs" });
    expect(within(recorded).queryByRole("link", { name: "60 published tests on one Linux host" })).not.toBeInTheDocument();
    expect(within(recorded).getByText("1 more recorded run is listed with its pairs under Before against after.")).toBeVisible();
    expect(within(recorded).queryByText("No recorded runs yet. Import a recording file made by the lab.")).not.toBeInTheDocument();
  });

  it("lists two runs side by side as such, and a limited verdict as limited, never as a plain gain", async () => {
    vi.spyOn(api, "recordings").mockResolvedValue({ recordings: [running], unreadable_count: 0, omitted_count: 0 });
    const counts = { paired: 91, same: 90, better: 1, worse: 0, changed: 0, "not attributable": 0, "without cause": 0, "no verdict": 0, by_mark: 1, new: 0, gone: 0 };
    const side = (id: string, started: string) => ({ sha256: "a".repeat(64), id, environment: "GitHub-hosted runner", run_url: "https://github.com/example/bluefire/actions/runs/7", started });
    const limited: DeltaSummary = {
      id: "0000000000000003", claim: "one pair of runs", declared_change: "sensors:auditd", runners: 2, comparable: true, refused_because: [], counts,
      limit: { why: "the two runners differed", differences: ["images:target", "kernels:target"], credits: "only a step that carries the change's own mark: every event the recordings hold of it is of an audit key whose every rule in that run watches a path that no rule of the other run, as written, could have recorded, and the other run holds nothing of it", credited: 1, not_attributable: 0 },
      before: side("pair-before", "2026-11-24T09:08:49Z"), after: side("pair-after", "2026-11-24T09:09:06Z"),
      recordings: { before: { ...shipped, id: "pair-before" }, after: { ...shipped, id: "pair-after" } },
      origin: { kind: "imported", note: "Imported." },
    };
    mount({ deltas: [limited] });

    const list = await screen.findByRole("region", { name: "Before against after" });
    const [item] = within(list).getAllByRole("listitem");
    if (!item) throw new Error("The pair should be listed.");
    expect(within(item).getByText("Two runs side by side, 24 Nov 2026")).toBeVisible();
    expect(within(item).getByText("Limited verdict, the runners differed: 1 better, 0 worse, 1 of them by the change's own mark alone; 0 not attributable; of 91 paired steps")).toBeVisible();
    expect(within(item).queryByText(/^1 better/)).not.toBeInTheDocument();
  });

  it("shows no pairs, and no heading for them, when the service keeps none", async () => {
    vi.spyOn(api, "recordings").mockResolvedValue({ recordings: [shipped], unreadable_count: 0, omitted_count: 0 });
    mount();
    await screen.findByText("3 of 60 tests alerted, 56 seen, 1 unseen");
    expect(screen.queryByText("Before against after")).not.toBeInTheDocument();
  });

  it("gives recorded runs and the older engine's runs each their own empty state", async () => {
    vi.spyOn(api, "recordings").mockResolvedValue({ recordings: [], unreadable_count: 0, omitted_count: 0 });
    mount({ runs: [] });
    expect(await screen.findByText("No recorded runs yet. Import a recording file made by the lab.")).toBeVisible();
    expect(await screen.findByText("No experiment runs yet.")).toBeVisible();
  });

  it("shows a refused import with every problem the service named, and opens a recording it accepts", async () => {
    vi.spyOn(api, "recordings").mockResolvedValue({ recordings: [shipped], unreadable_count: 0, omitted_count: 0 });
    const importing = vi.spyOn(api, "importRecording")
      .mockRejectedValueOnce(new ApiError("The recording is not valid: score.alerted is 2, but the steps give 1.", "recording_invalid", { problems: ["score.alerted is 2, but the steps give 1.", "score.seen is 1, but the steps give 0."] }, 422))
      .mockResolvedValueOnce({ created: true, replaced: false, summary: { ...running, id: "path-run-2" } });
    const user = mount();
    await screen.findByRole("region", { name: "Recorded runs" });
    const input = screen.getByLabelText("Recording file to import");

    await user.upload(input, recordingFile({ schema: "bluefire.recording/1", id: "broken" }));
    const refusal = await screen.findByRole("alert");
    expect(within(refusal).getByText("The recording was not imported")).toBeVisible();
    // Each problem once: the service's message repeats the first, so it is not shown beside the list.
    expect(within(refusal).getAllByText(/score\.alerted is 2, but the steps give 1\./)).toHaveLength(1);
    expect(within(refusal).getByText("score.seen is 1, but the steps give 0.")).toBeVisible();
    // The file's own bytes are sent, not the recording parsed and written again.
    expect(new TextDecoder().decode(importing.mock.lastCall?.[0])).toBe(JSON.stringify({ schema: "bluefire.recording/1", id: "broken" }));
    expect(screen.getByLabelText("Address")).toHaveTextContent("/runs");

    await user.upload(input, recordingFile({ schema: "bluefire.recording/1", id: "path-run-2" }));
    expect(await screen.findByText("Recorded run page")).toBeVisible();
    expect(screen.getByLabelText("Address")).toHaveTextContent("/runs/recorded/path-run-2");
  });

  it("does not send a file that is not JSON, and says why", async () => {
    vi.spyOn(api, "recordings").mockResolvedValue({ recordings: [shipped], unreadable_count: 0, omitted_count: 0 });
    const importing = vi.spyOn(api, "importRecording");
    const user = mount();
    await screen.findByRole("region", { name: "Recorded runs" });
    await user.upload(screen.getByLabelText("Recording file to import"), recordingFile("not json", "notes.json"));
    expect(await screen.findByText(/^notes\.json is not a JSON file, so it was not sent/)).toBeVisible();
    expect(importing).not.toHaveBeenCalled();
  });

  it("says so when the service cannot list its recordings, and keeps the older runs listed", async () => {
    vi.spyOn(api, "recordings").mockRejectedValue(new ApiError("The local service is unavailable.", "service_unavailable"));
    mount();
    expect(await screen.findByText("Recorded runs unavailable")).toBeVisible();
    expect(await screen.findByRole("heading", { name: "Experiment runs" })).toBeVisible();
  });
});
