import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Suspense, use, type ReactNode } from "react";
import { HashRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, type RecordingSummary } from "../src/lib/api";
import { demoCatalog, demoRuns, demoScenario } from "../src/lib/demo";
import { RecordedRunPage } from "../src/pages/RecordedRun";
import { RunsPage } from "../src/pages/Runs";
import { ProductProvider } from "../src/state/ProductContext";

// Going back to Runs from a recorded run, in the app's own hash addresses, with
// the cache kept as the app keeps it between visits.

/** A small recording that follows the format: two steps of an attack path, one alerted and one seen. */
const small = {
  schema: "bluefire.recording/1",
  id: "small-attack-path",
  title: "Two steps toward a secrets file",
  kind: "attack path",
  source: { engine: "test-engine", environment: "containers on a developer machine", started: "2026-11-20T10:00:00Z", finished: "2026-11-20T10:05:00Z", tools: [] },
  network: {
    hosts: [{ id: "web", name: "web", role: "web application", kind: "host" }],
    sensors: [{ id: "sysmon", name: "Sysmon for Linux 1.6.0", host: "web", records: "program starts" }],
    detectors: [{ id: "pinned", name: "Published Sigma rules", rules: 10, when: "after the run" }],
  },
  attacker: { kind: "scripted", description: "A short script.", goal: "Read the web server's secrets file." },
  steps: [
    {
      id: "1", order: 1, role: "test", title: "Discover the host", plain: "Prints what system the host runs.", technique: { id: "T1082" }, host: "web",
      started: "2026-11-20T10:01:00.000Z", ended: "2026-11-20T10:01:02.000Z",
      happened: { answer: "took effect", basis: "the command exited with status 0" },
      visibility: { answer: "alert", basis: "a published rule matched at level high", events: 1 },
      outcome: "alerted", first_event: "2026-11-20T10:01:00.500Z", first_alert: "2026-11-20T10:01:00.500Z",
    },
    {
      id: "2", order: 2, role: "test", title: "Read the secrets file", plain: "Reads the web server's secrets file.", technique: { id: "T1005" }, host: "web",
      started: "2026-11-20T10:02:00.000Z", ended: "2026-11-20T10:02:03.000Z",
      happened: { answer: "took effect", basis: "the file was read" },
      visibility: { answer: "telemetry only", basis: "a sensor recorded it, no rule at alert level matched", events: 1 },
      outcome: "seen", first_event: "2026-11-20T10:02:01.000Z",
    },
  ],
  events: [
    { id: "e1", time: "2026-11-20T10:01:00.500Z", host: "web", sensor: "sysmon", kind: "process start", text: "uname -a", step: "1", tied_by: "session" },
    { id: "e2", time: "2026-11-20T10:02:01.000Z", host: "web", sensor: "sysmon", kind: "process start", text: "cat /srv/secrets", step: "2", tied_by: "session" },
  ],
  alerts: [{
    id: "a1", time: "2026-11-20T10:01:00.500Z", host: "web", detector: "pinned",
    rule: { id: "r1", title: "System Information Discovery", level: "high", origin: "pinned" }, counts: true, step: "1", events: ["e1"],
  }],
  score: { steps: 2, took_effect: 2, alerted: 1, seen: 1, unseen: 0, stopped: 0, first_alert_seconds: 0.5, goal_seconds: 63 },
  notes: [],
};

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

const imported: RecordingSummary = {
  id: small.id,
  title: small.title,
  kind: "attack path",
  source: { engine: small.source.engine, environment: small.source.environment, started: small.source.started, finished: small.source.finished },
  score: small.score,
  counts: { steps: 2, events: 2, alerts: 1 },
  origin: { kind: "imported", note: "Imported. BlueFire cannot confirm that the steps ran." },
  running: false,
};

const stillRunning: RecordingSummary = { ...imported, source: { engine: small.source.engine, environment: small.source.environment, started: small.source.started }, running: true };

/** Holds the Runs page back while it is set, as a Runs page that takes long to render on a busy machine. */
const slow: { until: Promise<void> | null } = { until: null };
function Slow({ children }: { children: ReactNode }) {
  if (slow.until) use(slow.until);
  return children;
}

/**
 * The service as these tests need it: what it keeps, its list, one recording,
 * and an import that keeps the recording it is sent.
 */
function mount(kept: { list: RecordingSummary[]; entry: RecordingSummary }) {
  vi.spyOn(api, "catalog").mockResolvedValue(structuredClone(demoCatalog));
  vi.spyOn(api, "runs").mockResolvedValue({ runs: structuredClone(demoRuns), unavailable_run_count: 0 });
  vi.spyOn(api, "scenarios").mockResolvedValue({ scenarios: [structuredClone(demoScenario)] });
  vi.spyOn(api, "activeJobs").mockResolvedValue({ schema_version: "bluefire.active-job-list.v1", jobs: [] });
  vi.spyOn(api, "recordings").mockImplementation(async () => ({ recordings: [...kept.list], unreadable_count: 0, omitted_count: 0 }));
  vi.spyOn(api, "recording").mockImplementation(async () => ({ summary: kept.entry, recording: small }));
  // The app's own query settings: a list read in the last 15 seconds is shown as it is when Runs opens again.
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 15_000, refetchOnWindowFocus: false }, mutations: { retry: false } } });
  window.history.replaceState(null, "", "#/runs");
  render(<QueryClientProvider client={client}><ProductProvider><HashRouter><Suspense fallback={<p>Loading the page</p>}>
    <Routes>
      <Route path="/runs" element={<Slow><RunsPage /></Slow>} />
      <Route path="/runs/recorded/:recordingId" element={<RecordedRunPage />} />
    </Routes>
  </Suspense></HashRouter></ProductProvider></QueryClientProvider>);
  return userEvent.setup();
}

function recordingFile(value: unknown) {
  return new File([JSON.stringify(value)], "small.json", { type: "application/json" });
}

/** How long a page may take to show: the live view and the Runs page mount whole, which is slow on a busy machine. */
const shown = { timeout: 8_000 };

const backToRuns = () => within(screen.getByRole("navigation", { name: "Recorded run" })).getByRole("link", { name: "Runs" });

/** The row of the Runs screen's recorded runs that names `title`. */
async function listed(title: string): Promise<HTMLElement> {
  const region = await screen.findByRole("region", { name: "Recorded runs" }, shown);
  const row = (await within(region).findByRole("link", { name: title }, shown)).closest("li");
  if (!row) throw new Error(`${title} is not in a row of the list`);
  return row;
}

// The live view mounts whole in each test, which takes some seconds on a busy machine.
describe("going back to Runs from a recorded run", { timeout: 20_000 }, () => {
  afterEach(() => { slow.until = null; });

  it("lists the recording just imported, when the run's page writes its moment while Runs is still rendering", async () => {
    const kept = { list: [shipped], entry: imported };
    vi.spyOn(api, "importRecording").mockImplementation(async () => {
      kept.list = [shipped, imported];
      return { created: true, replaced: false, summary: imported };
    });
    const user = mount(kept);
    await screen.findByRole("region", { name: "Recorded runs" }, shown);
    await user.upload(screen.getByLabelText("Recording file to import"), recordingFile(small));
    await screen.findByRole("slider", { name: /^Timeline/ }, shown);

    // The viewer pauses, which the page puts in its address a moment later, and
    // at once goes back to Runs, which takes longer than that to show.
    let ready = () => {};
    slow.until = new Promise((resolve) => { ready = resolve; });
    await user.click(screen.getByRole("button", { name: "Pause" }));
    // A plain click, as in a browser: the router renders the next page in a
    // transition, which a test's act scope would otherwise finish at once.
    backToRuns().click();
    await new Promise((resolve) => setTimeout(resolve, 700));
    slow.until = null;
    ready();

    const row = await listed("Two steps toward a secrets file");
    expect(within(row).getByText("Imported, not verified by BlueFire")).toBeVisible();
    expect(within(row).getByText("1 of 2 steps alerted, 1 seen, 0 unseen")).toBeVisible();
    expect(window.location.hash).toBe("#/runs");
  });

  it("shows a run that finished after the list was read as finished, not still running", async () => {
    const kept = { list: [shipped, stillRunning], entry: stillRunning };
    const user = mount(kept);
    const before = await listed("Two steps toward a secrets file");
    expect(within(before).getByText("Still running")).toBeVisible();

    // The engine sends the finished version; the viewer then opens the run, and goes back.
    kept.list = [shipped, imported];
    kept.entry = imported;
    await user.click(within(before).getByRole("link", { name: "Two steps toward a secrets file" }));
    await screen.findByRole("slider", { name: /^Timeline/ }, shown);
    expect(screen.queryByText("Still running: new steps appear as they arrive")).not.toBeInTheDocument();
    await user.click(backToRuns());

    const after = await listed("Two steps toward a secrets file");
    expect(within(after).queryByText("Still running")).not.toBeInTheDocument();
    expect(within(after).getByText("1 of 2 steps alerted, 1 seen, 0 unseen")).toBeVisible();
  });

  it("lists a recording the service kept when its answer to the import was lost", async () => {
    const kept = { list: [shipped], entry: imported };
    vi.spyOn(api, "importRecording").mockImplementation(async () => {
      kept.list = [shipped, imported];
      throw new ApiError("The local service did not respond before the timeout.", "request_timeout");
    });
    const user = mount(kept);
    await screen.findByRole("region", { name: "Recorded runs" }, shown);
    await user.upload(screen.getByLabelText("Recording file to import"), recordingFile(small));

    expect(await screen.findByRole("alert", {}, shown)).toHaveTextContent("The local service did not respond before the timeout.");
    const row = await listed("Two steps toward a secrets file");
    expect(within(row).getByText("Imported, not verified by BlueFire")).toBeVisible();
  });
});
