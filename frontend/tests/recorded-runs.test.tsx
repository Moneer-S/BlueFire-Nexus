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
    // The run shipped with BlueFire first, although the imported one started a day later.
    expect(items.map((item) => within(item).getByRole("link").textContent)).toEqual(["60 published tests on one Linux host", "Two steps toward a secrets file"]);
    const [list, path] = items;
    expect(within(list!).getByRole("link")).toHaveAttribute("href", "/runs/recorded/lab-run-1");
    expect(within(list!).getByText("Test list")).toBeVisible();
    expect(within(list!).getByText("Recorded on a GitHub-hosted runner, 23 Nov 2026")).toBeVisible();
    expect(within(list!).getByText("Shipped with BlueFire")).toBeVisible();
    expect(within(list!).getByText("3 of 60 tests alerted, 56 seen, 1 unseen")).toBeVisible();
    expect(within(list!).queryByText("Still running")).not.toBeInTheDocument();

    expect(within(path!).getByText("Attack path")).toBeVisible();
    expect(within(path!).getByText("Recording on containers on a developer machine, started 24 Nov 2026")).toBeVisible();
    expect(within(path!).getByText("Imported, not verified by BlueFire")).toBeVisible();
    expect(within(path!).getByText("Still running")).toBeVisible();
    expect(within(path!).getByText("1 of 2 tests alerted, 1 seen, 0 unseen so far")).toBeVisible();
    expect(within(path!).getByText("First alert after 500 ms, the goal after 1 min 3 s")).toBeVisible();

    // Only what BlueFire shipped is called real.
    expect(within(recorded).getByText(/^Runs recorded step by step/)).toHaveTextContent("Those shipped with BlueFire are real runs of this repository's CI; imported ones are shown as their files say.");

    // The older engine's runs stay listed below, as they were.
    expect(await screen.findAllByRole("link", { name: /^Review run / })).toHaveLength(demoRuns.length);
  });

  it("keeps the shipped run first above an imported copy of it with later dates and the same title", async () => {
    const copy: RecordingSummary = { ...shipped, id: "newer-copy", source: { ...shipped.source, started: "2026-11-24T17:25:50Z", finished: "2026-11-24T17:36:23Z" }, origin: { kind: "imported", note: "Imported." } };
    const older: RecordingSummary = { ...copy, id: "older-import", title: "An older import", source: { ...shipped.source, started: "2026-11-01T10:00:00Z" } };
    vi.spyOn(api, "recordings").mockResolvedValue({ recordings: [older, copy, shipped], unreadable_count: 0, omitted_count: 0 });
    mount();
    const recorded = await screen.findByRole("region", { name: "Recorded runs" });
    const items = await within(recorded).findAllByRole("listitem");
    expect(items.map((item) => within(item).getByRole("link").getAttribute("href"))).toEqual(["/runs/recorded/lab-run-1", "/runs/recorded/newer-copy", "/runs/recorded/older-import"]);
    const [first, second] = items;
    if (!first || !second) throw new Error("The list holds fewer than two runs.");
    expect(within(first).getByText("Shipped with BlueFire")).toBeVisible();
    expect(within(second).getByText("Imported, not verified by BlueFire")).toBeVisible();
  });

  it("lists each change to the defense as a turn of the loop: named by what it did, how it was compared, and its result in a line", async () => {
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
    // Named by what it did, from the delta's count; the list entry names no step, so the words stay general.
    expect(within(changed).getByRole("link", { name: "1 step moved." })).toHaveAttribute("href", "/runs/compared/0000000000000001");
    expect(within(changed).getByText("New auditd settings")).toBeVisible();
    expect(within(changed).getByText("the settings of sensor auditd")).toBeVisible();
    expect(within(changed).getByText("Before 23 Nov 2026, after 24 Nov 2026")).toBeVisible();
    expect(within(changed).getByText("90 of 91 steps the same")).toBeVisible();
    expect(within(noVerdict).getByRole("link", { name: "No verdict." })).toBeVisible();
    expect(within(noVerdict).getByText("Nothing declared")).toBeVisible();
    expect(within(noVerdict).getByText("No verdict: the before recording has no source.setup, so what it was made with is not known (and 1 more reason)")).toBeVisible();
    // A comparison that declares no change is listed and opens as a comparison, outside the loop: no turn, no number.
    expect(within(within(list).getByRole("list", { name: "The changes to the defense, in order" })).getAllByRole("listitem")).toEqual([changed]);
    expect(within(list).getByRole("list", { name: "Comparisons that declare no change" })).toContainElement(noVerdict);
    expect(noVerdict).not.toHaveTextContent(/Turn/);
    expect(within(noVerdict).getByRole("link", { name: "See the difference" })).toHaveAttribute("href", "/runs/compared/0000000000000002");
    // Each run of a pair opens from its pair, by the file the pair names, and is not listed again as a run of its own.
    expect(within(changed).getByRole("link", { name: /^Play the before run/ })).toHaveAttribute("href", `/runs/recorded/lab-run-1/${"a".repeat(64)}`);
    expect(within(changed).getByRole("link", { name: /^Play the after run/ })).toHaveAttribute("href", `/runs/recorded/lab-run-2/${"a".repeat(64)}`);
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

  it("lists the turns in the order they happened, each named by what it did with its marks and its price, a run evaluated twice as one run", async () => {
    vi.spyOn(api, "recordings").mockResolvedValue({ recordings: [shipped], unreadable_count: 0, omitted_count: 0 });
    const counts = { paired: 93, same: 89, better: 4, worse: 0, changed: 0, "not attributable": 0, "without cause": 0, "no verdict": 0, new: 0, gone: 0 };
    const run = "https://github.com/example/bluefire/actions/runs/8";
    const side = (sha: string, started: string) => ({ sha256: sha.repeat(64), id: "rule-run", environment: "GitHub-hosted runner", run_url: run, started });
    const outcome = (value: "seen" | "alerted") => ({ happened: "took effect", recorded: "recorded", outcome: "seen", outcome_with_lab_rules: value } as const);
    const movedStep = (role: string, title: string) => ({ id: `${role}:${title}`, role, title, technique: "T1070.003", result: "better" as const, before: outcome("seen"), after: outcome("alerted") });
    const later: DeltaSummary = {
      id: "0000000000000005", claim: "one run evaluated with two rule sets", declared_change: "detectors:lab", runners: null, one_run: true, comparable: true, refused_because: [], counts,
      lab_rules: [{ rule: "r1", title: "Shell History File Truncated In Place", change: "new", before: null, after: { accepted: true, reason: "it alerted on every run" } }],
      moved: [movedStep("test", "Clear Bash history (echo)"), movedStep("variant", "Clear Bash history (echo)"), movedStep("test", "Clear Bash history (cat dev/null)"), movedStep("variant", "Clear Bash history (cat dev/null)")],
      before: side("b", "2026-11-24T12:42:13Z"), after: side("c", "2026-11-24T12:42:13Z"),
      recordings: { before: { ...shipped, id: "rule-run", source: { ...shipped.source, started: "2026-11-24T12:42:13Z" } }, after: { ...shipped, id: "rule-run", source: { ...shipped.source, started: "2026-11-24T12:42:13Z" } } },
      origin: { kind: "imported", note: "Imported." },
    };
    const earlier: DeltaSummary = {
      ...later, id: "0000000000000004", claim: "one pair of runs", declared_change: "sensors:auditd", one_run: false, runners: 2, lab_rules: null,
      counts: { ...counts, paired: 91, same: 90, better: 1 },
      moved: [{ ...movedStep("test", "Clear Bash history (echo)"), before: { ...outcome("seen"), outcome: "unseen", outcome_with_lab_rules: "unseen" }, after: outcome("seen"), price: "price: published rules that alerted on ordinary activity: 2 before, 2 after" }],
      before: { ...side("d", "2026-11-24T09:32:51Z"), id: "watch-before" }, after: { ...side("e", "2026-11-24T09:32:09Z"), id: "watch-after" },
      recordings: { before: { ...shipped, id: "watch-before", source: { ...shipped.source, started: "2026-11-24T09:32:51Z" } }, after: { ...shipped, id: "watch-after", source: { ...shipped.source, started: "2026-11-24T09:32:09Z" } } },
    };
    // The service lists the later pair first; the screen tells them in the order they happened.
    mount({ deltas: [later, earlier] });

    const list = await screen.findByRole("region", { name: "Before against after" });
    const items = within(list).getAllByRole("listitem");
    expect(items.map((item) => within(item).getAllByRole("link")[0]?.textContent)).toEqual(["Clear Bash history (echo) went from unseen to seen.", "4 steps went from seen to alerted."]);
    const [watch, rule] = items;
    if (!watch || !rule) throw new Error("Both pairs should be listed.");
    // The headline names the one test, and no line under it names it again.
    expect(within(watch).getAllByText(/Clear Bash history \(echo\)/)).toHaveLength(1);
    expect(within(watch).getByText("unseen")).toBeVisible();
    // The price in plain words, not the lab's log line.
    expect(within(watch).getByText("Price").parentElement).toHaveTextContent("Price2 published rules alert on ordinary activity, before and after");
    expect(within(rule).getByText("A new rule")).toBeVisible();
    expect(within(rule).getByText("Shell History File Truncated In Place")).toBeVisible();
    expect(within(rule).getByText("One run evaluated with two rule sets, 24 Nov 2026")).toBeVisible();
    expect(within(rule).getByText("Clear Bash history (echo) and (cat dev/null), each also with other arguments")).toBeVisible();
    // Alerted by the lab's rules alone, and said so.
    expect(within(rule).getByText("alerted")).toBeVisible();
    expect(within(rule).getByText("with the lab's rules")).toBeVisible();
    // The run evaluated twice opens with either set of rules, each by its own file.
    expect(within(rule).getByRole("link", { name: /^Play with the rules before/ })).toHaveAttribute("href", `/runs/recorded/rule-run/${"b".repeat(64)}`);
    expect(within(rule).getByRole("link", { name: /^Play with the rules after/ })).toHaveAttribute("href", `/runs/recorded/rule-run/${"c".repeat(64)}`);
  });

  it("keeps the turns shipped with BlueFire first, before an imported one from earlier runs, which is marked imported", async () => {
    vi.spyOn(api, "recordings").mockResolvedValue({ recordings: [shipped], unreadable_count: 0, omitted_count: 0 });
    const counts = { paired: 91, same: 90, better: 1, worse: 0, changed: 0, "not attributable": 0, "without cause": 0, "no verdict": 0, new: 0, gone: 0 };
    const side = (id: string, started: string) => ({ sha256: "a".repeat(64), id, environment: "GitHub-hosted runner", started });
    const at = (id: string, started: string) => ({ ...shipped, id, source: { ...shipped.source, started } });
    const ours: DeltaSummary = {
      id: "0000000000000006", claim: "one pair of runs", declared_change: "sensors:auditd", comparable: true, refused_because: [], counts,
      before: side("ours-before", "2026-11-24T09:00:00Z"), after: side("ours-after", "2026-11-24T09:10:00Z"),
      recordings: { before: at("ours-before", "2026-11-24T09:00:00Z"), after: at("ours-after", "2026-11-24T09:10:00Z") },
      origin: { kind: "shipped", run_url: "https://github.com/example/bluefire/actions/runs/9", note: "Shipped." },
    };
    const theirs: DeltaSummary = {
      ...ours, id: "0000000000000007", declared_change: "sensors:sysmon",
      before: side("theirs-before", "2026-11-20T09:00:00Z"), after: side("theirs-after", "2026-11-20T09:10:00Z"),
      recordings: { before: at("theirs-before", "2026-11-20T09:00:00Z"), after: at("theirs-after", "2026-11-20T09:10:00Z") },
      origin: { kind: "imported", note: "Imported." },
    };
    mount({ deltas: [theirs, ours] });
    const loop = await screen.findByRole("list", { name: "The changes to the defense, in order" });
    const [first, second] = within(loop).getAllByRole("listitem");
    if (!first || !second) throw new Error("Both turns should be listed.");
    expect(first).toHaveTextContent("Turn 1: New auditd settings");
    expect(first).toHaveTextContent("Shipped with BlueFire");
    expect(second).toHaveTextContent("Turn 2: New sysmon settings");
    expect(second).toHaveTextContent("Imported, not verified by BlueFire");
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

  it("sends a file the browser would read otherwise as it is, and shows the service's reason", async () => {
    vi.spyOn(api, "recordings").mockResolvedValue({ recordings: [shipped], unreadable_count: 0, omitted_count: 0 });
    const reason = "The file is not UTF-8 JSON: the key 'title' appears twice in one object";
    const importing = vi.spyOn(api, "importRecording").mockRejectedValue(new ApiError(`The recording is not valid: ${reason}`, "recording_invalid", { problems: [reason] }, 422));
    const user = mount();
    await screen.findByRole("region", { name: "Recorded runs" });
    // A byte order mark and a key twice: a browser's JSON reader would drop the one and keep the last of the other.
    const bytes = new Uint8Array([0xef, 0xbb, 0xbf, ...new TextEncoder().encode('{"title": "one", "title": "two"}')]);
    await user.upload(screen.getByLabelText("Recording file to import"), new File([bytes], "twice.json", { type: "application/json" }));
    const refusal = await screen.findByRole("alert");
    expect(within(refusal).getByText(`The recording is not valid: ${reason}`)).toBeVisible();
    expect([...(importing.mock.lastCall?.[0] ?? [])]).toEqual([...bytes]);
  });

  it("says so when the service cannot list its recordings, and keeps the older runs listed", async () => {
    vi.spyOn(api, "recordings").mockRejectedValue(new ApiError("The local service is unavailable.", "service_unavailable"));
    mount();
    expect(await screen.findByText("Recorded runs unavailable")).toBeVisible();
    expect(await screen.findByRole("heading", { name: "Experiment runs" })).toBeVisible();
  });
});
