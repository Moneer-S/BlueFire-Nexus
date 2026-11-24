import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { api, type Delta, type DeltaStep, type DeltaSummary, type RecordingSummary } from "../src/lib/api";
import { activeProviderKind, backPath, candidates, draftKey, fixPath, modelWords, tieOf, triedFor } from "../src/lib/fix-step";
import type { Recording } from "../src/live/recording";
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

const WATCH = delta("0000000000000001", { id: "rec-1", sha256: SHA }, { id: "rec-2", sha256: OTHER_SHA }, [movedStep("1", "unseen", "seen", "better: unseen to seen by the published rules; price: 2 ordinary events before, 2 after; one pair of runs", "price: 2 ordinary events before, 2 after")]);
const RULE_PRICE = "price: 1 rule more (The run accepted 1 of the 2 rules written in this repository.)";
const ELSEWHERE = delta("0000000000000002", { id: "rec-8", sha256: "d".repeat(64) }, { id: "rec-9", sha256: "e".repeat(64) }, [movedStep("1", "seen", "alerted", `better: seen to alerted with the lab's rules; ${RULE_PRICE}`, RULE_PRICE)]);

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
    expect(start).toHaveTextContent("Nothing of this test was recorded. Start with a sensor's settings: a rule can only match what a sensor records.");
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
    const rm = within(recorded).getByRole("link", { name: /Clear Bash history \(rm\)/ });
    expect(rm).toHaveTextContent("test 4");
    expect(rm).toHaveTextContent("alerted");
    expect(rm).toHaveAttribute("href", "/runs/recorded/rec-1?step=4&at=0&paused=1&mode=analyse&select=4");

    expect(screen.queryByRole("textbox")).toBeNull();
    expect(screen.queryByRole("region", { name: "A draft" })).toBeNull();
    expect(screen.queryByRole("region", { name: "Rules that matched it" })).toBeNull();
  });

  it("for a step seen with no alert, shows what matched it below alert level with what the recording says of the lab's rules, and an empty draft", async () => {
    mount("2");
    const start = await screen.findByRole("region", { name: "Where to start" });
    expect(start).toHaveTextContent("A sensor recorded this test, but no rule raised an alert. Start with a rule that matches what the sensor recorded.");
    const matched = screen.getByRole("region", { name: "Rules that matched it" });
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
    expect(draft).toHaveAccessibleDescription(/A run accepts it only if it alerts on every rerun of a test with changed arguments and on nothing in ordinary activity/);
  });

  it("offers no draft while the recording is still running, since a draft is kept for one finished file", async () => {
    mount("2", { running: true });
    const draft = await screen.findByRole("region", { name: "A draft" });
    expect(draft).toHaveTextContent("This recording is still running.");
    expect(screen.queryByRole("textbox")).toBeNull();
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
    expect(start).toHaveTextContent("One of the lab's own rules raised an alert on it: it is caught. The score counts published rules only, and none of those alerted, so the score leaves it out.");
    const matched = screen.getByRole("region", { name: "Rules that matched it" });
    // Where the run loaded the rule from, as the recording says; not a claim about the repository today.
    expect(matched).toHaveTextContent("The run loaded it from commit ffffffff.");
    expect(matched).not.toHaveTextContent(/in the repository already/);
    const rule = within(matched).getByRole("article", { name: "Shell History File Truncated In Place" });
    expect(rule).toHaveTextContent("would alert · high");
    expect(rule).toHaveTextContent("accepted");
    expect(rule).toHaveTextContent("lab/rules/linux/auditd/truncated.yml");
    expect(within(rule).getByLabelText("The text of the rule Shell History File Truncated In Place")).toHaveTextContent("title: Shell History File Truncated In Place level: high");
    expect(screen.queryByRole("textbox")).toBeNull();
  });

  it("for a step a published rule alerted on, shows the rule that alerted", async () => {
    mount("4");
    const start = await screen.findByRole("region", { name: "Where to start" });
    expect(start).toHaveTextContent("A published rule raised an alert on it. There is nothing to fix here.");
    expect(within(screen.getByRole("region", { name: "Rules that matched it" })).getByRole("article", { name: "History File Deletion" })).toHaveTextContent("alert · high");
    expect(screen.queryByRole("textbox")).toBeNull();
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
    expect(watch).toHaveTextContent("The settings of sensor auditd");
    expect(watch).toHaveTextContent("This run is the one before the change.");
    expect(watch).toHaveTextContent("Imported");
    expect(within(watch).getByText("price: 2 ordinary events before, 2 after")).toHaveClass("cmp-price");
    expect(within(watch).getByRole("link", { name: "Open the comparison at this step" })).toHaveAttribute("href", "/runs/compared/0000000000000001?step=1");
    expect(within(watch).getByRole("link", { name: "Open the same step in the after run" })).toHaveAttribute("href", `/runs/recorded/rec-2/${OTHER_SHA}?step=1&at=0&paused=1&mode=analyse&select=1`);
    // A comparison of other runs, tied by the step's stable id, and said to be of another run.
    expect(elsewhere).toHaveTextContent("Another run of the same list, not this one, with the same published test. Step 1");
    expect(within(elsewhere).queryByRole("link", { name: "Open the same step in the after run" })).toBeNull();
    // The price's lead on the step's line, and the comparison's own words, with what the price quotes, one click away.
    expect(within(elsewhere).getByText("price: 1 rule more")).toHaveClass("cmp-price");
    expect(within(elsewhere).getByText(/The run accepted 1 of the 2 rules written in this repository/)).not.toBeVisible();
    await userEvent.setup().click(within(elsewhere).getByText("The comparison's own words"));
    expect(within(elsewhere).getByText(/The run accepted 1 of the 2 rules written in this repository/)).toBeVisible();
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
    expect(line).toHaveTextContent("Another run of the same list, not this one, with the same published test as the list runs it. Published test cbf506a5");
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
