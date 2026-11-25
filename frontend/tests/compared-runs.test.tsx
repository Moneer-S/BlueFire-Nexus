import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import ruleDeltaText from "../../bluefire/data/recordings/deltas/lab-rule-history-truncated.json?raw";
import ruleBaseText from "../../bluefire/data/recordings/lab-rule-history-truncated-base.json?raw";
import ruleHeadText from "../../bluefire/data/recordings/lab-rule-history-truncated-head.json?raw";
import sensorDeltaText from "../../bluefire/data/recordings/deltas/lab-pair-history-watch.json?raw";
import sensorBeforeText from "../../bluefire/data/recordings/lab-pair-history-watch-before.json?raw";
import sensorAfterText from "../../bluefire/data/recordings/lab-pair-history-watch-after.json?raw";
import { api, readDelta, type Delta, type DeltaStep, type DeltaSummary, type RecordingSummary } from "../src/lib/api";
import { codeSpans, listedPrice, movedWords, pairChangeWords, pairHeadline, pairResultWords, raceWords, titlesWords, turnName, variationWords, verdictParts } from "../src/lib/recording-pairs";
import { ComparedRunsPage } from "../src/pages/ComparedRuns";
import { alert, event, recording, step } from "./live-fixture";

// Small deltas in the shape `bluefire-lab compare` writes them, and the two real
// comparisons shipped with the app. The page draws what each one says; none of
// the small ones is a result.

// Two digests that differ in their first 12 digits, which the page shows.
const DIGEST_BEFORE = `7da98ea7a3c0${"0".repeat(52)}`;
const DIGEST_AFTER = `1cad187ffe68${"1".repeat(52)}`;
const PRICE = "price: published rules that alerted on ordinary activity: 2 before, 2 after; ordinary events: 8858 before, 8765 after";
const ID = "0000000000000001";

function side(id: string, started: string) {
  return { sha256: "a".repeat(64), id, run_url: `https://github.com/example/lab/actions/runs/${id === "run-before" ? 1 : 2}`, environment: "GitHub-hosted runner", commit: "c".repeat(40), started };
}

function same(id: string, title: string): DeltaStep {
  const outcomes = { happened: "took effect", recorded: "recorded", outcome: "seen", outcome_with_lab_rules: "seen" } as const;
  return { id, role: "test", title, technique: "T1082", paired_by: "id", before: outcomes, after: outcomes, changed: [], underneath: [], result: "same", verdict: "no change" };
}

const better: DeltaStep = {
  id: "2",
  role: "test",
  title: "Clear Bash history (echo)",
  technique: "T1070.003",
  paired_by: "id",
  before: { happened: "took effect", recorded: "no telemetry", outcome: "unseen", outcome_with_lab_rules: "unseen" },
  after: { happened: "took effect", recorded: "recorded", outcome: "seen", outcome_with_lab_rules: "seen" },
  changed: ["recorded", "outcome", "outcome_with_lab_rules"],
  underneath: ["recorded now: 1 event"],
  result: "better",
  verdict: `better: no telemetry to recorded by the sensors; unseen to seen by the published rules, on 1 of the 4 published procedures of T1070.003 in the list; ${PRICE}; one pair of runs`,
  price: PRICE,
  procedures: { better: 1, of: 4 },
};

function sensorDelta(): Delta {
  return {
    schema: "bluefire.delta/1",
    claim: "one pair of runs",
    before: side("run-before", "2026-11-23T17:25:50Z"),
    after: side("run-after", "2026-11-23T23:25:32Z"),
    declared_change: "sensors:auditd",
    comparable: true,
    refused_because: [],
    differences: [{ what: "sensors:auditd", before: DIGEST_BEFORE, after: DIGEST_AFTER }],
    same_in_both: ["atomic_commit", "kernels:target"],
    lab_code: { before: "c".repeat(40), after: "c".repeat(40), same: true },
    judged: ["recorded", "outcome", "outcome_with_lab_rules"],
    control: { fields: ["happened"], same: 2, of: 2, varied: [] },
    counts: { paired: 2, same: 1, better: 1, worse: 0, changed: 0, "not attributable": 0, "without cause": 0, "no verdict": 0, new: 0, gone: 0 },
    unexplained: [],
    steps: [same("1", "List OS Information"), better],
    new: [],
    gone: [],
    race: { why: "the rules ran after each run, so there is no race to compare" },
  };
}

// A limited verdict built here in the shape `bluefire-lab compare` writes for
// two runners that differed: the step credited by the change's own mark, its
// price not known, and one more step not attributable because of the runners.
// No CI run has yet written one by the lab's current rule for the mark.
const RUN = "https://github.com/example/lab/actions/runs/3";
const UNKNOWN_PRICE = "price not known: each run counted its ordinary activity on its own runner, and the two runners differed, so what differs between the counts is not the change's price (each run's own, published rules that alerted on ordinary activity: 2 before, 2 after; ordinary events: 8858 before, 8779 after)";
const RUNNERS_SAID = "the image of host `target`, the kernel of host `target`";
const CREDITS = "only a step that carries the change's own mark: every event the recordings hold of it is of an audit key whose every rule in that run watches a path that no rule of the other run, as written, could have recorded, and the other run holds nothing of it";
const RESTS = "it rests on 1 event of the audit key `shell-history`, whose every rule in the after run watches a path that no rule of the before run, as written, could have recorded, the only events either run holds of the step";
const HOME_RULE = "the before run's rule `-a always,exit -F path=/home/bluefire-lab -F perm=aw` watches `/home/bluefire-lab`, a folder above `/home/bluefire-lab/.bash_history`";

function limitedDelta(): Delta {
  const delta = sensorDelta();
  const marked: DeltaStep = {
    ...better,
    records: { sensor: "auditd", new: { count: 1, lines: ["openat: /home/bluefire-lab/.bash_history"] }, gone: { count: 0, lines: [] } },
    mark: { run: "after", keys: ["shell-history"], events: 1 },
    verdict: `better by the change's own mark, on two runners that differed: no telemetry to recorded by the sensors; unseen to seen by the published rules, on 1 of the 4 published procedures of T1070.003 in the list; ${UNKNOWN_PRICE}; ${RESTS}, on two runners that differed (${RUNNERS_SAID}); one pair of runs`,
    price: UNKNOWN_PRICE,
  };
  const unattributed: DeltaStep = {
    ...same("3", "Stop the audit daemon"),
    after: { happened: "took effect", recorded: "recorded", outcome: "alerted", outcome_with_lab_rules: "alerted" },
    changed: ["outcome", "outcome_with_lab_rules"],
    underneath: ["matches now: high: Audit daemon stopped"],
    result: "not attributable",
    verdict: `not attributable: the two runners differed (${RUNNERS_SAID}), and the step does not carry the change's own mark (both runs hold events of it), so this is run variation or the runners' difference; one pair of runs`,
  };
  return {
    ...delta,
    before: { ...delta.before, run_url: RUN, defense_commit: "d".repeat(40) },
    after: { ...delta.after, run_url: RUN, defense_commit: "c".repeat(40) },
    runners: 2,
    limit: { why: "the two runners differed", differences: ["images:target", "kernels:target"], credits: CREDITS, credited: 1, not_attributable: 1 },
    audit_keys: { only_before: {}, only_after: { "shell-history": { events: 1, steps: ["2"], mark: true } } },
    differences: [
      { what: "images:target", before: "ubuntu24 20261116.376.1", after: "ubuntu24 20261116.133.1" },
      { what: "kernels:target", before: "7.0.0-1017-azure", after: "7.0.0-1014-aws" },
      { what: "sensors:auditd", before: DIGEST_BEFORE, after: DIGEST_AFTER, declared: true },
    ],
    same_in_both: ["atomic_commit"],
    control: { fields: ["happened"], same: 3, of: 3, varied: [] },
    counts: { paired: 3, same: 1, better: 1, worse: 0, changed: 0, "not attributable": 1, "without cause": 0, "no verdict": 0, by_mark: 1, new: 0, gone: 0 },
    unexplained: ["3"],
    steps: [same("1", "List OS Information"), marked, unattributed],
  };
}

/** The same pair when the before run's rules also watch the history file's folder: the key gives no mark. */
function unmarkedDelta(): Delta {
  const delta = limitedDelta();
  const steps = delta.steps.map((item): DeltaStep => {
    if (item.id !== "2") return item;
    return { ...item, mark: undefined, price: undefined, procedures: undefined, result: "not attributable", verdict: `not attributable: the two runners differed (${RUNNERS_SAID}), the step does not carry the change's own mark (its events' audit key \`shell-history\` gives no mark: ${HOME_RULE}), so this is run variation or the runners' difference; one pair of runs` };
  });
  return {
    ...delta,
    limit: { why: "the two runners differed", differences: ["images:target", "kernels:target"], credits: CREDITS, credited: 0, not_attributable: 2 },
    audit_keys: { only_before: {}, only_after: { "shell-history": { events: 1, steps: ["2"], mark: false, no_mark: HOME_RULE } } },
    counts: { ...delta.counts, better: 0, "not attributable": 2, by_mark: 0 },
    unexplained: ["2", "3"],
    steps,
  };
}

function summaryOf(recordingId: string): RecordingSummary {
  return {
    id: recordingId,
    title: "Two published tests on one Linux host",
    kind: "test list",
    source: { engine: "bluefire-lab", environment: "GitHub-hosted runner", started: "2026-11-23T17:25:50Z", finished: "2026-11-23T17:36:23Z" },
    score: { steps: 2, took_effect: 2, alerted: 0, seen: 1, unseen: 1, stopped: 0 },
    counts: { steps: 2, events: 1, alerts: 0 },
    origin: { kind: "imported", note: "Imported. BlueFire cannot confirm that the steps ran." },
    running: false,
  };
}

function pairSummary(delta: Delta, id = ID): DeltaSummary {
  return {
    id, claim: delta.claim, declared_change: delta.declared_change, runners: delta.runners ?? null, one_run: delta.one_run === true, lab_rules: delta.lab_rules ?? null, comparable: delta.comparable, limit: delta.limit ?? null, refused_because: delta.refused_because, counts: delta.counts,
    moved: delta.steps.filter((item) => ["better", "worse", "changed"].includes(item.result)),
    before: delta.before, after: delta.after,
    recordings: { before: summaryOf(delta.before.id), after: summaryOf(delta.after.id) },
    origin: { kind: "imported", note: "Imported. BlueFire did not make the comparison." },
  };
}

function Address() {
  const location = useLocation();
  return <output aria-label="Address">{`${location.pathname}${location.search}`}</output>;
}

type Files = Map<string, unknown>;

/** Mounts the page of `delta`, with `loop` the comparisons the service lists, and the recording files by SHA-256. */
function mount(delta: Delta, { files, loop = [] as DeltaSummary[], id = ID }: { files?: Files; loop?: DeltaSummary[]; id?: string } = {}) {
  vi.spyOn(api, "recordingDelta").mockResolvedValue({ summary: pairSummary(delta, id), delta });
  vi.spyOn(api, "recordingDeltas").mockResolvedValue({ deltas: loop, unreadable_count: 0, omitted_count: 0 });
  const fetched = vi.spyOn(api, "recordingFile").mockImplementation(async (recordingId, sha256) => {
    const file = files?.get(sha256);
    if (file === undefined) throw new Error("not kept in this test");
    return { summary: summaryOf(recordingId), recording: file };
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={["/runs", `/runs/compared/${id}`]} initialIndex={1}>
    <Routes>
      <Route path="/runs/compared/:deltaId" element={<ComparedRunsPage />} />
      <Route path="*" element={<p>Elsewhere</p>} />
    </Routes>
    <Address />
  </MemoryRouter></QueryClientProvider>);
  return { user: userEvent.setup(), fetched };
}

async function openProof(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByText("How we know"));
  return screen.getByText("How we know").closest("details") as HTMLElement;
}

function shippedSensor() {
  const delta = readDelta(JSON.parse(sensorDeltaText));
  const files: Files = new Map([[delta.before.sha256, JSON.parse(sensorBeforeText) as unknown], [delta.after.sha256, JSON.parse(sensorAfterText) as unknown]]);
  return { delta, files };
}

function shippedRule() {
  const delta = readDelta(JSON.parse(ruleDeltaText));
  const files: Files = new Map([[delta.before.sha256, JSON.parse(ruleBaseText) as unknown], [delta.after.sha256, JSON.parse(ruleHeadText) as unknown]]);
  return { delta, files };
}

describe("the page of a change to the defense", () => {
  it("says first what the change did, from the delta alone, with the basis of the verdict in sight", async () => {
    mount(sensorDelta());
    expect(await screen.findByRole("heading", { level: 1, name: "One test that nobody saw is now seen." })).toBeVisible();
    const move = screen.getByRole("region", { name: "What the change did" });
    expect(within(move).getByText("unseen")).toBeVisible();
    expect(within(move).getByText("seen, no alert")).toBeVisible();
    expect(within(move).getByText("new auditd settings")).toBeVisible();
    // How the comparison was made, without opening anything, and the fair line does not say it again.
    expect(screen.getByText("It rests on one pair of runs: before 23 Nov 2026, after 23 Nov 2026.")).toBeVisible();
    expect(screen.getByText("Only the settings of sensor auditd differed.")).toBeVisible();
  }, 20_000);

  it("keeps how we know behind one line: the one change highlighted with both values, what was the same, the control and the lab's words", async () => {
    const { user } = mount(sensorDelta());
    await screen.findByRole("heading", { level: 1 });
    const proof = await openProof(user);
    const table = within(proof).getByRole("table", { name: "The two runs, before and after" });
    const [, declared] = within(table).getAllByRole("row");
    expect(declared).toHaveClass("is-declared");
    expect(declared).toHaveTextContent("the settings of sensor auditdthe one change");
    // A digest reads by its start, and whole on focus and to a screen reader.
    const digest = within(table).getByTitle(DIGEST_BEFORE);
    expect(digest).toHaveTextContent(DIGEST_BEFORE);
    expect(digest).toHaveAttribute("tabindex", "0");
    expect(within(table).getByText("7da98ea7a3c0…")).toBeInTheDocument();
    expect(within(proof).getByText(/The same steps, made with the same setup apart from this change\./)).toBeVisible();
    expect(within(proof).getByText("Recorded as the same in both: the tests' commit, the kernel of host target.")).toBeVisible();
    expect(within(proof).getByText("What happened, which this change cannot move: the same on 2 of 2 paired steps.")).toBeVisible();
    expect(within(proof).getByText("No race: the rules ran after each run, so there is no race to compare.")).toBeVisible();
    const words = within(proof).getByRole("region", { name: "Each step that differs, in the comparison's words" });
    expect(words).toHaveTextContent("on 1 of the 4 published procedures of T1070.003 in the list");
    expect(within(words).getByText(PRICE)).toHaveClass("cmp-price");
    expect(within(words).queryByText("List OS Information")).not.toBeInTheDocument();
  }, 20_000);

  it("never shows the gain without its price, and says the price is in the lab's words", async () => {
    mount(sensorDelta());
    const cost = await screen.findByRole("region", { name: "What it cost" });
    expect(cost).toHaveTextContent("Published rules that alerted on ordinary activity, outside every step.");
    expect(cost).toHaveTextContent(`In the lab's words: ${PRICE}`);
  }, 20_000);

  it("says a limited verdict near the top, why, and keeps the steps it does not credit apart", async () => {
    const { user } = mount(limitedDelta());
    expect(await screen.findByRole("heading", { level: 1, name: "One test that nobody saw is now seen." })).toBeVisible();
    const limit = screen.getByRole("region", { name: "A limited verdict: the two runners differed" });
    const rows = within(within(limit).getByRole("table", { name: "What differed between the two runners" })).getAllByRole("row");
    expect(rows.map((row) => row.textContent)).toEqual([
      "The runnersBeforeAfter",
      "the image of host targetubuntu24 20261116.376.1ubuntu24 20261116.133.1",
      "the kernel of host target7.0.0-1017-azure7.0.0-1014-aws",
    ]);
    expect(within(limit).getByText("1 step credited by the mark, 1 not attributable.")).toBeVisible();
    expect(screen.getByText("Limited")).toBeVisible();
    expect(screen.queryByText("The one change")).not.toBeInTheDocument();
    // The step not credited is listed apart, with no move.
    const move = screen.getByRole("region", { name: "What the change did" });
    expect(within(move).getByText("Also moved, not credited to the change")).toBeVisible();
    expect(within(move).getByRole("button", { name: /Stop the audit daemon/ })).toHaveTextContent("not attributable");
    expect(screen.getByRole("region", { name: "What it cost" })).toHaveTextContent("Not known");

    // Each run names the commit its rules and sensor settings came from.
    const proof = await openProof(user);
    expect(within(proof).getByRole("row", { name: /^Rules and sensor settings from commit/ })).toHaveTextContent("dddddddd" + "cccccccc (the lab's commit)");
    const words = within(proof).getByRole("region", { name: "Each step that differs, in the comparison's words" });
    expect(words).toHaveTextContent("better by the change's own mark, on two runners that differed: no telemetry to recorded by the sensors");
    expect(words).toHaveTextContent(RESTS.replaceAll("`", ""));
    expect(within(words).getByText(/^price not known: /)).toHaveTextContent(UNKNOWN_PRICE);
    expect(within(words).getAllByText("shell-history", { selector: "code" })[0]).toBeVisible();
  }, 20_000);

  it("says under a step that is not attributable why the key of its events gives no mark", async () => {
    const { user } = mount(unmarkedDelta());
    expect(await screen.findByRole("heading", { level: 1, name: "No step moved." })).toBeVisible();
    expect(screen.getByRole("region", { name: "What else moved" })).toHaveTextContent("None of 3 steps moved. 1 is the same, 2 differ without a verdict for the change.");
    const proof = await openProof(user);
    const why = within(proof).getByText(/^No mark of the change's own from the audit key/);
    expect(why).toHaveTextContent(`No mark of the change's own from the audit key shell-history, only in the after run's events: ${HOME_RULE.replaceAll("`", "")}.`);
    expect(screen.getAllByText(/^No mark of the change's own/)).toHaveLength(1);
  }, 20_000);

  it("says No verdict with every reason and every difference, and judges no step", async () => {
    const delta = sensorDelta();
    delta.comparable = false;
    delta.refused_because = ["also differed: the kernel of host `target` (7.0.0-1014-aws before, 7.0.0-1015-aws after)", "the steps of the two recordings ran in another order"];
    delta.differences = [{ what: "kernels:target", before: "7.0.0-1014-aws", after: "7.0.0-1015-aws" }, ...delta.differences];
    const [first] = delta.steps;
    if (!first) throw new Error("The delta should have a step.");
    delta.steps = [first, { ...better, result: "no verdict", verdict: "no verdict: the comparison is refused; one pair of runs", price: undefined, procedures: undefined }];
    delta.counts = { ...delta.counts, better: 0, "no verdict": 1 };
    mount(delta);

    expect(await screen.findByRole("heading", { level: 1, name: "No verdict." })).toBeVisible();
    const refused = screen.getByRole("region", { name: /^Declared change: the settings of sensor auditd\. The comparison was refused/ });
    const reasons = within(refused).getAllByRole("listitem");
    expect(reasons.map((item) => item.textContent)).toEqual(delta.refused_because.map((reason) => reason.replaceAll("`", "")));
    expect(within(reasons[0] ?? document.body).getByText("target").tagName).toBe("CODE");
    const rows = within(within(refused).getByRole("table", { name: "What differed between the two runs" })).getAllByRole("row");
    expect(rows.map((row) => row.textContent)).toEqual([
      "What differedBeforeAfter",
      "the kernel of host target7.0.0-1014-aws7.0.0-1015-aws",
      `the settings of sensor auditddeclared7da98ea7a3c0…${DIGEST_BEFORE}1cad187ffe68…${DIGEST_AFTER}`,
    ]);
    const move = screen.getByRole("region", { name: "What the change did" });
    expect(within(move).getByText("Steps that differ, not judged")).toBeVisible();
    expect(within(move).getByRole("button", { name: /Clear Bash history \(echo\)/ })).toHaveTextContent("not judged");
    expect(screen.getByRole("region", { name: "What it cost" })).toHaveTextContent("Not judged");
    expect(screen.getByRole("region", { name: "What else moved" })).toHaveTextContent("2 paired steps, none judged. 1 is the same, 1 differs without a verdict for the change.");
    expect(screen.queryByText("The one change")).not.toBeInTheDocument();
  }, 20_000);

  it("names a step that varied with nothing declared as run variation, never as an effect", async () => {
    const delta = sensorDelta();
    delta.declared_change = null;
    delta.differences = [];
    delta.judged = [];
    delta.lab_code = { before: "a".repeat(40), after: "b".repeat(40), same: false };
    delta.control = { fields: ["happened", "recorded", "outcome", "outcome_with_lab_rules"], same: 1, of: 2, varied: ["2"] };
    delta.unexplained = ["2"];
    delta.counts = { ...delta.counts, better: 0, "without cause": 1 };
    delta.steps = [same("1", "List OS Information"), { ...better, result: "without cause", verdict: "changed without a cause: run variation or a change of the lab's code, not an effect; one pair of runs", price: undefined, procedures: undefined }];
    const { user } = mount(delta);

    expect(await screen.findByRole("heading", { level: 1, name: "Nothing was declared as changed." })).toBeVisible();
    expect(within(screen.getByRole("region", { name: "What the change did" })).getByText("Changed without a cause")).toBeVisible();
    const proof = await openProof(user);
    expect(within(proof).getByText("What happened, whether a sensor recorded the step, the outcome by the published rules and the outcome with the lab's rules, every field, since nothing was declared: the same on 1 of 2 paired steps.")).toBeVisible();
    expect(within(proof).getByText("It varied on 1 step: that is run variation or a change of the lab's code, not an effect.")).toBeVisible();
    expect(within(proof).getByText(/The lab's code differed/)).toHaveTextContent("The lab's code differed (aaaaaaaa before, bbbbbbbb after).");
  }, 20_000);

  it("lists new and gone steps without counting them, and a race only when the delta has one with numbers", async () => {
    const delta = sensorDelta();
    delta.new = [{ id: "test:aaaa", role: "test", title: "A test only after", technique: "T1059" }];
    delta.gone = [{ id: "control:bbbb", role: "control", title: "A control only before", technique: "T1082" }];
    delta.race = { before: { goal_seconds: 63 }, after: { first_alert_seconds: 12.5, goal_seconds: 61 } };
    const { user } = mount(delta);
    await screen.findByRole("heading", { level: 1 });
    const proof = await openProof(user);
    expect(within(proof).getByText("New and gone, listed, not counted")).toBeVisible();
    expect(within(proof).getByText("Only in the after run").parentElement).toHaveTextContent("A test only after");
    expect(within(proof).getByText("Only in the before run").parentElement).toHaveTextContent("A control only before");
    expect(within(proof).getByText("Before: the goal after 63 s. After: first alert after 12.5 s, the goal after 61 s.")).toBeVisible();
  }, 20_000);

  it("draws the moved step on two stages from both recordings, and opens its whole detail from both, kept in the address", async () => {
    const delta = sensorDelta();
    const before = { ...recording({ steps: [step("1", 1, 2), step("2", 3, 4, { outcome: "unseen", visibility: { answer: "no telemetry", basis: "nothing of the test was recorded besides its launcher's start", events: 0 } })] }), id: "run-before" };
    const after = { ...recording({ steps: [step("1", 1, 2), step("2", 3, 4, { visibility: { answer: "telemetry only", basis: "one record", events: 1 }, first_event: "2026-01-01T10:00:03.500Z" })], events: [event("2-1", "2", 3.5)] }), id: "run-after" };
    // Both files have the same digest in this small delta: each side is read by its id here.
    const { user, fetched } = mount(delta);
    fetched.mockImplementation(async (id) => ({ summary: summaryOf(id), recording: id === "run-before" ? before : after }));

    const stages = await screen.findByRole("group", { name: "Clear Bash history (echo), before and after" });
    const beforeStage = await within(stages).findByRole("article", { name: /^Before/ });
    const afterStage = within(stages).getByRole("article", { name: /^After/ });
    expect(beforeStage).toHaveTextContent("Nothing of the test was recorded besides its launcher's start.");
    expect(afterStage).toHaveTextContent("Sysmon recorded 1 event. No rule matched it.");
    expect(within(beforeStage).getByRole("link", { name: "Play it in the run before" })).toHaveAttribute("href", `/runs/recorded/run-before/${"a".repeat(64)}?step=2&at=0&paused=1`);
    // A step still with no alert offers Fix this, in the run after.
    expect(within(afterStage).getByRole("link", { name: "Fix this" })).toHaveAttribute("href", `/runs/recorded/run-after/${"a".repeat(64)}?step=2&paused=1&mode=analyse&select=2`);

    await user.click(within(stages).getByRole("button", { name: "Every detail of this step, from both runs" }));
    const detail = await screen.findByRole("region", { name: "Clear Bash history (echo), every detail before and after" });
    expect(within(detail).getByRole("heading", { name: "Clear Bash history (echo), every detail before and after" })).toHaveFocus();
    expect(screen.getByLabelText("Address")).toHaveTextContent(`/runs/compared/${ID}?step=2&detail=1`);
    const articles = await within(detail).findAllByRole("article");
    expect(articles).toHaveLength(2);
    // The unseen test is told in its recording's own words.
    expect(articles[0]).toHaveTextContent("It took effect, and nothing of the test was recorded besides its launcher's start.");
    expect(articles[1]).toHaveTextContent("1 event recorded, no rule matched, none at alert level.");
    await user.click(within(detail).getByRole("button", { name: "Close the step's detail" }));
    expect(screen.queryByRole("region", { name: /every detail before and after/ })).not.toBeInTheDocument();
    expect(screen.getByLabelText("Address")).toHaveTextContent(`/runs/compared/${ID}?step=2`);
  }, 20_000);

  it("counts every test of the run after that raises no alert, seen or unseen, beside what its score gives", async () => {
    const delta = sensorDelta();
    const alerted = { happened: "took effect", recorded: "recorded", outcome: "alerted", outcome_with_lab_rules: "alerted" } as const;
    delta.steps = [same("1", "List OS Information"), { ...better, after: alerted }];
    const before = { ...recording({ steps: [step("1", 1, 2), step("2", 3, 4), step("3", 5, 6)] }), id: "run-before" };
    const after = { ...recording({ steps: [step("1", 1, 2, { outcome: "unseen" }), step("2", 3, 4, { outcome_with_lab_rules: "alerted" }), step("3", 5, 6)] }), id: "run-after" };
    after.score = { ...after.score, seen: 2, unseen: 1 };
    const { fetched } = mount(delta);
    fetched.mockImplementation(async (id) => ({ summary: summaryOf(id), recording: id === "run-before" ? before : after }));

    const next = await screen.findByRole("region", { name: "What comes next" });
    expect(await within(next).findByText("Two tests still raise no alert.")).toBeVisible();
    expect(next).toHaveTextContent("In the run after, with the lab's own rules too; one of them went unseen.");
    expect(next).toHaveTextContent("Its score counts only published rules: 3 with no alert.");
    expect(screen.getByRole("link", { name: /^Your next change\s*Two tests still raise no alert, with the lab's own rules too/ })).toBeVisible();
  }, 20_000);

  it("with no test left without an alert, speaks only of the tests the run can judge, and says how many had no effect", async () => {
    const delta = sensorDelta();
    const alerted = { happened: "took effect", recorded: "recorded", outcome: "alerted", outcome_with_lab_rules: "alerted" } as const;
    delta.steps = [same("1", "List OS Information"), { ...better, after: alerted }];
    const before = { ...recording({ steps: [step("1", 1, 2), step("2", 3, 4), step("3", 5, 6)] }), id: "run-before" };
    const noEffect = { happened: { answer: "not attempted", basis: "the test did not start" }, visibility: { answer: "no telemetry", basis: "no events", events: 0 }, outcome: "no effect" } as const;
    const after = { ...recording({ steps: [step("1", 1, 2, { outcome: "alerted" }), step("2", 3, 4, noEffect), step("3", 5, 6, noEffect)] }), id: "run-after" };
    after.score = { ...after.score, seen: 0, unseen: 0 };
    const { fetched } = mount(delta);
    fetched.mockImplementation(async (id) => ({ summary: summaryOf(id), recording: id === "run-before" ? before : after }));

    const next = await screen.findByRole("region", { name: "What comes next" });
    expect(await within(next).findByText("Every test the run can judge raises an alert or was stopped.")).toBeVisible();
    expect(next).toHaveTextContent("In the run after, with the lab's own rules too. Two tests had no effect, so the run says nothing about them.");
    expect(next).not.toHaveTextContent("Every test raises an alert or was stopped.");
    const card = screen.getByRole("link", { name: /^Your next change/ });
    expect(card).toHaveTextContent("Every test the run can judge raises an alert or was stopped");
    expect(card).toHaveTextContent("See the run after. Two tests had no effect, so the run says nothing about them");
    expect(card).not.toHaveTextContent("The tests with no alert");
  }, 20_000);

  it("shows the alert a changed rule no longer raises, with the rule and the event it matched, from the before recording alone", async () => {
    // One run read with two rule sets: the lab's rule was changed, not removed, and stopped alerting on step 2.
    const RULE = "Shell History File Truncated In Place";
    const seen = { happened: "took effect", recorded: "recorded", outcome: "seen", outcome_with_lab_rules: "seen" } as const;
    const lost: DeltaStep = {
      ...same("2", "Clear Bash history (echo)"),
      before: { ...seen, outcome_with_lab_rules: "alerted" },
      after: seen,
      changed: ["outcome_with_lab_rules"],
      underneath: [`matches no more: high: ${RULE}`],
      result: "worse",
      verdict: "worse: alerted to seen with the lab's rules; one run evaluated with two rule sets",
    };
    const base = sensorDelta();
    const delta: Delta = {
      ...base,
      claim: "one run evaluated with two rule sets",
      one_run: true,
      before: { ...side("run-once", "2026-11-24T12:42:13Z"), sha256: "b".repeat(64) },
      after: { ...side("run-once", "2026-11-24T12:42:13Z"), sha256: "c".repeat(64) },
      declared_change: "detectors:lab",
      lab_rules: [{ rule: "r1", title: RULE, change: "changed", before: { accepted: true, reason: "it alerted on every run" }, after: { accepted: true, reason: "it alerted on every run" } }],
      differences: [{ what: "detectors:lab", before: DIGEST_BEFORE, after: DIGEST_AFTER, declared: true }],
      judged: ["outcome_with_lab_rules"],
      counts: { ...base.counts, better: 0, worse: 1 },
      steps: [same("1", "List OS Information"), lost],
    };
    const truncate = { ...event("2-1", "2", 3.5), kind: "open for writing", text: "/home/bluefire-lab/.bash_history" };
    const ruleAlert = alert("a1", "2", 3.6, ["2-1"], { detector: "lab", rule: { id: "r1", title: RULE, level: "high", origin: "lab" } });
    const steps = [step("1", 1, 2, { title: "List OS Information" }), step("2", 3, 4, { title: "Clear Bash history (echo)", technique: { id: "T1070.003" } })];
    const before = { ...recording({ steps: steps.map((item) => (item.id === "2" ? { ...item, outcome_with_lab_rules: "alerted" as const } : item)), events: [truncate], alerts: [ruleAlert] }), id: "run-once" };
    const after = { ...recording({ steps, events: [truncate] }), id: "run-once" };
    mount(delta, { files: new Map<string, unknown>([["b".repeat(64), before], ["c".repeat(64), after]]) });

    // The rule that alerted before is drawn on the stage of the run before, which only the before recording holds.
    const stages = await screen.findByRole("group", { name: "Clear Bash history (echo), before and after" });
    const beforeStage = await within(stages).findByRole("article", { name: /^Before/ });
    expect(await within(beforeStage).findAllByText(RULE)).not.toHaveLength(0);
    expect(within(within(stages).getByRole("article", { name: /^After/ })).queryAllByText(RULE)).toHaveLength(0);
    // The event its alert rests on, said to be of the rules before.
    const difference = screen.getByRole("region", { name: "What made the difference" });
    const evidence = await within(difference).findByRole("article", { name: "What the alerts rest on" });
    expect(evidence).toHaveTextContent("Clear Bash history (echo)");
    expect(evidence).toHaveTextContent("with the rules before");
    expect(within(evidence).getByText("/home/bluefire-lab/.bash_history")).toBeVisible();
    expect(evidence).toHaveTextContent("alert · high");
  }, 20_000);
});

describe("the two comparisons shipped with the app", () => {
  it("reads the change of auditd's settings as the first turn of the loop: the test, the event it now records, and the next turn", async () => {
    const { delta, files } = shippedSensor();
    const rule = shippedRule();
    const loop = [pairSummary(delta, "0000000000000001"), pairSummary(rule.delta, "0000000000000002")];
    mount(delta, { files, loop, id: "0000000000000001" });
    expect(await screen.findByRole("heading", { level: 1, name: "One test that nobody saw is now seen." })).toBeVisible();
    const bar = screen.getByRole("navigation", { name: "The defender loop" });
    expect(within(bar).getByText("New auditd settings").closest("[aria-current]")).toHaveAttribute("aria-current", "page");
    expect(within(bar).getByRole("link", { name: /^Turn 2:\s*A new rule$/ })).toHaveAttribute("href", "/runs/compared/0000000000000002");
    expect(await screen.findByText(/a published test of Atomic Red Team for T1070\.003, Indicator Removal: Clear Command History\./)).toBeVisible();

    const stages = screen.getByRole("group", { name: "Clear Bash history (echo), before and after" });
    expect(await within(stages).findByRole("article", { name: /^Before auditd's earlier settings/ })).toHaveTextContent("Nothing of the test was recorded besides its launcher's start.");
    expect(within(stages).getByRole("article", { name: /^After auditd's new settings/ })).toHaveTextContent("auditd recorded 1 event. No alert: Use Of Hidden Paths Or Files matched at level low, below the alert level.");

    const cost = screen.getByRole("region", { name: "What it cost" });
    expect(cost).toHaveTextContent("2 before, 2 after");
    const others = screen.getByRole("region", { name: "What else moved" });
    expect(others).toHaveTextContent("One of 91 steps moved. 90 are the same.");
    const next = screen.getByRole("region", { name: "What comes next" });
    expect(next).toHaveTextContent("Seen, but nothing alerts on it.");
    expect(within(next).getByRole("link", { name: /^Next turn: A new rule/ })).toHaveAttribute("href", "/runs/compared/0000000000000002");

    const difference = screen.getByRole("region", { name: "What made the difference" });
    expect(within(difference).getByRole("heading", { name: "auditd now records Clear Bash history (echo)" })).toBeVisible();
    expect(within(difference).getByText("/home/bluefire-lab/.bash_history")).toBeVisible();
    expect(within(difference).getByText("only after")).toBeVisible();
    expect(difference).toHaveTextContent("It marks 9 events on 9 steps.");
    const ways = screen.getByRole("region", { name: "Every published test of T1070.003" });
    expect(ways).toHaveTextContent("Two of 4 raise an alert.");
    expect(within(ways).getAllByRole("listitem")).toHaveLength(4);
  }, 30_000);

  it("reads the new rule as one run evaluated twice: four rows, a row chooses the stages, the rule's text and the price not counted", async () => {
    const { delta, files } = shippedRule();
    const { user, fetched } = mount(delta, { files });
    expect(await screen.findByRole("heading", { level: 1, name: "Four steps that were seen with no alert now raise an alert." })).toBeVisible();
    expect(screen.getByText("One run, its telemetry read with two rule sets, 24 Nov 2026.")).toBeVisible();
    expect(screen.getByText("Only the rules of detector lab differed.")).toBeVisible();
    const move = screen.getByRole("region", { name: "What the change did" });
    const rows = within(move).getAllByRole("button", { pressed: false }).concat(within(move).getAllByRole("button", { pressed: true }));
    expect(rows).toHaveLength(4);
    const echoAgain = within(move).getAllByRole("button", { name: /Clear Bash history \(echo\)\s*with other arguments/ })[0];
    if (!echoAgain) throw new Error("The rerun of echo should be listed.");
    await user.click(echoAgain);
    expect(echoAgain).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByLabelText("Address")).toHaveTextContent("?step=variant%3Acbf506a5%3A27e9e5");
    const stages = screen.getByRole("group", { name: "Clear Bash history (echo), before and after" });
    expect(await within(stages).findByRole("article", { name: /^After with the new rule/ })).toHaveTextContent("The new rule raised an alert: Shell History File Truncated In Place (high).");

    expect(screen.getByRole("region", { name: "What it cost" })).toHaveTextContent("Not counted");
    const rule = screen.getByRole("article", { name: "Shell History File Truncated In Place" });
    expect(within(rule).getByLabelText("How each evaluation judged it")).toHaveTextContent("Beforenot there");
    const text = within(rule).getByLabelText("The text of the rule Shell History File Truncated In Place");
    expect(text.tagName).toBe("PRE");
    expect(text.textContent?.startsWith("title: Shell History File Truncated In Place\nid: 3d6f0b8e-5a41-4c7e-9b2d-7e1a6c40f5b9\n")).toBe(true);
    const difference = screen.getByRole("region", { name: "What made the difference" });
    expect(within(difference).getAllByText("/home/bluefire-lab/.bash_history")).toHaveLength(2);
    expect(within(difference).getByText("/home/bluefire-lab/.zsh_history")).toBeVisible();
    // Counted with the lab's own rules, beside the score the run after's page shows, which counts only published rules.
    expect(screen.getByRole("region", { name: "What comes next" })).toHaveTextContent("41 tests still raise no alert.In the run after, with the lab's own rules too; none went unseen.");
    expect(screen.getByRole("region", { name: "What comes next" })).toHaveTextContent("Its score counts only published rules: 57 with no alert.");
    // Each evaluation is read by its own file.
    expect(new Set(fetched.mock.calls.map(([, sha256]) => sha256))).toEqual(new Set([delta.before.sha256, delta.after.sha256]));
  }, 30_000);
});

describe("the words of a pair", () => {
  it("says what a change did, and names its turn, from the delta's own steps", () => {
    const rule = readDelta(JSON.parse(ruleDeltaText));
    const sensor = readDelta(JSON.parse(sensorDeltaText));
    const moved = (delta: Delta) => delta.steps.filter((item) => item.result === "better");
    expect(pairHeadline(rule, moved(rule))).toBe("Four steps that were seen with no alert now raise an alert.");
    expect(pairHeadline(sensor, moved(sensor))).toBe("One test that nobody saw is now seen.");
    expect(pairHeadline({ ...sensor, comparable: false }, [])).toBe("No verdict.");
    expect(turnName(rule)).toBe("A new rule");
    expect(turnName(sensor)).toBe("New auditd settings");
    expect(titlesWords(moved(rule))).toBe("Clear Bash history (echo) and (cat dev/null)");
    // A summary lists at most 20 moved steps: words for how they moved only when the list holds them all.
    expect(pairHeadline({ ...rule, counts: { ...rule.counts, better: 21, worse: 1 } }, moved(rule))).toBe("22 steps moved.");
    expect(listedPrice(moved(rule))?.words).toBe("Not counted: the lab keeps its own rules' matches on ordinary activity out of the recording");
    expect(listedPrice(moved(sensor))?.words).toBe("2 published rules alert on ordinary activity, before and after");
    expect(listedPrice([{ price: "price: published rules that alerted on ordinary activity: 1 before, 3 after; ordinary events: 8902 before, 8841 after" }])?.words).toBe("Published rules alerting on ordinary activity: 1 before, 3 after");
    expect(pairChangeWords(rule)).toBe("A new rule: Shell History File Truncated In Place");
    expect(movedWords({ declared_change: "sensors:auditd", moved: [better] })).toBe("Clear Bash history (echo): unseen to seen");
  });

  it("never draws a gain without its price, even when the verdict leaves it out", () => {
    expect(verdictParts(better)).toEqual({
      before: "no telemetry to recorded by the sensors; unseen to seen by the published rules, on 1 of the 4 published procedures of T1070.003 in the list; ",
      price: PRICE,
      after: "; one pair of runs",
    });
    expect(verdictParts({ ...better, verdict: "better: unseen to seen; one pair of runs" })).toEqual({ before: "unseen to seen; one pair of runs; ", price: PRICE, after: "" });
  });

  it("says a step that changed outside the order is changed, as the delta does", () => {
    const counts = { ...sensorDelta().counts, better: 0, changed: 1 };
    expect(pairResultWords({ comparable: true, refused_because: [], counts })).toBe("0 better, 0 worse, 1 changed, 0 changed without a cause, of 2 paired steps");
  });

  it("counts a limited verdict's credited steps by the mark, and its other steps as not attributable", () => {
    const delta = limitedDelta();
    expect(pairResultWords(delta)).toBe("Limited verdict, the runners differed: 1 better, 0 worse, 1 of them by the change's own mark alone; 1 not attributable; of 3 paired steps");
    expect(variationWords(delta)).toBe("run variation or the runners' difference");
  });

  it("draws a race with no numbers on either side as a quiet line", () => {
    expect(raceWords({ before: {}, after: {} })).toEqual({ quiet: true, text: "No race: neither run recorded a first alert or the goal." });
    expect(raceWords({ before: {}, after: { goal_seconds: 61 } })).toEqual({ quiet: false, text: "Before: not recorded. After: the goal after 61 s." });
  });

  it("cuts the lab's code spans out of its text", () => {
    expect(codeSpans("the kernel of host `target` (a before, b after)")).toEqual([
      { text: "the kernel of host ", code: false },
      { text: "target", code: true },
      { text: " (a before, b after)", code: false },
    ]);
  });
});
