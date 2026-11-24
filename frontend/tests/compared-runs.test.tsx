import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import ruleDeltaText from "../../bluefire/data/recordings/deltas/lab-rule-history-truncated.json?raw";
import ruleBaseText from "../../bluefire/data/recordings/lab-rule-history-truncated-base.json?raw";
import ruleHeadText from "../../bluefire/data/recordings/lab-rule-history-truncated-head.json?raw";
import { api, readDelta, type Delta, type DeltaStep, type DeltaSummary, type RecordingSummary } from "../src/lib/api";
import { codeSpans, movedWords, pairChangeWords, pairResultWords, raceWords, variationWords, verdictParts } from "../src/lib/recording-pairs";
import { ComparedRunsPage } from "../src/pages/ComparedRuns";
import { event, recording, step } from "./live-fixture";

// Small deltas in the shape `bluefire-lab compare` writes them. The page draws
// what each one says; none of these is a result.

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
const CREDITS = "only a step that carries the change's own mark: every event the recordings hold of it is of an audit key whose every rule in that run watches a path that no rule of the other run, as written, could have recorded (none there watches that path, any other path the event names, a folder above one or a path under one, and none without a path records the same kind of event, a program start being one kind and a read, a write or a change of attributes the other; paths are compared as written, so a second name that a link gives a file is not found out), and the other run holds nothing of it";
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
    // The run of a pair before the change loads its rules and sensor settings from the base commit.
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

/**
 * The same pair when the before run's rules also watch the history file's
 * folder: the key gives no mark, so the step is not attributable either.
 */
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

function pairSummary(delta: Delta): DeltaSummary {
  return {
    id: ID, claim: delta.claim, declared_change: delta.declared_change, runners: delta.runners ?? null, one_run: delta.one_run === true, lab_rules: delta.lab_rules ?? null, comparable: delta.comparable, limit: delta.limit ?? null, refused_because: delta.refused_because, counts: delta.counts,
    before: delta.before, after: delta.after,
    recordings: { before: summaryOf(delta.before.id), after: summaryOf(delta.after.id) },
    origin: { kind: "imported", note: "Imported. BlueFire did not make the comparison." },
  };
}

function Address() {
  const location = useLocation();
  return <output aria-label="Address">{`${location.pathname}${location.search}`}</output>;
}

function mount(delta: Delta) {
  vi.spyOn(api, "recordingDelta").mockResolvedValue({ summary: pairSummary(delta), delta });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={["/runs", `/runs/compared/${ID}`]} initialIndex={1}>
    <Routes>
      <Route path="/runs/compared/:deltaId" element={<ComparedRunsPage />} />
      <Route path="*" element={<p>Elsewhere</p>} />
    </Routes>
    <Address />
  </MemoryRouter></QueryClientProvider>);
  return userEvent.setup();
}

describe("the page of two compared runs", () => {
  it("names the one declared change with both values, and a moved step as one line with its price and procedures", async () => {
    mount(sensorDelta());
    expect(await screen.findByRole("heading", { level: 1, name: "One change: the settings of sensor auditd" })).toBeVisible();
    // A digest reads by its start, and whole on focus and to a screen reader.
    const digest = screen.getByTitle(DIGEST_BEFORE);
    expect(digest).toHaveTextContent(DIGEST_BEFORE);
    expect(digest).toHaveAttribute("tabindex", "0");
    expect(screen.getByText("7da98ea7a3c0…")).toBeInTheDocument();
    expect(screen.getByText("The same steps, made with the same setup apart from this change.")).toBeVisible();
    expect(screen.getByText("the kernel of host target")).toBeVisible();

    const moved = screen.getByRole("region", { name: /^What the change moved/ });
    const [line] = within(moved).getAllByRole("listitem").filter((item) => item.classList.contains("cmp-step"));
    if (!line) throw new Error("The moved step should be listed.");
    expect(within(line).getByRole("button", { name: /Clear Bash history \(echo\)/ })).toHaveAttribute("aria-expanded", "false");
    expect(line).toHaveTextContent("Before unseen, after seen, no alert");
    expect(line).toHaveTextContent("on 1 of the 4 published procedures of T1070.003 in the list");
    expect(within(line).getByText(PRICE)).toHaveClass("cmp-price");
    expect(within(line).getByText("recorded now: 1 event")).toBeVisible();
    // The step that did not move is not among them.
    expect(within(moved).queryByText("List OS Information")).not.toBeInTheDocument();

    const control = screen.getByRole("region", { name: /^The control/ });
    expect(within(control).getByText("What happened, which this change cannot move: the same on 2 of 2 paired steps.")).toBeVisible();
    expect(screen.getByText("No race: the rules ran after each run, so there is no race to compare.")).toBeVisible();
    expect(screen.getByText("All of this rests on one pair of runs.")).toBeVisible();
  });

  it("says that two runs side by side on alike runners had the same setup apart from the change", async () => {
    mount({ ...sensorDelta(), runners: 2, limit: null });
    expect(await screen.findByText("The same steps, made with the same setup apart from this change, side by side in one CI run, each on a fresh runner of its own.")).toBeVisible();
    expect(screen.queryByRole("region", { name: /^A limited verdict/ })).not.toBeInTheDocument();
    expect(screen.queryByText(/limited verdict/i)).not.toBeInTheDocument();
  });

  it("says a limited verdict at the top, why, in what the runners differed, and what alone is credited", async () => {
    mount(limitedDelta());
    // Not "One change": the runners differed too.
    expect(await screen.findByRole("heading", { level: 1, name: "Declared change: the settings of sensor auditd" })).toBeVisible();
    expect(screen.queryByText(/One change/)).not.toBeInTheDocument();
    expect(screen.queryByText(/made with the same setup apart from this change/)).not.toBeInTheDocument();
    expect(screen.getByText("The same steps, made side by side in one CI run on two fresh runners.")).toBeVisible();
    const limit = screen.getByRole("region", { name: "A limited verdict: the two runners differed" });
    // It comes before the steps, inside the claim.
    const moved = screen.getByRole("region", { name: /^What the change moved/ });
    expect(limit.compareDocumentPosition(moved) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    const rows = within(within(limit).getByRole("table", { name: "What differed between the two runners" })).getAllByRole("row");
    expect(rows.map((row) => row.textContent)).toEqual([
      "The runnersBeforeAfter",
      "the image of host targetubuntu24 20261116.376.1ubuntu24 20261116.133.1",
      "the kernel of host target7.0.0-1017-azure7.0.0-1014-aws",
    ]);
    expect(within(limit).getByText(/^Credited: only a step that carries the change's own mark/).parentElement).toHaveTextContent(`Credited: ${CREDITS}.`);
    expect(within(limit).getByText("1 step credited by the mark, 1 not attributable.")).toBeVisible();

    // Each run names the commit its rules and sensor settings came from, never one relative to the other.
    const before = screen.getByRole("article", { name: "Before" });
    const after = screen.getByRole("article", { name: "After" });
    expect(before).toHaveTextContent("Rules and sensor settingsfrom commit dddddddd");
    expect(after).toHaveTextContent("Rules and sensor settingsfrom commit cccccccc (the lab's commit)");
    expect(screen.queryByText(/the same commit/)).not.toBeInTheDocument();
  });

  it("draws a step credited by the mark as that, with the mark, its records and a price that is not known", async () => {
    mount(limitedDelta());
    const moved = await screen.findByRole("region", { name: /^What the change moved/ });
    expect(moved).toHaveTextContent("each credited by the change's own mark only");
    const [line] = within(moved).getAllByRole("listitem").filter((item) => item.classList.contains("cmp-step"));
    if (!line) throw new Error("The credited step should be listed.");
    expect(within(line).getByText("better")).toHaveClass("cmp-result");
    expect(line).toHaveTextContent("better by the change's own mark, on two runners that differed: no telemetry to recorded by the sensors");
    // The mark is said once, in the delta's own verdict.
    expect(line).toHaveTextContent(RESTS.replaceAll("`", ""));
    expect(line.textContent?.match(/it rests on/g)).toHaveLength(1);
    expect(line).toHaveTextContent("What sensor auditd recorded of it in one run onlyOnly in the after run, 1 eventopenat: /home/bluefire-lab/.bash_history");
    // A key that can carry the mark gives no line of why it carries none.
    expect(line).not.toHaveTextContent(/No mark of the change's own/);
    const price = within(line).getByText(/^price not known: /);
    expect(price).toHaveClass("cmp-price");
    expect(price).toHaveTextContent(UNKNOWN_PRICE);
    expect(line).not.toHaveTextContent(/price: published/);
    // The lab's code spans read as code.
    expect(within(line).getByText("shell-history", { selector: "code" })).toBeVisible();
  });

  it("draws a step that is not attributable on two runners that differed as the runners', not as run variation alone", async () => {
    mount(limitedDelta());
    const control = await screen.findByRole("region", { name: /^The control/ });
    expect(within(control).getByRole("heading", { name: /^Not attributable to the change/ })).toHaveTextContent("the two runners differed, and could have moved these");
    expect(within(control).queryByRole("heading", { name: "Changed without a cause" })).not.toBeInTheDocument();
    const [line] = within(control).getAllByRole("listitem").filter((item) => item.classList.contains("cmp-step"));
    expect(line).toHaveTextContent("not attributable: the two runners differed (the image of host target, the kernel of host target), and the step does not carry the change's own mark");
    // Both values side by side, flat: not a move from one to the other.
    expect(line).toHaveTextContent("Beforeseen, no alertAfteralerted");
    const moved = screen.getByRole("region", { name: /^What the change moved/ });
    expect(within(moved).queryByText("Stop the audit daemon")).not.toBeInTheDocument();
    // Its events are of no key only one run's events carry, so no key's reason is told under it.
    expect(line).not.toHaveTextContent(/No mark of the change's own/);
  });

  it("says under a step that is not attributable why the key of its events gives no mark", async () => {
    mount(unmarkedDelta());
    const control = await screen.findByRole("region", { name: /^The control/ });
    const lines = within(control).getAllByRole("listitem").filter((item) => item.classList.contains("cmp-step"));
    const history = lines.find((item) => item.textContent?.includes("Clear Bash history (echo)"));
    if (!history) throw new Error("The step whose key gives no mark should be listed as not attributable.");
    const why = within(history).getByText(/^No mark of the change's own from the audit key/);
    expect(why).toHaveTextContent(`No mark of the change's own from the audit key shell-history, only in the after run's events: ${HOME_RULE.replaceAll("`", "")}.`);
    expect(within(why).getByText("/home/bluefire-lab", { selector: "code" })).toBeVisible();
    // Said once under its own step, and not under the step whose events are of no such key.
    expect(screen.getAllByText(/^No mark of the change's own/)).toHaveLength(1);
    // Nothing is credited, so nothing moved.
    const moved = screen.getByRole("region", { name: /^What the change moved/ });
    expect(within(moved).getByText("No step moved in what this change can move.")).toBeVisible();
  });

  it("says No verdict with every reason and every difference, as prominently as a verdict", async () => {
    const delta = sensorDelta();
    delta.comparable = false;
    delta.refused_because = ["also differed: the kernel of host `target` (7.0.0-1014-aws before, 7.0.0-1015-aws after)", "the steps of the two recordings ran in another order"];
    delta.differences = [{ what: "kernels:target", before: "7.0.0-1014-aws", after: "7.0.0-1015-aws" }, ...delta.differences];
    delta.same_in_both = ["atomic_commit"];
    const [first] = delta.steps;
    if (!first) throw new Error("The delta should have a step.");
    delta.steps = [first, { ...better, result: "no verdict", verdict: "no verdict: the comparison is refused; one pair of runs", price: undefined, procedures: undefined }];
    mount(delta);

    expect(await screen.findByRole("heading", { level: 1, name: "No verdict" })).toBeVisible();
    // Every reason, with the lab's code spans drawn as code rather than as backticks.
    const reasons = screen.getAllByRole("listitem").filter((item) => item.closest(".cmp-reasons"));
    expect(reasons.map((item) => item.textContent)).toEqual(delta.refused_because.map((reason) => reason.replaceAll("`", "")));
    expect(within(reasons[0] ?? document.body).getByText("target").tagName).toBe("CODE");
    const table = screen.getByRole("table", { name: "What differed between the two runs" });
    const rows = within(table).getAllByRole("row");
    expect(rows.map((row) => row.textContent)).toEqual([
      "What differedBeforeAfter",
      "the kernel of host target7.0.0-1014-aws7.0.0-1015-aws",
      `the settings of sensor auditddeclared7da98ea7a3c0…${DIGEST_BEFORE}1cad187ffe68…${DIGEST_AFTER}`,
    ]);
    const moved = screen.getByRole("region", { name: /^Steps that differ, with no verdict/ });
    const [line] = within(moved).getAllByRole("listitem").filter((item) => item.classList.contains("cmp-step"));
    // Both values side by side, led by its result: not a move from one to the other.
    expect(line).toHaveTextContent("BeforeunseenAfterseen, no alert");
    expect(line).not.toHaveTextContent("Before unseen, after");
    expect(line).toHaveTextContent("no verdict: the comparison is refused; one pair of runs");
    expect(screen.queryByText(/One change/)).not.toBeInTheDocument();
  });

  it("names a step that varied in the control as run variation, never as an effect", async () => {
    const delta = sensorDelta();
    delta.declared_change = null;
    delta.differences = [];
    delta.judged = [];
    delta.lab_code = { before: "a".repeat(40), after: "b".repeat(40), same: false };
    delta.control = { fields: ["happened", "recorded", "outcome", "outcome_with_lab_rules"], same: 1, of: 2, varied: ["2"] };
    delta.unexplained = ["2"];
    delta.steps = [same("1", "List OS Information"), { ...better, result: "without cause", verdict: "changed without a cause: run variation or a change of the lab's code, not an effect; one pair of runs", price: undefined, procedures: undefined }];
    mount(delta);

    expect(await screen.findByRole("heading", { level: 1, name: "Nothing declared as changed" })).toBeVisible();
    expect(screen.getByRole("heading", { name: /^Steps credited to a change/ })).toBeVisible();
    expect(screen.getByText("Nothing was declared as changed, so no step is credited to a change.")).toBeVisible();
    const control = screen.getByRole("region", { name: /^The control/ });
    expect(within(control).getByText("What happened, whether a sensor recorded the step, the outcome by the published rules and the outcome with the lab's rules, every field, since nothing was declared: the same on 1 of 2 paired steps.")).toBeVisible();
    expect(within(control).getByText("It varied on 1 step: that is run variation or a change of the lab's code, not an effect.")).toBeVisible();
    expect(within(control).getByRole("heading", { name: "Changed without a cause" })).toBeVisible();
    const [line] = within(control).getAllByRole("listitem").filter((item) => item.classList.contains("cmp-step"));
    expect(line).toHaveTextContent("changed without a cause: run variation or a change of the lab's code, not an effect; one pair of runs");
    expect(line).toHaveTextContent("BeforeunseenAfterseen, no alert");
    expect(screen.getByText(/The lab's code differed/)).toHaveTextContent("The lab's code differed (aaaaaaaa before, bbbbbbbb after).");
  });

  it("lists new and gone steps without counting them, and a race only when the delta has one with numbers", async () => {
    const delta = sensorDelta();
    delta.new = [{ id: "test:aaaa", role: "test", title: "A test only after", technique: "T1059" }];
    delta.gone = [{ id: "control:bbbb", role: "control", title: "A control only before", technique: "T1082" }];
    delta.race = { before: { goal_seconds: 63 }, after: { first_alert_seconds: 12.5, goal_seconds: 61 } };
    mount(delta);

    const control = await screen.findByRole("region", { name: /^The control/ });
    expect(within(control).getByRole("heading", { name: /^New and gone/ })).toHaveTextContent("listed, not counted");
    expect(within(control).getByText("Only in the after run").parentElement).toHaveTextContent("A test only after");
    expect(within(control).getByText("Only in the before run").parentElement).toHaveTextContent("A control only before");
    expect(screen.getByText("Before: the goal after 63 s. After: first alert after 12.5 s, the goal after 61 s.")).toBeVisible();
    expect(screen.queryByText(/^No race/)).not.toBeInTheDocument();
  });

  it("opens a step's detail for both runs side by side and keeps it in the address", async () => {
    const delta = sensorDelta();
    const before = { ...recording({ steps: [step("1", 1, 2), step("2", 3, 4, { outcome: "unseen", visibility: { answer: "no telemetry", basis: "nothing recorded", events: 0 } })] }), id: "run-before" };
    const after = { ...recording({ steps: [step("1", 1, 2), step("2", 3, 4, { visibility: { answer: "telemetry only", basis: "one record", events: 1 }, first_event: "2026-01-01T10:00:03.500Z" })], events: [event("2-1", "2", 3.5)] }), id: "run-after" };
    // Each side is asked for by its file, as the delta names it: one run evaluated twice has one id for both.
    const recordingFetch = vi.spyOn(api, "recordingFile").mockImplementation(async (id) => ({ summary: summaryOf(id), recording: id === "run-before" ? before : after }));
    const user = mount(delta);

    await user.click(await screen.findByRole("button", { name: /Clear Bash history \(echo\)/ }));
    const detail = await screen.findByRole("region", { name: "Clear Bash history (echo), before and after" });
    expect(within(detail).getByRole("heading", { name: "Clear Bash history (echo), before and after" })).toHaveFocus();
    expect(screen.getByLabelText("Address")).toHaveTextContent(`/runs/compared/${ID}?step=2`);
    const articles = await within(detail).findAllByRole("article");
    expect(articles).toHaveLength(2);
    expect(articles[0]).toHaveTextContent("It took effect, and no sensor recorded it.");
    expect(articles[1]).toHaveTextContent("1 event recorded, no rule matched, none at alert level.");
    expect(recordingFetch.mock.calls.map(([id]) => id).sort()).toEqual(["run-after", "run-before"]);
    expect(recordingFetch.mock.calls.every(([, sha256]) => sha256 === "a".repeat(64))).toBe(true);
    // One way to close the pair's detail, and none of the live view's playback actions.
    expect(within(detail).queryByRole("button", { name: /Whole run|Watch from here/ })).not.toBeInTheDocument();

    await user.click(within(detail).getByRole("button", { name: "Close the step's detail" }));
    expect(screen.queryByRole("region", { name: "Clear Bash history (echo), before and after" })).not.toBeInTheDocument();
    expect(screen.getByLabelText("Address")).toHaveTextContent(`/runs/compared/${ID}`);

    await user.click(screen.getByRole("button", { name: /Clear Bash history \(echo\)/ }));
    expect(await screen.findByRole("region", { name: "Clear Bash history (echo), before and after" })).toBeVisible();
    await user.click(screen.getByRole("button", { name: /Clear Bash history \(echo\)/ }));
    expect(screen.queryByRole("region", { name: "Clear Bash history (echo), before and after" })).not.toBeInTheDocument();
  });
});

describe("the page of one run evaluated with two rule sets", () => {
  // The real files of CI run 45395673682, as the app ships them.
  function shipped() {
    const delta = readDelta(JSON.parse(ruleDeltaText));
    const files = new Map([[delta.before.sha256, JSON.parse(ruleBaseText) as unknown], [delta.after.sha256, JSON.parse(ruleHeadText) as unknown]]);
    const fetched = vi.spyOn(api, "recordingFile").mockImplementation(async (id, sha256) => ({ summary: summaryOf(id), recording: files.get(sha256) }));
    return { delta, fetched };
  }

  it("says at the top that it is one run, not a pair, and shows the rule, how each evaluation judged it and its text", async () => {
    const { delta, fetched } = shipped();
    mount(delta);
    expect(await screen.findByRole("heading", { level: 1, name: "A new rule: Shell History File Truncated In Place" })).toBeVisible();
    expect(screen.getByText("one run evaluated with two rule sets", { selector: ".cmp-kicker span" })).toBeVisible();
    expect(screen.getByText(/^One run, evaluated twice: the list ran once, on one runner/)).toHaveTextContent("Not a pair of runs, so no second runner and no run variation");
    // No two runs side by side: one run, with the commit each evaluation took the lab's rules from.
    expect(screen.queryByRole("region", { name: "The two runs" })).not.toBeInTheDocument();
    const run = screen.getByRole("region", { name: "The run" });
    expect(run).toHaveTextContent("before from commit 3d8f3610; after from commit e809f685");
    expect(within(run).getByRole("link", { name: /Open with the rules after/ })).toHaveAttribute("href", `/runs/recorded/b2666c50/${delta.after.sha256}`);

    const rule = screen.getByRole("article", { name: "Shell History File Truncated In Place" });
    expect(within(rule).getByText("lab/rules/linux/auditd/lnx_auditd_history_file_truncated_in_place.yml")).toBeVisible();
    const judged = within(rule).getByLabelText("How each evaluation judged it");
    expect(judged).toHaveTextContent("Beforenot there");
    expect(judged).toHaveTextContent("Afteraccepted" + "it alerted on every run with changed input arguments and on no ordinary activity");
    // The rule's text as the after recording carries it, as text that can be selected.
    const text = await within(rule).findByLabelText("The text of the rule Shell History File Truncated In Place");
    expect(text.tagName).toBe("PRE");
    expect(text.textContent?.startsWith("title: Shell History File Truncated In Place\nid: 3d6f0b8e-5a41-4c7e-9b2d-7e1a6c40f5b9\n")).toBe(true);
    expect(text).toHaveTextContent("condition: selection_watch and (selection_openat or selection_open or selection_creat)");
    // Only the evaluation that has the rule is loaded for it.
    expect(fetched.mock.calls.map(([, sha256]) => sha256)).toEqual([delta.after.sha256]);
  });

  it("lists the steps the rule moved, seen to alerted, each with the event its alert rests on, and the price once in the lab's words", async () => {
    const { delta } = shipped();
    mount(delta);
    const moved = await screen.findByRole("region", { name: /^What the change moved/ });
    const lines = within(moved).getAllByRole("listitem").filter((item) => item.classList.contains("cmp-step"));
    expect(lines).toHaveLength(4);
    const [first] = lines;
    if (!first) throw new Error("A moved step should be listed.");
    expect(first).toHaveTextContent("Before seen, no alert, after alerted");
    expect(first).toHaveTextContent("with the lab's rules");
    expect(await within(first).findByText("auditd openat: /home/bluefire-lab/.bash_history")).toBeVisible();
    expect(first).toHaveTextContent('by sh -c echo "" > ~/.bash_history');
    expect(first).toHaveTextContent("audit key shell-history");
    // Each step carries the price's lead; the price is said whole once, under the steps.
    expect(within(first).getByText("price not counted: the lab's rules that matched ordinary activity are left out of the recording before it is written")).toHaveClass("cmp-price");
    const price = within(moved).getByRole("heading", { name: /^The price/ }).parentElement;
    expect(price).toHaveTextContent("(before: The run accepted 8 of the 9 rules written in this repository.");
    expect(price).toHaveTextContent("after: The run accepted 9 of the 10 rules written in this repository.");
    expect(screen.getByText("All of this rests on one run evaluated with two rule sets.")).toBeVisible();
  });
});

describe("the words of a pair", () => {
  it("says what a list's pair changed and moved, from its summary", () => {
    const delta = readDelta(JSON.parse(ruleDeltaText));
    const moved = delta.steps.filter((item) => item.result === "better");
    expect(pairChangeWords(delta)).toBe("A new rule: Shell History File Truncated In Place");
    expect(movedWords({ declared_change: delta.declared_change, moved })).toBe("Clear Bash history (echo) and Clear Bash history (cat dev/null), each also with changed input arguments: seen to alerted with the lab's rules");
    expect(movedWords({ declared_change: "sensors:auditd", moved: [better] })).toBe("Clear Bash history (echo): unseen to seen");
    expect(movedWords({ declared_change: "sensors:auditd", moved: [] })).toBeNull();
    expect(pairChangeWords(sensorDelta())).toBe("The settings of sensor auditd");
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

  it("leaves the mark's lead to the step's tags, and keeps the rest of the verdict in the delta's words", () => {
    const [, marked] = limitedDelta().steps;
    if (!marked) throw new Error("The limited delta should have a credited step.");
    const parts = verdictParts(marked);
    expect(parts.before).toBe("no telemetry to recorded by the sensors; unseen to seen by the published rules, on 1 of the 4 published procedures of T1070.003 in the list; ");
    expect(parts.price).toBe(UNKNOWN_PRICE);
    expect(parts.after.startsWith("; it rests on 1 event of the audit key `shell-history`")).toBe(true);
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
