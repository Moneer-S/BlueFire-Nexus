import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { api, type Delta, type DeltaStep, type DeltaSummary, type RecordingSummary } from "../src/lib/api";
import { codeSpans, pairResultWords, raceWords, verdictParts } from "../src/lib/recording-pairs";
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
    id: ID, claim: delta.claim, declared_change: delta.declared_change, comparable: delta.comparable, refused_because: delta.refused_because, counts: delta.counts,
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
    const recordingFetch = vi.spyOn(api, "recording").mockImplementation(async (id) => ({ summary: summaryOf(id), recording: id === "run-before" ? before : after }));
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

describe("the words of a pair", () => {
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
