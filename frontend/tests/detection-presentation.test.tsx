import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog, demoRuns } from "../src/lib/demo";
import { detectionDraftIdentity } from "../src/state/useDetectionDraft";
import { DetectionLabPage } from "../src/pages/DetectionLab";
import type { DetectionResource, RunRecord } from "../src/types";

const id = `detection-${"a".repeat(20)}`;
const childId = `detection-${"b".repeat(20)}`;
const definition = `sha256:${"c".repeat(64)}`;
const query = `sha256:${"d".repeat(64)}`;
const source = "SELECT fixture_id FROM logs WHERE observation_kind = 'filesystem'";
const workspaceTabKey = `bluefire.detection-draft.v1:${detectionDraftIdentity({ namespace: "registry-tab", id })}`;
const original: DetectionResource = { kind: "detections", id, status: "parsed", digest: "sha256:resource", created_at: "2026-09-09", updated_at: "2026-09-09", document: {
  candidate_id: id, revision_root_id: id, revision: 1, revision_kind: "origin", title: "Collection rule", behavior_id: "sandbox.collection.stage.v1", target_language: "sqlite", state: "parsed", rule_source: source, selection: {}, logsource: {}, definition_digest: definition,
  parser_backend: { name: "SQLite bounded executor", version: "3.46" }, validation: { query_sha256: query, converted_query: source, source_rule_executed: true, execution_backend: "SQLite", execution_backend_version: "3.46", last_execution: { fixture_ids: ["observed-one", "observed-two"], matched_fixture_ids: ["observed-two"] }, unsupported_fields: [] },
} };
function Location() { return <output data-testid="location">{useLocation().search}</output>; }
function setup(candidates = [structuredClone(original)], ready = true, sourceRun?: RunRecord, additionalRuns: RunRecord[] = []) {
  const runs = sourceRun ? [sourceRun, ...additionalRuns] : [];
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  vi.spyOn(api, "runs").mockResolvedValue({ schema_version: "v1", unavailable_run_count: 0, runs });
  if (sourceRun) vi.spyOn(api, "runDetail").mockImplementation(async runId => {
    const run = runs.find(item => item.run_id === runId);
    if (!run) throw new Error("The requested test run is unavailable.");
    return run;
  });
  const detectionList = vi.spyOn(api, "detections").mockResolvedValue({ schema_version: "v1", candidates });
  vi.spyOn(api, "resources").mockResolvedValue({ schema_version: "v1", kind: "research-sources", resources: [] });
  vi.spyOn(api, "detectionHealth").mockResolvedValue({ schema_version: "v1", ready, persistence_ready: true, candidate_resources: candidates.length, invalid_candidate_resources: 0, languages: { sqlite: { ready, authoritative: true, backend: "SQLite bounded executor" }, sigma: { ready, authoritative: true, backend: "pySigma" } }, limits: { source_bytes: 262144, fixture_bytes: 1048576, fixtures_per_action: 128, evidence_per_action: 256, notes_per_action: 64 } });
  vi.spyOn(api, "detectionRunEvaluations").mockResolvedValue({ evaluations: [] });
  const action = vi.spyOn(api, "detectionAction");
  const revise = vi.spyOn(api, "reviseDetectionSource");
  const evaluate = vi.spyOn(api, "evaluateDetectionRun");
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const route = sourceRun ? `/detection-lab?run=${encodeURIComponent(sourceRun.run_id)}` : `/detection-lab?candidate=${id}&candidate_scope=registry`;
  const rendered = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[route]}><DetectionLabPage/><Location/></MemoryRouter></QueryClientProvider>);
  return { ...rendered, user: userEvent.setup(), action, revise, evaluate, detectionList, client };
}

it("names SQLite consistently and discloses identities without hiding query execution or results", async () => {
  const { user, action, revise, evaluate } = setup();
  expect(await screen.findByRole("textbox", { name: /^SQLite source/ })).toHaveValue(source);
  expect(screen.getByRole("complementary", { name: "Selected detector context" })).toHaveTextContent("No source run selected");
  expect(screen.getByText(/Available evidence does not mean this detector has been evaluated/)).toBeVisible();
  expect(within(screen.getByRole("textbox", { name: /^SQLite source/ }).closest(".candidate-workspace") as HTMLElement).getByText("Evaluator: SQLite", { exact: true })).toBeVisible();
  expect(screen.getByText("Source query executed")).toBeVisible();
  expect(screen.getByText("Matched records")).toBeVisible();
  expect(screen.getByText("observed-two", { exact: true })).toBeVisible();
  expect(screen.getByText(definition)).not.toBeVisible();
  expect(screen.getByText(query)).not.toBeVisible();
  const details = screen.getByText("Rule identity and parser details");
  await user.click(details);
  expect(screen.getByText(definition)).toBeVisible();
  expect(screen.getAllByText(id, { exact: true, selector: "code" }).every(element => element.closest("details")?.open)).toBe(true);
  await user.click(screen.getByText("Query source and identity"));
  expect(screen.getByText(query)).toBeVisible();
  expect(action).not.toHaveBeenCalled(); expect(revise).not.toHaveBeenCalled(); expect(evaluate).not.toHaveBeenCalled();
});

it("keeps source context separate and routes rail actions through the existing review tabs", async () => {
  const { user, action, revise, evaluate } = setup();
  await screen.findByRole("textbox", { name: /^SQLite source/ });
  const rail = screen.getByRole("complementary", { name: "Selected detector context" });
  expect(within(rail).getByText("Parser and fixture checks are lifecycle evidence. Retained run evaluations show their own engine execution and measured result.")).toBeVisible();
  await user.click(within(rail).getByRole("button", { name: "Open run evaluations" }));
  expect(screen.getByRole("tab", { name: "Run evaluations" })).toHaveAttribute("aria-selected", "true");
  expect(await screen.findByText("No retained run evaluations")).toBeVisible();
  await user.click(within(rail).getByRole("button", { name: "Review rule revisions" }));
  expect(screen.getByRole("heading", { name: "Compare two revisions" })).toBeVisible();
  expect(action).not.toHaveBeenCalled(); expect(revise).not.toHaveBeenCalled(); expect(evaluate).not.toHaveBeenCalled();
});

it("keeps language choices concise and reports Sigma conversion and unavailable evaluation separately", async () => {
  const candidate = structuredClone(original);
  candidate.document.target_language = "sigma";
  const { user, action, revise, evaluate } = setup([candidate], false);
  expect(await screen.findByRole("textbox", { name: /^Sigma source/ })).toBeVisible();
  expect(screen.getByText(/Sigma rules are converted with pySigma/)).toHaveTextContent("Unavailable");
  expect(screen.getByText("Query backend unavailable")).toBeVisible();
  await user.click(screen.getByText("New rule", { exact: true }));
  const language = screen.getByRole("combobox", { name: "Target language" });
  expect(within(language).getByRole("option", { name: "SQLite" })).toHaveValue("sqlite");
  expect(within(language).getByRole("option", { name: "Sigma" })).toHaveValue("sigma");
  await user.selectOptions(language, "sigma");
  expect(language).toHaveValue("sigma");
  expect(action).not.toHaveBeenCalled(); expect(revise).not.toHaveBeenCalled(); expect(evaluate).not.toHaveBeenCalled();
});

it("distinguishes same-title immutable revisions without grouping away older selections", async () => {
  const child = structuredClone(original);
  child.id = childId; child.document.candidate_id = childId; child.document.parent_candidate_id = id; child.document.revision = 2; child.document.revision_kind = "source"; child.document.rule_source = "SELECT fixture_id FROM logs LIMIT 1";
  const { user, container, action, revise, evaluate } = setup([original, child]);
  await screen.findByRole("textbox", { name: /^SQLite source/ });
  const list = within(container.querySelector(".candidate-list") as HTMLElement);
  const previous = list.getByRole("button", { name: /Collection rule.*Revision 1.*SQLite/ });
  const latest = list.getByRole("button", { name: /Collection rule.*Revision 2.*SQLite/ });
  expect(previous).not.toHaveTextContent(id); expect(latest).not.toHaveTextContent(childId);
  await user.click(latest);
  expect(screen.getByRole("textbox", { name: /^SQLite source/ })).toHaveValue(child.document.rule_source);
  expect(new URLSearchParams(screen.getByTestId("location").textContent!).get("candidate")).toBe(childId);
  await user.click(screen.getByRole("tab", { name: "Revisions" }));
  expect(screen.getByText("Collection rule · Revision 2 · Source", { selector: "strong" })).toBeVisible();
  await user.click(previous);
  expect(new URLSearchParams(screen.getByTestId("location").textContent!).get("candidate")).toBe(id);
  await user.click(screen.getByRole("tab", { name: "Rule" }));
  expect(screen.getByRole("textbox", { name: /^SQLite source/ })).toHaveValue(original.document.rule_source);
  expect(action).not.toHaveBeenCalled(); expect(revise).not.toHaveBeenCalled(); expect(evaluate).not.toHaveBeenCalled();
});

it("labels the benign-fixture lifecycle stage without implying observed validation", async () => {
  const candidate = structuredClone(original);
  candidate.status = "benign_evaluated";
  candidate.document.state = "benign_evaluated";
  const { container } = setup([candidate]);
  await screen.findByRole("textbox", { name: /^SQLite source/ });

  const list = within(container.querySelector(".candidate-list") as HTMLElement);
  const stateBadge = list.getByText("Benign fixtures evaluated");
  expect(stateBadge).toBeVisible();
  expect(stateBadge).toHaveClass("badge-info");
  expect(screen.queryByText("Benign evaluated", { exact: true })).not.toBeInTheDocument();
  expect(screen.getAllByText("Benign fixtures evaluated").length).toBeGreaterThan(1);
});

it("keeps the active workspace tab across lifecycle refreshes without carrying old definition inputs", async () => {
  const candidate = structuredClone(original);
  candidate.document.target_language = "internal";
  candidate.document.selection = { artifact_type: "file_observation" };
  const advanced = structuredClone(candidate);
  advanced.status = "fixture_exercised";
  advanced.digest = "sha256:advanced-resource";
  advanced.document.state = "fixture_exercised";
  advanced.document.definition_digest = `sha256:${"e".repeat(64)}`;
  advanced.document.malicious_fixtures = [{ fixture_id: "custom-example", artifact_type: "operator value" }];
  const { user, action, detectionList } = setup([candidate]);

  await screen.findByRole("tab", { name: "Fixtures" });
  await user.click(screen.getByRole("tab", { name: "Fixtures" }));
  const malicious = screen.getByRole("textbox", { name: /^Malicious fixtures JSON/ });
  const authoredFixture = [{ fixture_id: "operator-example", artifact_type: "operator value" }];
  fireEvent.change(malicious, { target: { value: JSON.stringify(authoredFixture) } });
  detectionList.mockResolvedValueOnce({ schema_version: "v1", candidates: [advanced] });
  action.mockResolvedValue({ schema_version: "v1", candidate: advanced });

  await user.click(screen.getByRole("button", { name: "Exercise malicious fixtures" }));
  await screen.findAllByText("Fixture exercised", { exact: true });
  const refreshedDefault = JSON.stringify([{ fixture_id: "synthetic-selection-example", artifact_type: "file_observation" }], null, 2);
  await waitFor(() => {
    expect(document.querySelector(".candidate-workspace")?.getAttribute("data-active-tab")).toBe("fixtures");
    expect(screen.getByRole("textbox", { name: /^Malicious fixtures JSON/ })).toHaveValue(refreshedDefault);
  });

  expect(screen.getByRole("tab", { name: "Fixtures" })).toHaveAttribute("aria-selected", "true");
  expect(screen.getByRole("textbox", { name: /^Malicious fixtures JSON/ })).toHaveValue(refreshedDefault);
  expect(action).toHaveBeenCalledWith(id, "exercise-fixtures", { fixtures: authoredFixture });
});

it("migrates the selected tab from a retained definition-bound draft", async () => {
  const first = setup();
  await screen.findByRole("tab", { name: "Fixtures" });
  await first.user.click(screen.getByRole("tab", { name: "Fixtures" }));
  const legacyEntry = Object.keys(sessionStorage).find((key) => {
    if (!key.startsWith("bluefire.detection-draft.v1:") || key === workspaceTabKey) return false;
    try {
      const value = JSON.parse(sessionStorage.getItem(key)!).value;
      return value && typeof value === "object" && value.tab === "fixtures" && "fixtures" in value;
    } catch { return false; }
  });
  expect(legacyEntry).toBeDefined();
  expect(JSON.parse(sessionStorage.getItem(legacyEntry!)!).value.tab).toBe("fixtures");
  sessionStorage.removeItem(workspaceTabKey);
  first.unmount();
  first.client.clear();

  const reopened = setup();
  await screen.findByRole("tab", { name: "Fixtures" });
  await waitFor(() => expect(screen.getByRole("tab", { name: "Fixtures" })).toHaveAttribute("aria-selected", "true"));
  expect(JSON.parse(sessionStorage.getItem(workspaceTabKey)!).value.tab).toBe("fixtures");
  reopened.unmount();
  reopened.client.clear();
});

it("surfaces and clears a malformed stable tab record through explicit draft discard", async () => {
  sessionStorage.setItem(workspaceTabKey, "{malformed");
  const { user } = setup();
  await screen.findByRole("tab", { name: "Rule" });
  expect(await screen.findByRole("alert")).toHaveTextContent("retained draft could not be read");

  await user.click(screen.getByRole("button", { name: "Discard local inputs" }));
  await user.click(screen.getByRole("button", { name: "Discard these inputs" }));

  await waitFor(() => expect(screen.queryByRole("alert")).not.toBeInTheDocument());
  expect(screen.getByRole("tab", { name: "Rule" })).toHaveAttribute("aria-selected", "true");
  const repaired = JSON.parse(sessionStorage.getItem(workspaceTabKey)!);
  expect(repaired.value).toEqual({ tab: "candidate" });
});

it.each([
  ["simulate", "synthetic", 0, "Synthetic simulation", "0 independent observations"],
  ["execute", "observed", 1, "Execution record", "1 independent observation"],
] as const)("shows source name, provenance and exact observed count by the run-authoring action", async (mode, provenance, count, sourceType, observationLabel) => {
  const sourceRun: RunRecord = {
    ...structuredClone(demoRuns[0]!),
    run_id: "run-20261021T000000Z-1234567812345678",
    scenario: undefined,
    scenario_title: "Selected source run by name",
    mode,
    is_demo: false,
    manifest: {},
    evidence: { records: Array.from({ length: count }, (_, index) => ({ evidence_id: `evidence-${index}`, run_id: "run-20261021T000000Z-1234567812345678", provenance })) },
    detections: { candidates: [] },
  };
  setup([], true, sourceRun);
  const create = await screen.findByRole("link", { name: "Create from run evidence" });
  const sourceSummary = await screen.findByLabelText("Selected source eligibility");
  expect(await within(sourceSummary).findByText(observationLabel)).toBeVisible();
  expect(sourceSummary).toHaveTextContent("Selected source run by name");
  expect(sourceSummary).toHaveTextContent(sourceRun.run_id.slice(-8));
  expect(sourceSummary).toHaveTextContent(sourceType);
  expect(sourceSummary).toHaveTextContent(observationLabel);
  expect(create).toHaveAttribute("href", expect.stringContaining("create=1"));
  if (count === 0) expect(sourceSummary).toHaveTextContent("cannot support observed exercise");
  else expect(sourceSummary).not.toHaveTextContent("cannot support observed exercise");
});

it.each([
  ["simulate", undefined, "Synthetic simulation"],
  ["simulate", false, "Synthetic simulation"],
  ["simulate", true, "Synthetic demo"],
  ["execute", false, "Execution record"],
  ["execute", undefined, "Execution record"],
  [undefined, false, "Source type unknown"],
  [undefined, undefined, "Source type unknown"],
] as const)("uses recorded mode %s and demo %s without claiming native proof", async (mode, demo, expected) => {
  const sourceRun = { ...structuredClone(demoRuns[0]!), run_id: "run-20261021T000000Z-aaaaaaaaaaaaaaaa", mode, is_demo: demo, detections: { candidates: [structuredClone(original.document)] } } as RunRecord;
  const { container, action, revise, evaluate } = setup([], true, sourceRun);
  const rail = await screen.findByRole("complementary", { name: "Selected detector context" });
  expect(within(rail).getByText(expected)).toBeVisible();
  const candidateList = within(container.querySelector(".candidate-list") as HTMLElement);
  expect(candidateList.getByText(expected)).toBeVisible();
  expect(screen.queryByText("Native run")).not.toBeInTheDocument();
  const save = screen.getByRole("button", { name: "Save hypothesis from run" });
  expect(save.closest(".run-linked-action")).not.toBeNull();
  expect(screen.getByText(/This candidate is part of an immutable run\./)).toHaveClass("run-linked-description");
  if (demo === true) expect(save).toBeDisabled();
  else expect(save).toBeEnabled();
  expect(action).not.toHaveBeenCalled(); expect(revise).not.toHaveBeenCalled(); expect(evaluate).not.toHaveBeenCalled();
});

it("preserves keyboard focus when switching run-linked candidates", async () => {
  const first: RunRecord = { ...structuredClone(demoRuns[0]!), run_id: "run-20261021T000000Z-aaaaaaaaaaaaaaaa", is_demo: false,
    evidence: { records: [] }, detections: { candidates: [{ ...structuredClone(original.document), title: "First source rule" }] } };
  const second: RunRecord = { ...structuredClone(first), run_id: "run-20261021T000001Z-bbbbbbbbbbbbbbbb",
    detections: { candidates: [{ ...structuredClone(original.document), candidate_id: childId, title: "Second source rule" }] } };
  const { user, action, revise, evaluate } = setup([], true, first, [second]);
  await screen.findByRole("heading", { name: "First source rule" });
  const selector = screen.getByRole("combobox", { name: "Detection source run" });
  await user.click(selector);
  await user.keyboard("{ArrowDown}");
  expect(selector).toHaveFocus();
  // Native select keyboard changes emit change; jsdom does not implement that default action.
  fireEvent.change(selector, { target: { value: second.run_id } });
  await screen.findByRole("heading", { name: "Second source rule" });
  expect(screen.getByRole("combobox", { name: "Detection source run" })).toBe(selector);
  expect(selector).toHaveValue(second.run_id);
  expect(selector).toHaveFocus();
  await user.tab();
  expect(screen.getByRole("link", { name: "Review source run" })).toHaveFocus();
  expect(action).not.toHaveBeenCalled(); expect(revise).not.toHaveBeenCalled(); expect(evaluate).not.toHaveBeenCalled();
});

it("distinguishes similarly named sources by their visible recorded time and run reference", async () => {
  const longName = "Collection comparison with the same deliberately long descriptive source name";
  const first: RunRecord = { ...structuredClone(demoRuns[0]!), run_id: "run-20261023T110501Z-aaaaaaaaaaaaaaaa", is_demo: false,
    scenario: undefined, scenario_title: longName, created_at: "2026-10-23T11:05:01.000Z", evidence: { records: [] }, detections: { candidates: [] } };
  const second: RunRecord = { ...structuredClone(first), run_id: "run-20261023T110609Z-bbbbbbbbbbbbbbbb", created_at: "2026-10-23T11:06:09.000Z" };
  const { user, action, revise, evaluate } = setup([structuredClone(original)], true, first, [second]);
  const reference = await screen.findByRole("link", { name: "Review source run" });
  expect(reference).toHaveAttribute("href", `/runs/${first.run_id}`);
  expect(reference).toHaveAttribute("title", expect.stringContaining(longName));
  expect(within(reference).getByText(first.run_id.slice(-8), { exact: true })).toBeVisible();
  expect(reference.querySelector("time")).toHaveAttribute("datetime", first.created_at);
  await user.selectOptions(screen.getByRole("combobox", { name: "Detection source run" }), second.run_id);
  await waitFor(() => expect(screen.getByRole("link", { name: "Review source run" })).toHaveAttribute("href", `/runs/${second.run_id}`));
  const current = screen.getByRole("link", { name: "Review source run" });
  expect(current).toHaveAttribute("title", expect.stringContaining(longName));
  expect(within(current).getByText(second.run_id.slice(-8), { exact: true })).toBeVisible();
  expect(within(current).queryByText(first.run_id.slice(-8), { exact: true })).not.toBeInTheDocument();
  expect(current.querySelector("time")).toHaveAttribute("datetime", second.created_at);
  expect(action).not.toHaveBeenCalled(); expect(revise).not.toHaveBeenCalled(); expect(evaluate).not.toHaveBeenCalled();
});

it.each([false, true])("distinguishes missing evidence from an explicitly empty inventory (reported: %s)", async reported => {
  const sourceRun: RunRecord = { ...structuredClone(demoRuns[0]!), run_id: "run-20261021T000000Z-aaaaaaaaaaaaaaaa", is_demo: false,
    evidence: reported ? { records: [] } : undefined, detections: { candidates: [structuredClone(original.document)] } };
  const { user, action, revise, evaluate } = setup([], true, sourceRun);
  const panel = (await screen.findByRole("heading", { name: "Source records" })).closest(".source-records-panel") as HTMLElement;
  expect(within(panel).getByText(reported ? "0" : "Not reported", { exact: true })).toBeVisible();
  expect(within(panel).getByText(reported ? "This run has no retained evidence records." : "This run did not report an evidence record inventory.")).toBeVisible();
  expect(within(panel).queryByRole("button", { name: /^Inspect source record/ })).not.toBeInTheDocument();
  expect(within(panel).queryByLabelText("Selected source record")).not.toBeInTheDocument();
  const observationLabel = reported ? "0 independent observations" : "Independent observations not reported";
  expect(within(screen.getByLabelText("Selected source eligibility")).getByText(observationLabel, { exact: true })).toBeVisible();
  await user.click(screen.getByText(observationLabel, { exact: true }));
  if (reported) expect(screen.getByText("Inspect source evidence (0)", { selector: "summary" })).toBeVisible();
  else {
    expect(screen.getByText("Observed evidence not reported")).toBeVisible();
    expect(screen.queryByText("Inspect source evidence (0)", { selector: "summary" })).not.toBeInTheDocument();
    expect(screen.queryByText("No evidence records", { exact: true })).not.toBeInTheDocument();
  }
  expect(action).not.toHaveBeenCalled(); expect(revise).not.toHaveBeenCalled(); expect(evaluate).not.toHaveBeenCalled();
});

it("keeps the inspected source record when a different candidate is selected", async () => {
  const sourceRun: RunRecord = { ...structuredClone(demoRuns[0]!), run_id: "run-20261021T000000Z-aaaaaaaaaaaaaaaa", is_demo: false,
    evidence: { records: [{ evidence_id: "first-record", provenance: "synthetic", summary: "First generated record" }, { evidence_id: "second-record", provenance: "synthetic", summary: "Second generated record" }] },
    detections: { candidates: [{ ...structuredClone(original.document), title: "First source rule" }, { ...structuredClone(original.document), candidate_id: childId, title: "Second source rule" }] } };
  const { user, action, revise, evaluate } = setup([], true, sourceRun);
  await screen.findByRole("heading", { name: "First source rule" });
  const record = screen.getByRole("button", { name: "Inspect source record 2: Second generated record" });
  await user.click(record);
  expect(within(screen.getByLabelText("Selected record overview")).getByText("Second generated record", { exact: true })).toBeVisible();
  expect(screen.getByLabelText("Selected source record")).not.toBeVisible();
  const retainedRecord = within(screen.getByLabelText("Selected record overview")).getByText("Inspect retained record", { selector: "summary" });
  await user.click(retainedRecord);
  expect(screen.getByLabelText("Selected source record")).toBeVisible();
  expect(screen.getByLabelText("Selected source record")).toHaveTextContent('"evidence_id": "second-record"');
  await user.click(screen.getByRole("button", { name: /^Second source rule · Revision/ }));
  await screen.findByRole("heading", { name: "Second source rule" });
  expect(screen.getByRole("button", { name: "Inspect source record 2: Second generated record" })).toBe(record);
  expect(record).toHaveAttribute("aria-pressed", "true");
  expect(screen.getByLabelText("Selected source record")).toHaveTextContent('"evidence_id": "second-record"');
  expect(action).not.toHaveBeenCalled(); expect(revise).not.toHaveBeenCalled(); expect(evaluate).not.toHaveBeenCalled();
});

it("names source records from saved step context and presents recognized projections without changing the record", async () => {
  const behavior = demoCatalog.behaviors.find(item => item.id === "sandbox.fixture.create.v1")!;
  const sourceRun: RunRecord = { ...structuredClone(demoRuns[0]!), run_id: "run-20261021T000000Z-aaaaaaaaaaaaaaaa", is_demo: false,
    steps: [{ step_id: "create_fixture", status: "success", behavior_id: behavior.id, simulation_id: behavior.simulation_id, evidence_ids: ["fixture-projection"] }],
    evidence: { records: [{ schema_version: "bluefire.evidence.v1", evidence_id: "fixture-projection", producer: "simulation-registry.v1", provenance: "synthetic",
      content: { simulation_id: "simulation.sandbox.fixture.create.v1", side_effects_started: false, artifacts: { workspace: { type: "artifact.sandbox.workspace.v1", format: "jsonl", record_count: 8 } } },
      limitations: ["Synthetic projection only; no host effect occurred."] }] }, detections: { candidates: [structuredClone(original.document)] } };
  const before = structuredClone(sourceRun);
  const { user, action, revise, evaluate } = setup([], true, sourceRun);
  const row = await screen.findByRole("button", { name: `Inspect source record 1: ${behavior.title}` });
  expect(within(row).getByText("Synthetic", { exact: true })).toBeVisible();
  expect(row).not.toHaveTextContent("simulation-registry.v1");
  const overview = screen.getByLabelText("Selected record overview");
  expect(within(overview).getByText("Simulation projected 8 sample records in JSONL format.")).toBeVisible();
  expect(within(overview).getByText("Synthetic projection only; no host effect occurred.")).toBeVisible();
  await user.click(within(overview).getByText("Inspect retained record", { selector: "summary" }));
  expect(JSON.parse(screen.getByLabelText("Selected source record").textContent!)).toEqual(before.evidence!.records![0]);
  expect(sourceRun).toEqual(before);
  expect(action).not.toHaveBeenCalled(); expect(revise).not.toHaveBeenCalled(); expect(evaluate).not.toHaveBeenCalled();
});
