import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog } from "../src/lib/demo";
import { DetectionLabPage } from "../src/pages/DetectionLab";
import type { DetectionResource } from "../src/types";

const id = `detection-${"a".repeat(20)}`;
const childId = `detection-${"b".repeat(20)}`;
const definition = `sha256:${"c".repeat(64)}`;
const query = `sha256:${"d".repeat(64)}`;
const source = "SELECT fixture_id FROM logs WHERE observation_kind = 'filesystem'";
const original: DetectionResource = { kind: "detections", id, status: "parsed", digest: "sha256:resource", created_at: "2026-09-09", updated_at: "2026-09-09", document: {
  candidate_id: id, revision_root_id: id, revision: 1, revision_kind: "origin", title: "Collection rule", behavior_id: "sandbox.collection.stage.v1", target_language: "sqlite", state: "parsed", rule_source: source, selection: {}, logsource: {}, definition_digest: definition,
  parser_backend: { name: "SQLite bounded executor", version: "3.46" }, validation: { query_sha256: query, converted_query: source, source_rule_executed: true, execution_backend: "SQLite", execution_backend_version: "3.46", last_execution: { fixture_ids: ["observed-one", "observed-two"], matched_fixture_ids: ["observed-two"] }, unsupported_fields: [] },
} };
function Location() { return <output data-testid="location">{useLocation().search}</output>; }
function setup(candidates = [structuredClone(original)], ready = true) {
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  vi.spyOn(api, "runs").mockResolvedValue({ schema_version: "v1", unavailable_run_count: 0, runs: [] });
  vi.spyOn(api, "detections").mockResolvedValue({ schema_version: "v1", candidates });
  vi.spyOn(api, "resources").mockResolvedValue({ schema_version: "v1", kind: "research-sources", resources: [] });
  vi.spyOn(api, "detectionHealth").mockResolvedValue({ schema_version: "v1", ready, persistence_ready: true, candidate_resources: candidates.length, invalid_candidate_resources: 0, languages: { sqlite: { ready, authoritative: true, backend: "SQLite bounded executor" }, sigma: { ready, authoritative: true, backend: "pySigma" } }, limits: { source_bytes: 262144, fixture_bytes: 1048576, fixtures_per_action: 128, evidence_per_action: 256, notes_per_action: 64 } });
  vi.spyOn(api, "detectionRunEvaluations").mockResolvedValue({ evaluations: [] });
  const action = vi.spyOn(api, "detectionAction");
  const revise = vi.spyOn(api, "reviseDetectionSource");
  const evaluate = vi.spyOn(api, "evaluateDetectionRun");
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const rendered = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/detection-lab?candidate=${id}&candidate_scope=registry`]}><DetectionLabPage/><Location/></MemoryRouter></QueryClientProvider>);
  return { ...rendered, user: userEvent.setup(), action, revise, evaluate };
}

it("names SQLite consistently and discloses identities without hiding query execution or results", async () => {
  const { user, action, revise, evaluate } = setup();
  expect(await screen.findByRole("textbox", { name: /^SQLite source/ })).toHaveValue(source);
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
  expect(screen.getByText("Revision 2 · Source", { selector: "strong" })).toBeVisible();
  await user.click(previous);
  expect(new URLSearchParams(screen.getByTestId("location").textContent!).get("candidate")).toBe(id);
  expect(action).not.toHaveBeenCalled(); expect(revise).not.toHaveBeenCalled(); expect(evaluate).not.toHaveBeenCalled();
});
