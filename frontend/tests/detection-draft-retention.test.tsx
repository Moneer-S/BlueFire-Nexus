import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Link, MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { api, ApiError } from "../src/lib/api";
import { demoCatalog, demoRuns } from "../src/lib/demo";
import { DetectionLabPage } from "../src/pages/DetectionLab";
import type { DetectionResource } from "../src/types";

const source = "SELECT fixture_id FROM logs WHERE observation_kind = 'filesystem'";
const edited = "SELECT fixture_id FROM logs WHERE observation_kind = 'collection_semantics'";
const id = `detection-${"a".repeat(20)}`;
const otherId = `detection-${"c".repeat(20)}`;
const parent: DetectionResource = { kind: "detections", id, status: "parsed", digest: "sha256:parent", created_at: "2026-09-06", updated_at: "2026-09-06", document: { candidate_id: id, revision_root_id: id, revision: 1, title: "Baseline SQL", target_language: "sqlite", state: "parsed", rule_source: source, selection: { observation_kind: "filesystem" }, logsource: { category: "file_event" }, parser_backend: { name: "SQLite bounded executor" } } };
const manualKey = "bluefire.detection-draft.v1:manual-new-rule";
const manualDefaults = { title: "", behaviorId: "sandbox.collection.stage.v1", language: "sqlite" };

function LocationWitness() {
  return <output data-testid="location">{useLocation().search}</output>;
}

function setup(ready = true, aiJob = false, draft = false) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const candidates = [structuredClone(parent), { ...structuredClone(parent), id: otherId, document: { ...structuredClone(parent.document), candidate_id: otherId, revision_root_id: otherId, title: "Other SQL" } }];
  if (draft) { candidates[0]!.document.state = "hypothesis"; candidates[0]!.document.rule_source = ""; }
  vi.spyOn(api, "detections").mockImplementation(async () => ({ schema_version: "v1", candidates }));
  vi.spyOn(api, "runs").mockResolvedValue({ schema_version: "v1", unavailable_run_count: 0, runs: demoRuns });
  vi.spyOn(api, "runDetail").mockResolvedValue(demoRuns[0]!);
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  vi.spyOn(api, "resources").mockResolvedValue({ schema_version: "v1", kind: "research-sources", resources: [] });
  vi.spyOn(api, "detectionHealth").mockResolvedValue({ schema_version: "v1", ready, persistence_ready: true, candidate_resources: 2, invalid_candidate_resources: 0, languages: { sqlite: { ready, authoritative: true, backend: "SQLite bounded executor" } }, limits: { source_bytes: 262144, fixture_bytes: 1048576, fixtures_per_action: 128, evidence_per_action: 256, notes_per_action: 64 } });
  vi.spyOn(api, "detectionRunEvaluations").mockResolvedValue({ evaluations: [] });
  if (aiJob) vi.spyOn(api, "job").mockResolvedValue({ schema_version: "bluefire.job.v1", job_id: "job-review-retained", kind: "detection.ai.propose", state: "failed", request: {}, progress: {} });
  const mount = (path: string) => render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><Link to="/elsewhere">Leave lab</Link><Link to="/detection-lab">Return to lab</Link><Routes><Route path="/detection-lab" element={<DetectionLabPage/>}/><Route path="/elsewhere" element={<p>Elsewhere</p>}/></Routes><LocationWitness/></MemoryRouter></QueryClientProvider>);
  let view = mount(`/detection-lab?run=${demoRuns[0]!.run_id}&candidate=${id}&candidate_scope=registry`);
  return { user: userEvent.setup(), candidates, client, remount: (path = "/detection-lab") => { view.unmount(); client.clear(); view = mount(path); } };

}

async function edit(user: ReturnType<typeof userEvent.setup>) {
  const editor = await screen.findByRole("textbox", { name: /sqlite source/i });
  expect(editor).toBeEnabled();
  await user.clear(editor);
  // Replace the full SQL document as a user pasting an edited rule would.
  await user.paste(edited);
  await user.type(screen.getByRole("textbox", { name: "Reason for source revision" }), "Inspect contents observations");
  expect(screen.getByText("Draft source not validated")).toBeVisible();
}

it("retains source, reasons, tuning and fixtures across candidate changes and routine navigation", async () => {
  const { user } = setup();
  const action = vi.spyOn(api, "detectionAction");
  const revise = vi.spyOn(api, "reviseDetectionSource");
  await edit(user);
  await user.click(screen.getByRole("tab", { name: "Revisions" }));
  await user.click(screen.getByText("Advanced clone and tune"));
  await user.click(screen.getByRole("radio", { name: /Tune rule behavior/ }));
  const selection = screen.getByRole("textbox", { name: /^Tuned selection JSON/ });
  await user.clear(selection); await user.paste('{"custom":"draft"}');
  const logsource = screen.getByRole("textbox", { name: /^Tuned log source JSON/ });
  await user.clear(logsource); await user.paste('{"category":"custom"}');
  await user.click(screen.getByRole("textbox", { name: "Revision title" }));
  await user.keyboard("{End}");
  await user.paste(" edited");
  await user.click(screen.getByRole("tab", { name: "Fixtures" }));
  const fixtures = screen.getByRole("textbox", { name: /^Malicious fixtures JSON/ });
  await user.click(fixtures); await user.paste("draft fixture text");
  await user.click(screen.getByRole("button", { name: /Other SQL/ }));
  expect(screen.getByRole("textbox", { name: /sqlite source/i })).toHaveValue(source);
  await user.click(screen.getByRole("button", { name: /Baseline SQL/ }));
  expect(screen.getByRole("tab", { name: "Fixtures" })).toHaveAttribute("aria-selected", "true");
  expect(screen.getByRole("textbox", { name: /^Malicious fixtures JSON/ })).toHaveValue("draft fixture text");
  await user.click(screen.getByRole("link", { name: "Leave lab" }));
  await user.click(screen.getByRole("link", { name: "Return to lab" }));
  expect(await screen.findByRole("textbox", { name: /^Malicious fixtures JSON/ })).toHaveValue("draft fixture text");
  await user.click(screen.getByRole("tab", { name: "Revisions" }));
  await user.click(screen.getByText("Advanced clone and tune"));
  expect(screen.getByRole("textbox", { name: /^Tuned selection JSON/ })).toHaveValue('{"custom":"draft"}');
  expect(screen.getByRole("textbox", { name: /^Tuned log source JSON/ })).toHaveValue('{"category":"custom"}');
  expect(screen.getByRole("textbox", { name: "Revision title" })).toHaveValue("Baseline SQL edited");
  expect(screen.getByRole("textbox", { name: /^Required research reason/ })).toHaveValue("Inspect contents observations");
  await user.click(screen.getByRole("tab", { name: "Rule" }));
  expect(screen.getByRole("textbox", { name: /sqlite source/i })).toHaveValue(edited);
  expect(action).not.toHaveBeenCalled(); expect(revise).not.toHaveBeenCalled();
});

it("restores exact selection, filter, tab and failed-save inputs after reload", async () => {
  const { user, remount } = setup();
  vi.spyOn(api, "reviseDetectionSource").mockRejectedValue(new Error("Validation refused"));
  await edit(user);
  await user.click(screen.getByRole("button", { name: "Validate and save new revision" }));
  await screen.findByText("Validation refused");
  await user.type(screen.getByRole("textbox", { name: "Search detection candidates" }), "Baseline");
  await user.click(screen.getByRole("tab", { name: "Revisions" }));
  await user.click(screen.getByText("Advanced clone and tune"));
  remount();
  await user.click(await screen.findByText("Advanced clone and tune"));
  expect(await screen.findByRole("textbox", { name: /^Required research reason/ })).toHaveValue("Inspect contents observations");
  expect(screen.getByRole("textbox", { name: "Search detection candidates" })).toHaveValue("Baseline");
  expect(new URLSearchParams(screen.getByTestId("location").textContent!).get("candidate")).toBe(id);
  await user.click(screen.getByRole("tab", { name: "Rule" }));
  expect(screen.getByRole("textbox", { name: /sqlite source/i })).toHaveValue(edited);
  expect(api.reviseDetectionSource).toHaveBeenCalledTimes(1);
});

it("keeps harmless refetch edits but never applies them to a new authoritative version", async () => {
  const { user, candidates, client } = setup();
  await edit(user);
  act(() => client.setQueryData(["detections"], { schema_version: "v1", candidates: structuredClone(candidates) }));
  expect(screen.getByRole("textbox", { name: /sqlite source/i })).toHaveValue(edited);
  const changed = structuredClone(candidates);
  changed[0]!.digest = "sha256:new-definition";
  changed[0]!.document.revision = 2;
  changed[0]!.document.rule_source = "SELECT fixture_id FROM logs LIMIT 2";
  act(() => client.setQueryData(["detections"], { schema_version: "v1", candidates: changed }));
  await waitFor(() => expect(screen.getByRole("textbox", { name: /sqlite source/i })).toHaveValue(changed[0]!.document.rule_source));
  expect(screen.getByRole("textbox", { name: "Reason for source revision" })).toHaveValue("");
  act(() => client.setQueryData(["detections"], { schema_version: "v1", candidates }));
  await waitFor(() => expect(screen.getByRole("textbox", { name: /sqlite source/i })).toHaveValue(edited));
});

it("separates evidence inputs by source context while preserving the rule draft", async () => {
  const { user } = setup();
  const action = vi.spyOn(api, "detectionAction");
  await edit(user);
  await user.click(screen.getByRole("tab", { name: "Observed" }));
  await user.type(screen.getByRole("textbox", { name: /^Evidence IDs/ }), "observed-only-from-original");
  await user.selectOptions(screen.getByRole("combobox", { name: "Detection source run" }), "");
  expect(screen.getByRole("textbox", { name: /^Evidence IDs/ })).toHaveValue("");
  expect(screen.getByRole("combobox", { name: "Finalized run" })).toHaveValue("");
  await user.click(screen.getByRole("tab", { name: "Rule" }));
  expect(screen.getByRole("textbox", { name: /sqlite source/i })).toHaveValue(edited);
  await user.selectOptions(screen.getByRole("combobox", { name: "Detection source run" }), demoRuns[0]!.run_id);
  await user.click(screen.getByRole("tab", { name: "Observed" }));
  expect(screen.getByRole("textbox", { name: /^Evidence IDs/ })).toHaveValue("observed-only-from-original");
  expect(action).not.toHaveBeenCalled();
});

it("keeps storage-failed inputs in the open session and requires explicit discard", async () => {
  const { user } = setup();
  await screen.findByRole("textbox", { name: /sqlite source/i });
  const write = Storage.prototype.setItem;
  vi.spyOn(Storage.prototype, "setItem").mockImplementation(function (this: Storage, key, value) {
    if (key.startsWith("bluefire.detection-draft.v1:")) throw new DOMException("Full", "QuotaExceededError");
    write.call(this, key, value);
  });
  await edit(user);
  expect(screen.getByRole("alert")).toHaveTextContent("only for this open session");
  await user.click(screen.getByRole("button", { name: /Other SQL/ }));
  await user.click(screen.getByRole("button", { name: /Baseline SQL/ }));
  expect(screen.getByRole("textbox", { name: /sqlite source/i })).toHaveValue(edited);
  await user.click(screen.getByRole("button", { name: "Discard local inputs" }));
  expect(screen.getByRole("dialog", { name: "Discard inputs for this revision?" })).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Keep editing" }));
  expect(screen.getByRole("textbox", { name: /sqlite source/i })).toHaveValue(edited);
  await user.click(screen.getByRole("button", { name: "Discard local inputs" }));
  await user.click(screen.getByRole("button", { name: "Discard these inputs" }));
  expect(screen.getByRole("textbox", { name: /sqlite source/i })).toHaveValue(source);
  expect(screen.getByRole("button", { name: "Discard local inputs" })).toHaveFocus();
});

it("retains benign examples and notes without evaluating them on return", async () => {
  const { user, candidates, remount } = setup();
  candidates[0]!.document.state = "fixture_exercised";
  const action = vi.spyOn(api, "detectionAction");
  await screen.findByRole("heading", { name: "Baseline SQL" });
  await user.click(screen.getByRole("tab", { name: "Fixtures" }));
  await user.type(screen.getByRole("textbox", { name: /^Benign fixtures JSON/ }), "unfinished benign sample");
  await user.type(screen.getByRole("textbox", { name: "Benign evaluation notes" }), "Investigate a normal collection");
  remount();
  expect(await screen.findByRole("textbox", { name: /^Benign fixtures JSON/ })).toHaveValue("unfinished benign sample");
  expect(screen.getByRole("textbox", { name: "Benign evaluation notes" })).toHaveValue("Investigate a normal collection");
  expect(action).not.toHaveBeenCalled();
});

it.each(["malformed", "oversized", "unknown-envelope"])("leaves an unreadable %s draft untouched until explicit discard", async kind => {
  const { user, remount } = setup();
  const action = vi.spyOn(api, "detectionAction");
  await edit(user);
  const key = Object.keys(sessionStorage).find(key => key.startsWith("bluefire.detection-draft.v1:") && !key.includes(":observed:"))!;
  expect(key).toBeTruthy();
  const raw = kind === "malformed" ? "{unreadable" : kind === "oversized" ? "x".repeat(2 * 1024 * 1024 + 1) : JSON.stringify({ ...JSON.parse(sessionStorage.getItem(key)!), unknown_field: "Preserve this unrecognized envelope" });
  sessionStorage.setItem(key, raw);
  remount();
  expect(await screen.findByRole("textbox", { name: /sqlite source/i })).toHaveValue(source);
  expect(screen.getByRole("alert")).toHaveTextContent("stored bytes have been left untouched");
  expect(sessionStorage.getItem(key)).toBe(raw);
  await user.click(screen.getByRole("tab", { name: "Fixtures" }));
  expect(sessionStorage.getItem(key)).toBe(raw);
  await user.click(screen.getByRole("button", { name: "Discard local inputs" }));
  await user.click(screen.getByRole("button", { name: "Discard these inputs" }));
  expect(sessionStorage.getItem(key)).toBeNull();
  expect(action).not.toHaveBeenCalled();
});

it("gives an explicit incoming candidate link precedence over a retained selection", async () => {
  const { user, remount } = setup();
  await edit(user);
  await user.type(screen.getByRole("textbox", { name: "Search detection candidates" }), "Baseline");
  remount(`/detection-lab?run=${demoRuns[1]!.run_id}&candidate=${otherId}&candidate_scope=registry`);
  expect(await screen.findByRole("heading", { name: "Other SQL" })).toBeVisible();
  expect(screen.getByRole("textbox", { name: "Search detection candidates" })).toHaveValue("");
  expect(screen.getByRole("textbox", { name: /sqlite source/i })).toHaveValue(source);
  expect(screen.getByRole("combobox", { name: "Detection source run" })).toHaveValue(demoRuns[1]!.run_id);
});

it("distinguishes creation source choices with mode and date, including missing dates", async () => {
  const { remount } = setup();
  vi.mocked(api.runs).mockResolvedValue({ schema_version: "v1", unavailable_run_count: 0, runs: [
    { ...demoRuns[0]!, scenario_title: "Collection", created_at: "2030-01-02T12:00:00Z", mode: "execute" },
    { ...demoRuns[1]!, scenario_title: "Collection", created_at: "", finalized_at: "", mode: "simulate" },
  ] });
  remount("/detection-lab?create=1");
  expect(await screen.findByRole("option", { name: /Collection.*Execute/ })).toHaveTextContent("2030");
  expect(screen.getByRole("option", { name: "Collection · Simulate · Date unavailable" })).toBeVisible();
});

it("preserves an oversized live edit across candidate switches in the open session", async () => {
  const { user } = setup();
  const action = vi.spyOn(api, "detectionAction");
  const editor = await screen.findByRole("textbox", { name: /sqlite source/i });
  const large = "x".repeat(2 * 1024 * 1024 + 1);
  await user.clear(editor); await user.paste(large);
  expect(screen.getByRole("alert")).toHaveTextContent("only for this open session");
  await user.click(screen.getByRole("button", { name: /Other SQL/ }));
  await user.click(screen.getByRole("button", { name: /Baseline SQL/ }));
  expect((screen.getByRole("textbox", { name: /sqlite source/i }) as HTMLTextAreaElement).value === large).toBe(true);
  expect(action).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Discard local inputs" }));
  await user.click(screen.getByRole("button", { name: "Discard these inputs" }));
});

async function openManual(user: ReturnType<typeof userEvent.setup>) {
  await screen.findByRole("heading", { name: "Baseline SQL" });
  await user.click(screen.getByText("New rule", { selector: "summary" }));
  expect(screen.getByRole("textbox", { name: "Title" })).toBeVisible();
}

it("keeps manual New rule inputs open across navigation, reload and evidence selections without saving", async () => {
  const { user, remount } = setup();
  const save = vi.spyOn(api, "upsertDetection");
  await openManual(user);
  const title = screen.getByRole("textbox", { name: "Title" });
  await user.clear(title); await user.paste("Manual collection draft");
  const behavior = demoCatalog.behaviors.find(item => item.id !== manualDefaults.behaviorId)!;
  await user.selectOptions(screen.getByRole("combobox", { name: "Registered behavior" }), behavior.id);
  await user.selectOptions(screen.getByRole("combobox", { name: "Target language" }), "sqlite");
  await user.click(screen.getByRole("link", { name: "Leave lab" }));
  await user.click(screen.getByRole("link", { name: "Return to lab" }));
  expect(await screen.findByRole("textbox", { name: "Title" })).toBeVisible();
  expect(screen.getByRole("textbox", { name: "Title" })).toHaveValue("Manual collection draft");
  remount(`/detection-lab?run=${demoRuns[1]!.run_id}&candidate=${otherId}&candidate_scope=registry`);
  expect(await screen.findByRole("textbox", { name: "Title" })).toBeVisible();
  expect(screen.getByRole("textbox", { name: "Title" })).toHaveValue("Manual collection draft");
  expect(screen.getByRole("combobox", { name: "Registered behavior" })).toHaveValue(behavior.id);
  expect(screen.getByRole("combobox", { name: "Target language" })).toHaveValue("sqlite");
  expect(save).not.toHaveBeenCalled();
});

it("confirms manual discard, returns focus, and preserves other rule drafts", async () => {
  const { user, remount } = setup();
  const save = vi.spyOn(api, "upsertDetection");
  await edit(user);
  await openManual(user);
  await user.type(screen.getByRole("textbox", { name: "Title" }), " edited");
  await user.click(screen.getByRole("button", { name: "Discard New rule inputs" }));
  expect(screen.getByRole("dialog", { name: "Discard New rule inputs?" })).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Keep editing" }));
  expect(screen.getByRole("textbox", { name: "Title" })).toHaveValue(manualDefaults.title + " edited");
  await user.click(screen.getByRole("button", { name: "Discard New rule inputs" }));
  await user.click(screen.getByRole("button", { name: "Discard these inputs" }));
  expect(screen.getByRole("textbox", { name: "Title" })).toBeVisible();
  expect(screen.getByRole("textbox", { name: "Title" })).toHaveValue(manualDefaults.title);
  expect(screen.getByRole("button", { name: "Discard New rule inputs" })).toHaveFocus();
  expect(sessionStorage.getItem(manualKey)).toBeNull();
  expect(screen.getByRole("textbox", { name: /sqlite source/i })).toHaveValue(edited);
  remount();
  expect(await screen.findByRole("textbox", { name: /sqlite source/i })).toHaveValue(edited);
  expect(save).not.toHaveBeenCalled();
});

it("keeps a storage-failed manual draft in this session until explicit discard", async () => {
  const { user, remount } = setup();
  const save = vi.spyOn(api, "upsertDetection");
  await openManual(user);
  const write = Storage.prototype.setItem;
  vi.spyOn(Storage.prototype, "setItem").mockImplementation(function (this: Storage, key, value) {
    if (key === manualKey) throw new DOMException("Full", "QuotaExceededError");
    write.call(this, key, value);
  });
  await user.type(screen.getByRole("textbox", { name: "Title" }), " only in session");
  expect(screen.getByRole("alert")).toHaveTextContent("only for this open session");
  remount();
  expect(await screen.findByRole("textbox", { name: "Title" })).toBeVisible();
  expect(screen.getByRole("textbox", { name: "Title" })).toHaveValue(manualDefaults.title + " only in session");
  await user.click(screen.getByRole("button", { name: "Discard New rule inputs" }));
  await user.click(screen.getByRole("button", { name: "Discard these inputs" }));
  expect(screen.getByRole("textbox", { name: "Title" })).toHaveValue(manualDefaults.title);
  expect(save).not.toHaveBeenCalled();
});

it.each(["malformed", "oversized", "unknown-envelope"])("preserves unreadable %s manual storage until confirmed discard", async kind => {
  const raw = kind === "malformed" ? "{unreadable" : kind === "oversized" ? "x".repeat(2 * 1024 * 1024 + 1) : JSON.stringify({ binding: "manual-new-rule", value: manualDefaults, unknown: "retained" });
  sessionStorage.setItem(manualKey, raw);
  const { user } = setup();
  const save = vi.spyOn(api, "upsertDetection");
  expect(await screen.findByRole("textbox", { name: "Title" })).toBeVisible();
  expect(screen.getByRole("alert")).toHaveTextContent("stored bytes have been left untouched");
  await user.type(screen.getByRole("textbox", { name: "Title" }), " new edit");
  expect(sessionStorage.getItem(manualKey)).toBe(raw);
  await user.click(screen.getByRole("button", { name: "Discard New rule inputs" }));
  await user.click(screen.getByRole("button", { name: "Keep editing" }));
  expect(sessionStorage.getItem(manualKey)).toBe(raw);
  await user.click(screen.getByRole("button", { name: "Discard New rule inputs" }));
  await user.click(screen.getByRole("button", { name: "Discard these inputs" }));
  expect(sessionStorage.getItem(manualKey)).toBeNull();
  expect(save).not.toHaveBeenCalled();
});

it("shows unavailable retained manual choices truthfully and refuses save without substituting", async () => {
  const value = { ...manualDefaults, title: "Retained manual rule", behaviorId: "missing.behavior.v1", language: "missing-language" };
  const raw = JSON.stringify({ binding: "manual-new-rule", value });
  sessionStorage.setItem(manualKey, raw);
  const { user } = setup();
  const save = vi.spyOn(api, "upsertDetection");
  expect(await screen.findByRole("textbox", { name: "Title" })).toBeVisible();
  expect(screen.getByRole("combobox", { name: "Registered behavior" })).toHaveValue(value.behaviorId);
  expect(screen.getByRole("combobox", { name: "Target language" })).toHaveValue(value.language);
  expect(screen.getByRole("option", { name: "Unavailable behavior" })).toBeVisible();
  expect(screen.getByRole("option", { name: "Unavailable language" })).toBeVisible();
  expect(screen.getByRole("button", { name: "Save rule draft" })).toBeDisabled();
  await user.click(screen.getByRole("button", { name: "Save rule draft" }));
  expect(sessionStorage.getItem(manualKey)).toBe(raw);
  await user.selectOptions(screen.getByRole("combobox", { name: "Registered behavior" }), demoCatalog.behaviors[0]!.id);
  expect(screen.getByRole("button", { name: "Save rule draft" })).toBeDisabled();
  await user.selectOptions(screen.getByRole("combobox", { name: "Target language" }), "sqlite");
  expect(screen.getByRole("button", { name: "Save rule draft" })).toBeEnabled();
  expect(save).not.toHaveBeenCalled();
});

it.each([false, true])("preserves newer manual edits when an earlier save completes (remount=%s)", async remountWhilePending => {
  const { user, remount } = setup();
  let finish!: (value: Awaited<ReturnType<typeof api.upsertDetection>>) => void;
  const save = vi.spyOn(api, "upsertDetection").mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  await openManual(user);
  const title = screen.getByRole("textbox", { name: "Title" });
  await user.clear(title); await user.paste("Submitted manual rule");
  await user.click(screen.getByRole("button", { name: "Save rule draft" }));
  expect(save).toHaveBeenCalledTimes(1);
  expect(save.mock.calls[0]![0]).toMatchObject({ title: "Submitted manual rule", behavior_id: manualDefaults.behaviorId, target_language: "sqlite" });
  expect(screen.getByRole("button", { name: "Discard New rule inputs" })).toBeDisabled();
  if (remountWhilePending) remount();
  const newer = await screen.findByRole("textbox", { name: "Title" });
  await user.clear(newer); await user.paste("Newer manual draft");
  const location = screen.getByTestId("location").textContent;
  await act(async () => { finish({ schema_version: "v1", candidate: { ...parent, id: "detection-newly-saved" } }); });
  expect(screen.getByRole("textbox", { name: "Title" })).toHaveValue("Newer manual draft");
  expect(screen.getByTestId("location").textContent).toBe(location);
  expect(save.mock.calls[0]![0]).toMatchObject({ title: "Submitted manual rule" });
  remount();
  expect(await screen.findByRole("textbox", { name: "Title" })).toBeVisible();
  expect(screen.getByRole("textbox", { name: "Title" })).toHaveValue("Newer manual draft");
  expect(save).toHaveBeenCalledTimes(1);
});

it.each(["candidate", "run"])("does not redirect a manual save after navigating %s away and back", async field => {
  const { user } = setup();
  let finish!: (value: Awaited<ReturnType<typeof api.upsertDetection>>) => void;
  const save = vi.spyOn(api, "upsertDetection").mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  await openManual(user);
  await user.type(screen.getByRole("textbox", { name: "Title" }), " submitted");
  await user.click(screen.getByRole("button", { name: "Save rule draft" }));
  const original = screen.getByTestId("location").textContent;
  if (field === "candidate") {
    await user.click(screen.getByRole("button", { name: /Other SQL/ }));
    await user.click(screen.getByRole("button", { name: /Baseline SQL/ }));
  } else {
    await user.selectOptions(screen.getByRole("combobox", { name: "Detection source run" }), "");
    await user.selectOptions(screen.getByRole("combobox", { name: "Detection source run" }), demoRuns[0]!.run_id);
  }
  expect(new URLSearchParams(screen.getByTestId("location").textContent!).get("candidate")).toBe(id);
  expect(new URLSearchParams(screen.getByTestId("location").textContent!).get("run")).toBe(new URLSearchParams(original!).get("run"));
  const returned = screen.getByTestId("location").textContent;
  await act(async () => { finish({ schema_version: "v1", candidate: { ...parent, id: "detection-newly-saved" } }); });
  expect(screen.getByTestId("location").textContent).toBe(returned);
  expect(screen.getByRole("textbox", { name: "Title" })).toHaveValue(manualDefaults.title + " submitted");
  expect(save).toHaveBeenCalledTimes(1);
});

it("keeps manual inputs after save and describes the returned rule's existing state", async () => {
  const { user, remount } = setup();
  const save = vi.spyOn(api, "upsertDetection").mockResolvedValue({ schema_version: "v1", candidate: parent });
  await openManual(user);
  await user.type(screen.getByRole("textbox", { name: "Title" }), " my input");
  await user.click(screen.getByRole("button", { name: "Save rule draft" }));
  expect(await screen.findByText(/Baseline SQL saved at its parsed state/)).toBeVisible();
  expect(screen.queryByText(/It has not been parsed or exercised/)).not.toBeInTheDocument();
  expect(screen.getByRole("textbox", { name: "Title" })).toHaveValue(manualDefaults.title + " my input");
  remount();
  expect(await screen.findByRole("textbox", { name: "Title" })).toBeVisible();
  expect(screen.getByRole("textbox", { name: "Title" })).toHaveValue(manualDefaults.title + " my input");
  expect(save).toHaveBeenCalledTimes(1);
});

it("starts a full-run rule in SQLite while preserving an older manual language choice", async () => {
  const { user, remount } = setup();
  const save = vi.spyOn(api, "upsertDetection");
  await openManual(user);
  expect(screen.getByRole("combobox", { name: "Target language" })).toHaveValue("sqlite");
  expect(screen.getByRole("textbox", { name: "Title" })).toHaveValue("");
  expect(screen.getByRole("button", { name: "Save rule draft" })).toBeDisabled();
  await user.selectOptions(screen.getByRole("combobox", { name: "Target language" }), "internal");
  remount();
  expect(await screen.findByRole("combobox", { name: "Target language" })).toHaveValue("internal");
  expect(save).not.toHaveBeenCalled();
});


const starter: DetectionResource = { ...structuredClone(parent), document: { ...structuredClone(parent.document),
  behavior_id: manualDefaults.behaviorId, revision_kind: "origin", logsource: { category: "file_event", product: "generic" },
  selection: { artifact_type: "file_observation", "path|contains": "staged/" }, validation: { source_rule_executed: false },
} };
const another: DetectionResource = { ...structuredClone(starter), id: `detection-${"b".repeat(20)}`, status: "hypothesis",
  document: { ...structuredClone(starter.document), candidate_id: `detection-${"b".repeat(20)}`, parent_candidate_id: id,
    revision: 2, revision_kind: "clone", title: "Second SQL", state: "hypothesis", rule_source: null, parser_backend: {}, validation: {} } };
function conflictError(details: unknown = { existing_candidate_id: id }) {
  return new ApiError("Existing definition is immutable", "detection_revision_required", details, 409);
}
async function submitSecond(user: ReturnType<typeof userEvent.setup>) {
  await openManual(user);
  await user.type(screen.getByRole("textbox", { name: "Title" }), "Second SQL");
  await user.click(screen.getByRole("button", { name: "Save rule draft" }));
}

it("recovers a second rule title through an explicit clone while keeping the existing source and results", async () => {
  const { user, candidates } = setup();
  candidates[0] = structuredClone(starter);
  vi.spyOn(api, "upsertDetection").mockRejectedValue(conflictError());
  const read = vi.spyOn(api, "detection").mockResolvedValue({ schema_version: "v1", candidate: starter });
  const clone = vi.spyOn(api, "cloneDetection").mockImplementation(async () => { candidates.push(another); return { schema_version: "v1", candidate: another }; });
  const action = vi.spyOn(api, "detectionAction");
  await submitSecond(user);
  expect(await screen.findByRole("region", { name: "Matching saved rule" })).toHaveTextContent("Baseline SQL already uses this starter definition (Parsed)");
  const start = await screen.findByRole("button", { name: "Start another draft" });
  expect(read).toHaveBeenCalledWith(id);
  expect(clone).not.toHaveBeenCalled();
  expect(screen.getByText(/These fields describe lifecycle checks/)).toBeVisible();
  expect(screen.getByRole("textbox", { name: /sqlite source/i })).toHaveValue(source);
  await user.click(start);
  await waitFor(() => expect(new URLSearchParams(screen.getByTestId("location").textContent!).get("candidate")).toBe(another.id));
  expect(clone).toHaveBeenCalledExactlyOnceWith(id, { title: "Second SQL", reason: "Start another operator-authored draft from the same starter definition." });
  expect(await screen.findByText(/Second SQL saved as a new rule draft/)).toBeVisible();
  expect(screen.getByRole("textbox", { name: "Title" })).toHaveValue("Second SQL");
  expect(candidates[0]).toEqual(starter);
  expect(action).not.toHaveBeenCalled();
});

it("retains the exact conflict and inputs through a read failure and an explicit clone refusal then retry", async () => {
  const { user, candidates } = setup();
  vi.spyOn(api, "upsertDetection").mockRejectedValue(conflictError());
  const read = vi.spyOn(api, "detection").mockRejectedValueOnce(new Error("Rule read disconnected")).mockResolvedValue({ schema_version: "v1", candidate: starter });
  let reject!: (error: Error) => void;
  const clone = vi.spyOn(api, "cloneDetection").mockImplementationOnce(() => new Promise((_resolve, fail) => { reject = fail; }))
    .mockImplementationOnce(async () => { candidates.push(another); return { schema_version: "v1", candidate: another }; });
  await submitSecond(user);
  expect(await screen.findByText("Rule read disconnected")).toBeVisible();
  expect(screen.queryByRole("button", { name: "Start another draft" })).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Try again" }));
  await user.click(await screen.findByRole("button", { name: "Start another draft" }));
  expect(screen.getByRole("button", { name: "Start another draft" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Save rule draft" })).toBeDisabled();
  await user.click(screen.getByRole("button", { name: "Start another draft" }));
  expect(clone).toHaveBeenCalledTimes(1);
  await act(async () => reject(new Error("Clone save refused")));
  expect(await screen.findByText("Clone save refused")).toBeVisible();
  expect(screen.getByRole("textbox", { name: "Title" })).toHaveValue("Second SQL");
  await user.click(screen.getByRole("button", { name: "Start another draft" }));
  await screen.findByText(/Second SQL saved as a new rule draft/);
  expect(clone).toHaveBeenCalledTimes(2);
  expect(read).toHaveBeenCalledTimes(2);
});

it.each(["id", "document-id", "behavior", "language", "selection", "logsource", "revision"])("refuses a conflict read with a mismatched %s", async field => {
  const { user } = setup();
  vi.spyOn(api, "upsertDetection").mockRejectedValue(conflictError());
  const bad = structuredClone(starter);
  if (field === "id") bad.id = otherId;
  else if (field === "document-id") bad.document.candidate_id = otherId;
  else if (field === "behavior") bad.document.behavior_id = "unrelated.behavior.v1";
  else if (field === "language") bad.document.target_language = "sigma";
  else if (field === "selection") bad.document.selection = { artifact_type: "file_observation", "path|contains": "another/" };
  else if (field === "logsource") bad.document.logsource = { category: "file_event", product: "generic", extra: "field" };
  else bad.document.revision_kind = "clone";
  vi.spyOn(api, "detection").mockResolvedValue({ schema_version: "v1", candidate: bad });
  const clone = vi.spyOn(api, "cloneDetection");
  await submitSecond(user);
  expect(await screen.findByText(/saved rule does not match this starter definition/)).toBeVisible();
  expect(screen.queryByRole("button", { name: "Start another draft" })).not.toBeInTheDocument();
  expect(clone).not.toHaveBeenCalled();
});

it.each([{}, { existing_candidate_id: "invalid-id" }, [id]])("does not guess a matching rule from malformed conflict details %j", async details => {
  const { user } = setup();
  vi.spyOn(api, "upsertDetection").mockRejectedValue(conflictError(details));
  const read = vi.spyOn(api, "detection");
  const clone = vi.spyOn(api, "cloneDetection");
  await submitSecond(user);
  expect(await screen.findByText("Existing definition is immutable")).toBeVisible();
  expect(read).not.toHaveBeenCalled(); expect(clone).not.toHaveBeenCalled();
});

it.each(["inputs", "navigation", "remount"])("ignores a delayed matching-rule read after %s changes", async change => {
  const { user, remount } = setup();
  vi.spyOn(api, "upsertDetection").mockRejectedValue(conflictError());
  let finish!: (value: Awaited<ReturnType<typeof api.detection>>) => void;
  vi.spyOn(api, "detection").mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  const clone = vi.spyOn(api, "cloneDetection");
  await submitSecond(user);
  await screen.findByText("Loading the matching saved rule");
  if (change === "inputs") await user.type(screen.getByRole("textbox", { name: "Title" }), " newer");
  else if (change === "remount") remount();
  else { await user.click(screen.getByRole("button", { name: /Other SQL/ })); await user.click(screen.getByRole("button", { name: /Baseline SQL/ })); }
  await act(async () => finish({ schema_version: "v1", candidate: starter }));
  expect(screen.queryByRole("region", { name: "Matching saved rule" })).not.toBeInTheDocument();
  expect(clone).not.toHaveBeenCalled();
});

it.each(["inputs", "navigation", "remount"])("does not redirect or discard edits when clone finishes after %s changes", async change => {
  const { user, remount } = setup();
  vi.spyOn(api, "upsertDetection").mockRejectedValue(conflictError());
  vi.spyOn(api, "detection").mockResolvedValue({ schema_version: "v1", candidate: starter });
  let finish!: (value: Awaited<ReturnType<typeof api.cloneDetection>>) => void;
  const clone = vi.spyOn(api, "cloneDetection").mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  await submitSecond(user);
  await user.click(await screen.findByRole("button", { name: "Start another draft" }));
  if (change === "inputs") await user.type(screen.getByRole("textbox", { name: "Title" }), " newer");
  else if (change === "remount") remount();
  else { await user.click(screen.getByRole("button", { name: /Other SQL/ })); await user.click(screen.getByRole("button", { name: /Baseline SQL/ })); }
  await screen.findByRole("textbox", { name: "Title" });
  const previous = screen.getByTestId("location").textContent;
  await act(async () => finish({ schema_version: "v1", candidate: another }));
  expect(screen.getByTestId("location").textContent).toBe(previous);
  expect(screen.getByRole("textbox", { name: "Title" })).toHaveValue(change === "inputs" ? "Second SQL newer" : "Second SQL");
  expect(screen.queryByText(/Second SQL saved as a new rule draft/)).not.toBeInTheDocument();
  expect(clone).toHaveBeenCalledExactlyOnceWith(id, { title: "Second SQL", reason: "Start another operator-authored draft from the same starter definition." });
});


it.each(["inputs", "navigation", "remount"])("ignores a late conflict from Save rule draft after %s changes", async change => {
  const { user, remount } = setup();
  let reject!: (error: Error) => void;
  vi.spyOn(api, "upsertDetection").mockImplementation(() => new Promise((_resolve, fail) => { reject = fail; }));
  const read = vi.spyOn(api, "detection");
  const clone = vi.spyOn(api, "cloneDetection");
  await submitSecond(user);
  if (change === "inputs") await user.type(screen.getByRole("textbox", { name: "Title" }), " newer");
  else if (change === "remount") remount();
  else { await user.click(screen.getByRole("button", { name: /Other SQL/ })); await user.click(screen.getByRole("button", { name: /Baseline SQL/ })); }
  await act(async () => reject(conflictError()));
  expect(screen.queryByRole("region", { name: "Matching saved rule" })).not.toBeInTheDocument();
  expect(read).not.toHaveBeenCalled(); expect(clone).not.toHaveBeenCalled();
});

it("opens the matching saved rule without cloning or losing New rule inputs", async () => {
  const { user, candidates } = setup();
  candidates[0] = structuredClone(starter);
  vi.spyOn(api, "upsertDetection").mockRejectedValue(conflictError());
  vi.spyOn(api, "detection").mockResolvedValue({ schema_version: "v1", candidate: starter });
  const clone = vi.spyOn(api, "cloneDetection");
  await openManual(user);
  await user.click(screen.getByRole("button", { name: /Other SQL/ }));
  await user.type(screen.getByRole("textbox", { name: "Title" }), "Second SQL");
  await user.click(screen.getByRole("button", { name: "Save rule draft" }));
  await user.click(await screen.findByRole("button", { name: "View saved rule" }));
  await waitFor(() => expect(new URLSearchParams(screen.getByTestId("location").textContent!).get("candidate")).toBe(id));
  expect(screen.getByRole("textbox", { name: /sqlite source/i })).toHaveValue(source);
  expect(screen.getByRole("textbox", { name: "Title" })).toHaveValue("Second SQL");
  expect(clone).not.toHaveBeenCalled();
});
