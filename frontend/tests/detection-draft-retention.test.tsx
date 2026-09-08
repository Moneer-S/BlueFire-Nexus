import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Link, MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog, demoRuns } from "../src/lib/demo";
import { DetectionLabPage } from "../src/pages/DetectionLab";
import type { DetectionResource } from "../src/types";

const source = "SELECT fixture_id FROM logs WHERE observation_kind = 'filesystem'";
const edited = "SELECT fixture_id FROM logs WHERE observation_kind = 'collection_semantics'";
const id = `detection-${"a".repeat(20)}`;
const otherId = `detection-${"c".repeat(20)}`;
const parent: DetectionResource = { kind: "detections", id, status: "parsed", digest: "sha256:parent", created_at: "2026-09-06", updated_at: "2026-09-06", document: { candidate_id: id, revision_root_id: id, revision: 1, title: "Baseline SQL", target_language: "sqlite", state: "parsed", rule_source: source, selection: { observation_kind: "filesystem" }, logsource: { category: "file_event" }, parser_backend: { name: "SQLite bounded executor" } } };

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
  await user.click(screen.getByRole("radio", { name: /Tune rule behavior/ }));
  const selection = screen.getByRole("textbox", { name: /^Tuned selection JSON/ });
  await user.clear(selection); await user.paste('{"custom":"draft"}');
  const logsource = screen.getByRole("textbox", { name: /^Tuned log source JSON/ });
  await user.clear(logsource); await user.paste('{"category":"custom"}');
  await user.type(screen.getByRole("textbox", { name: "Revision title" }), " edited");
  await user.click(screen.getByRole("tab", { name: "Fixtures" }));
  const fixtures = screen.getByRole("textbox", { name: /^Malicious fixtures JSON/ });
  await user.type(fixtures, "draft fixture text");
  await user.click(screen.getByRole("button", { name: /Other SQL/ }));
  expect(screen.getByRole("textbox", { name: /sqlite source/i })).toHaveValue(source);
  await user.click(screen.getByRole("button", { name: /Baseline SQL/ }));
  expect(screen.getByRole("tab", { name: "Fixtures" })).toHaveAttribute("aria-selected", "true");
  expect(screen.getByRole("textbox", { name: /^Malicious fixtures JSON/ })).toHaveValue("draft fixture text");
  await user.click(screen.getByRole("link", { name: "Leave lab" }));
  await user.click(screen.getByRole("link", { name: "Return to lab" }));
  expect(await screen.findByRole("textbox", { name: /^Malicious fixtures JSON/ })).toHaveValue("draft fixture text");
  await user.click(screen.getByRole("tab", { name: "Revisions" }));
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
  remount();
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
