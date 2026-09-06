import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog, demoRuns } from "../src/lib/demo";
import { DetectionLabPage } from "../src/pages/DetectionLab";
import type { DetectionResource, DetectionResourceEnvelope } from "../src/types";

const source = "SELECT fixture_id FROM logs WHERE observation_kind = 'filesystem'";
const edited = "SELECT fixture_id FROM logs WHERE observation_kind = 'collection_semantics'";
const id = `detection-${"a".repeat(20)}`;
const otherId = `detection-${"c".repeat(20)}`;
const parent: DetectionResource = { kind: "detections", id, status: "parsed", digest: "sha256:parent", created_at: "2026-09-06", updated_at: "2026-09-06", document: { candidate_id: id, revision_root_id: id, revision: 1, title: "Baseline SQL", target_language: "sqlite", state: "parsed", rule_source: source, selection: { observation_kind: "filesystem" }, logsource: { category: "file_event" }, parser_backend: { name: "SQLite bounded executor" } } };
const child: DetectionResource = { ...structuredClone(parent), id: `detection-${"b".repeat(20)}`, document: { ...structuredClone(parent.document), candidate_id: `detection-${"b".repeat(20)}`, parent_candidate_id: id, revision: 2, revision_kind: "source", rule_source: edited } };

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
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/detection-lab?run=${demoRuns[0]!.run_id}&candidate=${id}&candidate_scope=registry${aiJob ? "&ai_job=job-review-retained" : ""}`]}><DetectionLabPage /><LocationWitness /></MemoryRouter></QueryClientProvider>);
  return { user: userEvent.setup(), candidates };
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

it("edits SQL directly, saves a parsed child and opens the selected run without fixture or metadata input", async () => {
  const { user, candidates } = setup(true, true);
  const revise = vi.spyOn(api, "reviseDetectionSource").mockImplementation(async () => { candidates.push(child); return { schema_version: "v1", candidate: child }; });
  const action = vi.spyOn(api, "detectionAction");
  await edit(user);
  expect(screen.queryByRole("textbox", { name: /Selection JSON|Log source JSON|Malicious fixtures JSON/ })).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Validate and save new revision" }));
  await waitFor(() => expect(screen.getByRole("textbox", { name: /sqlite source/i })).toHaveValue(edited));
  expect(await screen.findByText(/Revision 2 validated and saved/)).toBeVisible();
  await waitFor(() => expect(new URLSearchParams(screen.getByTestId("location").textContent!).get("candidate")).toBe(child.id));
  const savedLink = new URLSearchParams(screen.getByTestId("location").textContent!);
  expect(savedLink.get("candidate_scope")).toBe("registry");
  expect(savedLink.get("run")).toBe(demoRuns[0]!.run_id);
  expect(savedLink.get("ai_job")).toBe("job-review-retained");
  expect(revise).toHaveBeenCalledWith(id, { source: edited, reason: "Inspect contents observations" });
  expect(candidates[0]).toEqual(parent);
  expect(action).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Evaluate actual runs" }));
  expect(screen.getByRole("combobox", { name: "Evaluation source run" })).toHaveValue(demoRuns[0]!.run_id);
  expect(screen.getByRole("button", { name: "Evaluate full observed run" })).toBeEnabled();
  await user.click(screen.getByRole("tab", { name: "Revisions" }));
  expect(screen.getByText(/Revision 2 · Source/, { selector: "strong" })).toBeVisible();
  expect(screen.getByText(/Clone copies the structured definition into an unparsed hypothesis/)).toBeVisible();
});

it("preserves the detection job when changing the selected source run", async () => {
  const { user } = setup(true, true);
  await screen.findByRole("heading", { name: "Baseline SQL" });
  await user.selectOptions(screen.getByRole("combobox", { name: /Detection source run/ }), "");
  const query = new URLSearchParams(screen.getByTestId("location").textContent!);
  expect(query.get("ai_job")).toBe("job-review-retained");
  expect(query.has("run")).toBe(false);
  expect(await screen.findByRole("region", { name: "Detection assistance" })).toBeVisible();
});

it("keeps the selected registry rule and unsaved source when choosing different evidence", async () => {
  const { user } = setup(true, true);
  await user.click(await screen.findByRole("button", { name: /Other SQL/ }));
  await edit(user);
  await user.selectOptions(screen.getByRole("combobox", { name: /Detection source run/ }), "");
  expect(screen.getByRole("heading", { name: "Other SQL" })).toBeVisible();
  expect(screen.getByRole("textbox", { name: /sqlite source/i })).toHaveValue(edited);
  const query = new URLSearchParams(screen.getByTestId("location").textContent!);
  expect(query.get("candidate")).toBe(otherId);
  expect(query.get("candidate_scope")).toBe("registry");
  expect(query.get("ai_job")).toBe("job-review-retained");
});

it("offers an editable SQLite starter without claiming validation or sending it automatically", async () => {
  const { user } = setup(true, false, true);
  const action = vi.spyOn(api, "detectionAction");
  const editor = await screen.findByRole("textbox", { name: /sqlite source/i });
  expect(editor).toHaveValue("");
  expect(screen.getByText(/example has not been validated or evaluated/)).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Insert SQLite starter" }));
  expect(editor).toHaveValue("SELECT fixture_id FROM logs\nWHERE artifact_type = 'file_observation'\n  AND path LIKE '%staged/%'");
  await user.type(editor, "{End}{Enter}LIMIT 1");
  expect(editor).toHaveValue("SELECT fixture_id FROM logs\nWHERE artifact_type = 'file_observation'\n  AND path LIKE '%staged/%'\nLIMIT 1");
  expect(screen.getByText("Draft source not validated")).toBeVisible();
  expect(screen.getByRole("button", { name: "Parse / compile honestly" })).toBeEnabled();
  expect(action).not.toHaveBeenCalled();
});

it.each(["success", "error"])("does not replace another selected detector when a pending source save returns %s", async (outcome) => {
  let resolve!: (value: DetectionResourceEnvelope) => void;
  let reject!: (reason: Error) => void;
  const pending = new Promise<DetectionResourceEnvelope>((yes, no) => { resolve = yes; reject = no; });
  const { user, candidates } = setup();
  vi.spyOn(api, "reviseDetectionSource").mockReturnValue(pending);
  await edit(user);
  await user.click(screen.getByRole("button", { name: "Validate and save new revision" }));
  expect(screen.getByRole("textbox", { name: /sqlite source/i })).toBeDisabled();
  await user.click(screen.getByRole("button", { name: /Other SQL/ }));
  await act(async () => {
    if (outcome === "success") { candidates.push(child); resolve({ schema_version: "v1", candidate: child }); }
    else reject(new Error("Old source request refused"));
  });
  expect(screen.getByRole("heading", { name: "Other SQL" })).toBeVisible();
  expect(screen.getByRole("textbox", { name: /sqlite source/i })).toHaveValue(source);
  expect(screen.queryByText(/Revision 2 validated and saved|Old source request refused/)).not.toBeInTheDocument();
});

it("visibly refuses an unavailable backend", async () => {
  const { user } = setup(false);
  const revise = vi.spyOn(api, "reviseDetectionSource");
  await edit(user);
  expect(screen.getByText("Query backend unavailable")).toBeVisible();
  expect(screen.getByRole("button", { name: "Validate and save new revision" })).toBeDisabled();
  expect(revise).not.toHaveBeenCalled();
});

it("preserves the edited source and selected parent after validation is refused", async () => {
  const { user, candidates } = setup();
  vi.spyOn(api, "reviseDetectionSource").mockRejectedValue(new Error("Edited source did not validate; no revision was saved."));
  await edit(user);
  await user.click(screen.getByRole("button", { name: "Validate and save new revision" }));
  expect(await screen.findByText(/Edited source did not validate/)).toBeVisible();
  expect(screen.getByRole("textbox", { name: /sqlite source/i })).toHaveValue(edited);
  expect(screen.getByRole("heading", { name: "Baseline SQL" })).toBeVisible();
  expect(screen.getByText("Draft source not validated")).toBeVisible();
  expect(candidates).toHaveLength(2);
  expect(candidates[0]).toEqual(parent);
});
