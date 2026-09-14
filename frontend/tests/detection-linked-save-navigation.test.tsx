import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation, useNavigate } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog, demoRuns } from "../src/lib/demo";
import { DetectionLabPage } from "../src/pages/DetectionLab";
import type { DetectionResource } from "../src/types";

const run = { ...structuredClone(demoRuns[0]!), is_demo: false, detections: { candidates: [{ candidate_id: "linked-rule", title: "Run hypothesis", behavior_id: "sandbox.collection.stage.v1", state: "hypothesis", target_language: "sqlite", selection: { observation_kind: "filesystem" }, logsource: { category: "file_event" } }] } };
const saved: DetectionResource = { kind: "detections", id: "detection-aaaaaaaaaaaaaaaaaaaa", status: "hypothesis", digest: "sha256:saved", created_at: "2026-09-09", updated_at: "2026-09-09", document: { ...run.detections.candidates[0]!, candidate_id: "detection-aaaaaaaaaaaaaaaaaaaa", title: "Saved hypothesis" } };
const other = { ...saved, id: "detection-bbbbbbbbbbbbbbbbbbbb", document: { ...saved.document, candidate_id: "detection-bbbbbbbbbbbbbbbbbbbb", title: "Other rule" } };
const arrival = `/detection-lab?run=${run.run_id}&candidate=linked-rule`;
function Navigation() { const location = useLocation(); const navigate = useNavigate(); return <><output data-testid="location">{location.search}</output><button onClick={() => navigate(arrival)}>Return to original source</button></>; }
function mount() {
  const candidates: DetectionResource[] = [other];
  vi.spyOn(api, "detections").mockImplementation(async () => ({ schema_version: "v1", candidates }));
  vi.spyOn(api, "runs").mockResolvedValue({ schema_version: "v1", unavailable_run_count: 0, runs: [run] });
  vi.spyOn(api, "runDetail").mockResolvedValue(run);
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  vi.spyOn(api, "resources").mockResolvedValue({ schema_version: "v1", kind: "research-sources", resources: [] });
  vi.spyOn(api, "detectionHealth").mockResolvedValue({ schema_version: "v1", ready: true, persistence_ready: true, candidate_resources: 1, invalid_candidate_resources: 0, languages: {}, limits: { source_bytes: 262144, fixture_bytes: 1048576, fixtures_per_action: 128, evidence_per_action: 256, notes_per_action: 64 } });
  vi.spyOn(api, "detectionRunEvaluations").mockResolvedValue({ evaluations: [] });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[arrival]}><DetectionLabPage/><Navigation/></MemoryRouter></QueryClientProvider>);
  return { user: userEvent.setup(), candidates };
}
it.each(["candidate", "source", "return", "unchanged"])("binds run-linked save completion to its navigation: %s", async (navigation) => {
  let finish!: (value: Awaited<ReturnType<typeof api.detectionFromRun>>) => void;
  const save = vi.spyOn(api, "detectionFromRun").mockReturnValue(new Promise(resolve => { finish = resolve; }));
  const { user, candidates } = mount();
  await user.click(await screen.findByRole("button", { name: "Save hypothesis from run" }));
  expect(save).toHaveBeenCalledExactlyOnceWith(run.run_id, "linked-rule");
  if (navigation === "candidate" || navigation === "return") await user.click(screen.getByRole("button", { name: /Other rule/ }));
  if (navigation === "source") await user.selectOptions(screen.getByRole("combobox", { name: /Detection source run/ }), "");
  if (navigation === "return") await user.click(screen.getByRole("button", { name: "Return to original source" }));
  const before = screen.getByTestId("location").textContent;
  await act(async () => { candidates.push(saved); finish({ schema_version: "v1", candidate: saved, operation: "created", source_run_id: run.run_id, source_candidate_id: "linked-rule" }); });
  await waitFor(() => expect(api.detections).toHaveBeenCalledTimes(2));
  if (navigation === "unchanged") {
    await waitFor(() => expect(new URLSearchParams(screen.getByTestId("location").textContent!).get("candidate")).toBe(saved.id));
    expect(screen.getByRole("heading", { name: "Saved hypothesis" })).toBeVisible();
  } else {
    expect(screen.getByTestId("location").textContent).toBe(before);
    expect(screen.queryByText(/created in hypothesis state/)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Saved hypothesis/ })).toBeVisible();
  }
});
it("does not paint an earlier run-linked save refusal over another rule", async () => {
  let refuse!: (error: Error) => void;
  vi.spyOn(api, "detectionFromRun").mockReturnValue(new Promise((_resolve, reject) => { refuse = reject; }));
  const { user } = mount();
  await user.click(await screen.findByRole("button", { name: "Save hypothesis from run" }));
  await user.click(screen.getByRole("button", { name: /Other rule/ }));
  await act(async () => refuse(new Error("Earlier save refused")));
  expect(screen.getByRole("heading", { name: "Other rule" })).toBeVisible();
  expect(screen.queryByText("Earlier save refused")).not.toBeInTheDocument();
});
