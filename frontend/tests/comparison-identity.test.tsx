import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { ComparePage } from "../src/pages/Compare";
import { DetectionLabPage } from "../src/pages/DetectionLab";
import { api } from "../src/lib/api";
import { compareDemoRuns, demoCatalog, demoRuns } from "../src/lib/demo";
import type { ComparisonResponse, DetectionResource } from "../src/types";

function mount(path: string, page: React.ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}>{page}</MemoryRouter></QueryClientProvider>);
}
function baseMocks() {
  vi.spyOn(api, "runs").mockResolvedValue({ schema_version: "v1", runs: demoRuns, unavailable_run_count: 0 });
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  vi.spyOn(api, "runDetail").mockImplementation(async (id) => demoRuns.find((run) => run.run_id === id)!);
  vi.spyOn(api, "detections").mockResolvedValue({ schema_version: "v1", candidates: [] });
}
afterEach(() => { vi.restoreAllMocks(); });

it.each(["selection", "navigation"])("discards a late comparison after %s changes and never exposes its detector export", async (change) => {
  const user = userEvent.setup();
  baseMocks();
  let finish!: (value: ComparisonResponse) => void;
  const pending = new Promise<ComparisonResponse>((resolve) => { finish = resolve; });
  const compare = vi.spyOn(api, "compare").mockReturnValue(pending);
  mount("/compare", <ComparePage />);
  await screen.findByRole("heading", { name: "Measure what changed" });
  const boxes = screen.getAllByRole("checkbox");
  await user.click(boxes[0]!);
  await user.click(boxes[1]!);
  await user.click(screen.getByRole("button", { name: "Compare selected" }));
  expect(compare).toHaveBeenCalledWith([demoRuns[0]!.run_id, demoRuns[1]!.run_id]);
  if (change === "selection") await user.click(boxes[0]!);
  else await user.selectOptions(screen.getByRole("combobox", { name: "Source run" }), demoRuns[1]!.run_id);
  await act(async () => { finish(compareDemoRuns(demoRuns.map((run) => run.run_id))); await pending; });
  await waitFor(() => expect(screen.getByRole("button", { name: "Compare selected" })).toBeDisabled());
  expect(screen.queryByRole("heading", { name: "Compare detector results" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Export comparison and evidence" })).not.toBeInTheDocument();
  expect(screen.getByText("Select at least two runs")).toBeInTheDocument();
});

it("reports a comparison whose returned run identities do not match the request", async () => {
  const user = userEvent.setup();
  baseMocks();
  vi.spyOn(api, "compare").mockResolvedValue(compareDemoRuns([demoRuns[1]!.run_id, demoRuns[0]!.run_id]));
  mount("/compare", <ComparePage />);
  await screen.findByRole("heading", { name: "Measure what changed" });
  for (const box of screen.getAllByRole("checkbox")) await user.click(box);
  await user.click(screen.getByRole("button", { name: "Compare selected" }));
  expect(await screen.findByText(/returned comparison does not match/)).toBeInTheDocument();
  expect(screen.queryByRole("heading", { name: "Compare detector results" })).not.toBeInTheDocument();
});

it.each(["available", "missing"])("resolves an explicit %s detector link without selecting another definition", async (state) => {
  baseMocks();
  const candidateId = "detection-aaaaaaaaaaaaaaaaaaaa";
  const candidate: DetectionResource = { kind: "detections", id: candidateId, status: "parsed", digest: "sha256:abc", created_at: "2026-09-06", updated_at: "2026-09-06", document: { candidate_id: candidateId, title: "Saved query revision", state: "parsed", target_language: "sqlite", revision: 2, rule_source: "SELECT fixture_id FROM logs" } };
  vi.mocked(api.detections).mockResolvedValue({ schema_version: "v1", candidates: [candidate] });
  vi.spyOn(api, "detectionHealth").mockResolvedValue({ schema_version: "v1", ready: true, persistence_ready: true, candidate_resources: 1, invalid_candidate_resources: 0, languages: { sqlite: { ready: true, authoritative: true, backend: "SQLite", version: "3.45.1" } }, limits: { source_bytes: 32768, fixture_bytes: 1048576, fixtures_per_action: 128, evidence_per_action: 128, notes_per_action: 128 } });
  vi.spyOn(api, "resources").mockResolvedValue({ schema_version: "v1", kind: "research-sources", resources: [] });
  const requested = state === "available" ? candidateId : "detection-bbbbbbbbbbbbbbbbbbbb";
  mount(`/detection-lab?run=${demoRuns[0]!.run_id}&candidate=${requested}`, <DetectionLabPage />);
  if (state === "available") expect(await screen.findByRole("heading", { name: "Saved query revision" })).toBeInTheDocument();
  else {
    expect(await screen.findByText("Detector unavailable")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Saved query revision" })).not.toBeInTheDocument();
  }
});
