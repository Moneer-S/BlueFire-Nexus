import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog } from "../src/lib/demo";
import { detectionJobId, readDetectionAIReceipt, storeDetectionAIReceipt, type DetectionAIReceipt } from "../src/lib/detection-ai";
import { DetectionLabPage } from "../src/pages/DetectionLab";

function mount(path = "/detection-lab") {
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  vi.spyOn(api, "runs").mockResolvedValue({ schema_version: "v1", unavailable_run_count: 0, runs: [] });
  vi.spyOn(api, "detections").mockResolvedValue({ schema_version: "v1", candidates: [] });
  vi.spyOn(api, "resources").mockResolvedValue({ schema_version: "v1", kind: "research-sources", resources: [] });
  vi.spyOn(api, "detectionHealth").mockResolvedValue({ schema_version: "v1", ready: true, persistence_ready: true, candidate_resources: 0, invalid_candidate_resources: 0,
    languages: { sqlite: { ready: true, authoritative: true, backend: "SQLite bounded executor" } },
    limits: { source_bytes: 262144, fixture_bytes: 1048576, fixtures_per_action: 128, evidence_per_action: 256, notes_per_action: 64 } });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><DetectionLabPage /></MemoryRouter></QueryClientProvider>);
}

it("keeps an empty registry focused on a clear creation action without an unrelated AI form", async () => {
  const user = userEvent.setup();
  const save = vi.spyOn(api, "upsertDetection");
  const send = vi.spyOn(api, "suggestDetectionRevision");
  const job = vi.spyOn(api, "job");
  mount();
  const create = await screen.findByRole("button", { name: "New detection" });
  expect(create).toHaveAttribute("aria-expanded", "false");
  expect(screen.getByRole("textbox", { name: "Title" })).not.toBeVisible();
  expect(screen.queryByRole("region", { name: "Detection assistance" })).not.toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Create from run evidence" })).toBeVisible();
  await user.click(create);
  const title = screen.getByRole("textbox", { name: "Title" });
  await user.click(title); await user.paste("Collection behavior draft");
  const retained = sessionStorage.getItem("bluefire.detection-draft.v1:manual-new-rule");
  await user.click(screen.getByText("New rule", { selector: "summary" }));
  expect(create).toHaveAttribute("aria-expanded", "false");
  expect(screen.getByText("Draft kept · Collection behavior draft")).toBeVisible();
  expect(title).not.toBeVisible();
  expect(sessionStorage.getItem("bluefire.detection-draft.v1:manual-new-rule")).toBe(retained);
  await user.click(create);
  expect(screen.getByRole("textbox", { name: "Title" })).toHaveValue("Collection behavior draft");
  expect(save).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled(); expect(job).not.toHaveBeenCalled();
});

it("keeps an explicit AI job reachable without a selected rule", async () => {
  vi.spyOn(api, "job").mockResolvedValue({ schema_version: "bluefire.job.v1", job_id: "job-unselected-review", kind: "detection.ai.propose", state: "interrupted", request: {}, progress: {} });
  const send = vi.spyOn(api, "suggestDetectionRevision");
  mount("/detection-lab?ai_job=job-unselected-review");
  expect(await screen.findByRole("button", { name: "Retry interrupted work" })).toBeVisible();
  expect(screen.getByRole("region", { name: "Detection assistance" })).toBeVisible();
  expect(screen.queryByRole("button", { name: "Propose rule revision" })).not.toBeInTheDocument();
  expect(send).not.toHaveBeenCalled();
});

it("retains and exposes pending-request recovery when its original rule is unavailable", async () => {
  const user = userEvent.setup();
  const receipt: DetectionAIReceipt = { candidateId: "detection-missing-rule", request: {
    submission_id: "01234567-89ab-4def-8123-456789abcdef", run_id: "run-original", parent_resource_digest: `sha256:${"a".repeat(64)}`,
    question: "Review the selected collection evidence", case_role: "attack", provider_id: "test-provider", autonomy: "assist",
  } };
  expect(storeDetectionAIReceipt(receipt)).toBe(true);
  const job = vi.spyOn(api, "job").mockRejectedValue(new Error("The original request is not stored yet."));
  const send = vi.spyOn(api, "suggestDetectionRevision");
  mount();
  await user.click(await screen.findByRole("button", { name: "Resume AI work" }));
  expect(await screen.findByRole("button", { name: "Retry original request" })).toBeVisible();
  expect(job).toHaveBeenCalledWith(detectionJobId(receipt.request.submission_id));
  expect(readDetectionAIReceipt()).toEqual(receipt);
  expect(screen.queryByRole("button", { name: "Propose rule revision" })).not.toBeInTheDocument();
  expect(send).not.toHaveBeenCalled();
});
