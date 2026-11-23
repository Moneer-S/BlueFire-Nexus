import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { FileAccessPage } from "../src/pages/FileAccess";
import { ExperimentAssistant } from "../src/components/ExperimentAssistant";
import { request } from "../src/lib/api";
import { fileAccessApi } from "../src/lib/file-access";
import { checkedFileAccessAssistanceContext, fileAccessAssistanceContext, fileAccessAssistanceLimitations, validFileAccessAssistanceSelection, type FileAccessAssistanceContext, type FileAccessAssistanceSelection } from "../src/lib/file-access-assistance";
import { matchesAssistanceReceipt, readAssistanceReceipt, storeAssistanceReceipt, type FileAccessAssistanceRequest } from "../src/lib/assistance";
import { AssistanceProvider, useAssistancePanel, useAssistanceSelection } from "../src/state/AssistanceContext";
import { ProductProvider } from "../src/state/ProductContext";
import { controlId, testDigest } from "./composition-fixture";
import { fileAccessControlFixture, fileAccessStatusFixture } from "./file-access-fixture";
import { receiverAssistantProvider as provider } from "./receiver-assistance-fixture";

vi.mock("../src/lib/api", () => ({ DEMO_MODE: false, request: vi.fn(), ApiError: class extends Error {} }));
const selected: FileAccessAssistanceSelection = { kind: "file_access_control", control_owner_id: controlId, control_revision: 3, control_digest: testDigest };
function context(): FileAccessAssistanceContext {
  return {
    schema_version: "bluefire.assistance-context.v1", selected, context_digest: testDigest, analysis_only: true, capabilities: [],
    limitations: [...fileAccessAssistanceLimitations],
    reference_summary: {
      schema_version: "bluefire.file-access-assistance-summary.v1", platform: "linux", control_status: "hardened",
      baseline: { recorded: true, non_owner: "allowed", owner: "allowed" },
      protection: { kind: "posix_mode", value: "0600", effective_access_proven: false },
      fresh_result: { recorded: false }, latest_operation: null, task_access: { usage_state: "settled" }, readiness: "not_assessed",
    },
  };
}
function SelectionProbe() {
  const selection = useAssistanceSelection();
  const panel = useAssistancePanel();
  return <><output aria-label="Published selection">{selection && "kind" in selection && selection.kind === "file_access" ? JSON.stringify(selection.selected) : "none"}</output><output aria-label="Assistant open">{String(panel?.open)}</output></>;
}
function mount(path: string, withAssistant = false) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } } });
  return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><ProductProvider><AssistanceProvider><FileAccessPage /><SelectionProbe />{withAssistant ? <ExperimentAssistant providers={[provider]} /> : null}</AssistanceProvider></ProductProvider></MemoryRouter></QueryClientProvider>);
}
afterEach(() => vi.restoreAllMocks());

it("validates the exact saved control binding and analysis-only bounded summary", () => {
  const response = context();
  expect(validFileAccessAssistanceSelection(selected)).toBe(true);
  expect(checkedFileAccessAssistanceContext(response, selected)).toBe(response);
  expect(() => checkedFileAccessAssistanceContext({ ...response, selected: { ...selected, control_revision: 2 } }, selected)).toThrow();
  expect(() => checkedFileAccessAssistanceContext({ ...response, capabilities: [{ id: "file_access.change" }] }, selected)).toThrow();
  expect(() => checkedFileAccessAssistanceContext({ ...response, limitations: [] }, selected)).toThrow();
  expect(() => checkedFileAccessAssistanceContext({ ...response, reference_summary: { ...response.reference_summary, protection: { ...response.reference_summary.protection, effective_access_proven: true } } }, selected)).toThrow();
  expect(() => checkedFileAccessAssistanceContext({ ...response, reference_summary: { ...response.reference_summary, fresh_result: { recorded: true, operation: "baseline", non_owner: "permission_denied", owner: "allowed", source: "verified_saved_task_observation", independent_observation: false } } }, selected)).toThrow();
  expect(() => checkedFileAccessAssistanceContext({ ...response, reference_summary: { ...response.reference_summary, task_access: { usage_state: "unresolved" } } }, selected)).toThrow();
  expect(validFileAccessAssistanceSelection({ ...selected, control_digest: "sha256:bad" })).toBe(false);
});

it("accepts the Windows paired-read summary and rejects cross-platform fact combinations", () => {
  const windowsSelection: FileAccessAssistanceSelection = { kind: "file_access_control", control_owner_id: "win-file-control-0123456789abcdef0123456789abcdef", control_revision: 3, control_digest: testDigest };
  const windows: FileAccessAssistanceContext = {
    ...context(), selected: windowsSelection,
    reference_summary: {
      schema_version: "bluefire.file-access-assistance-summary.v1", platform: "windows", control_status: "hardened",
      baseline: { recorded: true, non_owner: "allowed", owner: "allowed" },
      protection: { kind: "windows_metadata", value: "metadata_only", effective_access_proven: false },
      fresh_result: { recorded: true, operation: "harden", non_owner: "data_access_denied", owner: "allowed", source: "verified_saved_paired_read", independent_observation: false },
      latest_operation: null, task_access: { usage_state: "settled" }, readiness: "not_assessed",
    },
  };
  expect(checkedFileAccessAssistanceContext(windows, windowsSelection)).toBe(windows);
  expect(() => checkedFileAccessAssistanceContext({ ...windows, reference_summary: { ...windows.reference_summary, protection: { kind: "posix_mode", value: "0600", effective_access_proven: false } } }, windowsSelection)).toThrow();
  expect(() => checkedFileAccessAssistanceContext({ ...windows, reference_summary: { ...windows.reference_summary, task_access: { usage_state: "pending" } } }, windowsSelection)).toThrow();
  expect(() => checkedFileAccessAssistanceContext({ ...windows, reference_summary: { ...windows.reference_summary, fresh_result: { recorded: true, operation: "harden", non_owner: "allowed", owner: "allowed", source: "verified_saved_task_observation", independent_observation: false } } }, windowsSelection)).toThrow();
});

it("fetches context only for the exact saved owner and checks the returned binding", async () => {
  vi.mocked(request).mockResolvedValue(context());
  await expect(fileAccessAssistanceContext(selected)).resolves.toMatchObject({ selected, analysis_only: true, capabilities: [] });
  expect(request).toHaveBeenCalledWith(`/file-access/controls/${encodeURIComponent(controlId)}/assistant-context`);
  vi.mocked(request).mockResolvedValue({ ...context(), selected: { ...selected, control_digest: "sha256:" + "f".repeat(64) } });
  await expect(fileAccessAssistanceContext(selected)).rejects.toThrow(/context changed/);
});

it("retains and matches a read-only request against its exact empty-plan result", () => {
  const requestBody: FileAccessAssistanceRequest = { submission_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", context_digest: testDigest, selection: selected, message: "Explain the saved control evidence.", autonomy: "assist", provider_id: "test-provider" };
  expect(storeAssistanceReceipt(requestBody)).toBe(true);
  expect(readAssistanceReceipt()).toEqual(requestBody);
  const envelope = {
    job: { job_id: "job-aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa", kind: "assistance.turn", request: { submitted_request: requestBody } },
    turn: { schema_version: "bluefire.assistance-turn.v1", context_digest: testDigest, selected, plan: [], active_child: null, results: [] },
  };
  expect(matchesAssistanceReceipt(envelope as never, requestBody)).toBe(true);
  expect(matchesAssistanceReceipt({ ...envelope, turn: { ...envelope.turn, plan: [{ step_id: "file-write" }] } } as never, requestBody)).toBe(false);
});

it("publishes one exact selection only for a loaded saved control and opens Assistant from its entry", async () => {
  vi.spyOn(fileAccessApi, "status").mockResolvedValue(fileAccessStatusFixture());
  vi.spyOn(fileAccessApi, "list").mockResolvedValue({ schema_version: "bluefire.file-access-control-list.v1", controls: [] });
  vi.spyOn(fileAccessApi, "control").mockResolvedValue(fileAccessControlFixture());
  vi.spyOn(fileAccessApi, "operation").mockRejectedValue(new Error("No operation"));
  mount(`/file-access?control=${controlId}`);
  expect(await screen.findByRole("button", { name: "Explain saved control" })).toBeVisible();
  expect(JSON.parse(screen.getByLabelText("Published selection").textContent ?? "null")).toEqual(selected);
  fireEvent.click(screen.getByRole("button", { name: "Explain saved control" }));
  expect(screen.getByLabelText("Assistant open")).toHaveTextContent("true");
  expect(fileAccessApi.operation).not.toHaveBeenCalled();
});

it("uses the shared explanation-only Assistant without Detection controls or proposed actions", async () => {
  vi.spyOn(fileAccessApi, "status").mockResolvedValue(fileAccessStatusFixture());
  vi.spyOn(fileAccessApi, "list").mockResolvedValue({ schema_version: "bluefire.file-access-control-list.v1", controls: [] });
  vi.spyOn(fileAccessApi, "control").mockResolvedValue(fileAccessControlFixture());
  vi.spyOn(fileAccessApi, "operation").mockRejectedValue(new Error("No operation"));
  vi.mocked(request).mockResolvedValue(context());
  mount(`/file-access?control=${controlId}`, true);
  fireEvent.click(await screen.findByRole("button", { name: "Explain saved control" }));
  expect(await screen.findByText("Explanation scope and evidence limits")).toBeInTheDocument();
  expect(screen.getByText("Saved file-access evidence")).toBeInTheDocument();
  expect(screen.queryByLabelText("Development activity")).not.toBeInTheDocument();
  expect(screen.queryByRole("region", { name: "Suggested requests" })).not.toBeInTheDocument();
  expect(fileAccessApi.operation).not.toHaveBeenCalled();
});

it("does not publish an Assistant selection or entry on the initial page without a saved control", async () => {
  vi.spyOn(fileAccessApi, "status").mockResolvedValue(fileAccessStatusFixture());
  vi.spyOn(fileAccessApi, "list").mockResolvedValue({ schema_version: "bluefire.file-access-control-list.v1", controls: [] });
  mount("/file-access");
  expect(await screen.findByRole("heading", { name: /Prepare task access/ })).toBeVisible();
  expect(screen.getByLabelText("Published selection")).toHaveTextContent("none");
  expect(screen.queryByRole("button", { name: "Explain saved control" })).not.toBeInTheDocument();
});

it("does not publish stale control data after the selected control refresh fails", async () => {
  vi.spyOn(fileAccessApi, "status").mockResolvedValue(fileAccessStatusFixture());
  vi.spyOn(fileAccessApi, "list").mockResolvedValue({ schema_version: "bluefire.file-access-control-list.v1", controls: [] });
  vi.spyOn(fileAccessApi, "control").mockRejectedValue(new Error("Saved control is unavailable"));
  mount(`/file-access?control=${controlId}`);
  expect(await screen.findByText("Retained control unavailable")).toBeVisible();
  expect(screen.getByLabelText("Published selection")).toHaveTextContent("none");
  expect(screen.queryByRole("button", { name: "Explain saved control" })).not.toBeInTheDocument();
});
