import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { FileAccessReconciliation } from "../src/components/FileAccessReconciliation";
import { checkedFileAccessReconciliation, clearFileAccessReconciliationPending, fileAccessApi, fileAccessReconciliationConfirmed, readFileAccessReconciliationPending, storeFileAccessReconciliationPending, type FileAccessReconciliationPending, type FileAccessReconciliationReceipt } from "../src/lib/file-access";
import { controlId, proposalId, testDigest } from "./composition-fixture";
import { fileAccessOperationFixture } from "./file-access-fixture";

vi.mock("../src/lib/api", () => ({ DEMO_MODE: false, request: vi.fn(), ApiError: class extends Error {} }));
const pendingFixture = (): FileAccessReconciliationPending => ({ operation_job_id: proposalId, control_owner_id: controlId, body: { submission_id: "dddddddd-dddd-dddd-dddd-dddddddddddd", expected_outcome_digest: testDigest, reviewed_by: "operator" } });
const receiptFixture = (): FileAccessReconciliationReceipt => ({ submission_id: pendingFixture().body.submission_id, submitted_request: pendingFixture().body, state: "completed", problem: null });
function mount(element: React.ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><MemoryRouter>{element}</MemoryRouter></QueryClientProvider>);
}
beforeEach(() => localStorage.clear());
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it("keeps evidence reconciliation separate from resubmitting the original effect", () => {
  const pending = pendingFixture(); storeFileAccessReconciliationPending(pending);
  expect(readFileAccessReconciliationPending()).toEqual(pending);
  expect(() => storeFileAccessReconciliationPending({ ...pending, body: { ...pending.body, expected_outcome_digest: `sha256:${"e".repeat(64)}` } })).toThrow();
  expect(fileAccessReconciliationConfirmed(receiptFixture(), pending)).toBe(true);
  const changed = receiptFixture(); changed.submitted_request.reviewed_by = "other";
  expect(fileAccessReconciliationConfirmed(changed, pending)).toBe(false);
  clearFileAccessReconciliationPending(pending); expect(readFileAccessReconciliationPending()).toBeUndefined();
});
it("requires the exact operation and reconciliation ID on the read-only lookup", () => {
  const value = { schema_version: "bluefire.file-access-reconciliation.v1" as const, operation_job_id: proposalId, receipt: receiptFixture() };
  expect(checkedFileAccessReconciliation(value, proposalId, pendingFixture().body.submission_id)).toBe(value);
  expect(() => checkedFileAccessReconciliation(value, controlId, pendingFixture().body.submission_id)).toThrow();
  expect(() => checkedFileAccessReconciliation(value, proposalId, "different")).toThrow();
});
it("opens an explicit unchecked evidence review and never reconciles on render or refresh", async () => {
  const operation = fileAccessOperationFixture(); operation.reconciliation = { outcome_digest: testDigest, state: "unknown", available: true };
  const reconcile = vi.spyOn(fileAccessApi, "reconcile").mockImplementation(async (_id, body) => ({ ...operation, reconciliation_receipt: { submission_id: body.submission_id, submitted_request: body, state: "completed", problem: { code: "still_unknown", message: "The original terminal remains unavailable." } } }));
  const effect = vi.spyOn(fileAccessApi, "submit"); const onPending = vi.fn();
  mount(<FileAccessReconciliation operation={operation} disabled={false} onPending={onPending} onError={vi.fn()} />);
  expect(reconcile).not.toHaveBeenCalled(); expect(effect).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Review original task evidence" }));
  const read = screen.getByRole("button", { name: "Read original task evidence" });
  expect(read).toBeDisabled(); expect(screen.getByRole("checkbox")).not.toBeChecked();
  fireEvent.change(screen.getByRole("textbox", { name: "Evidence review by" }), { target: { value: "operator" } });
  fireEvent.click(screen.getByRole("checkbox")); fireEvent.click(read);
  await waitFor(() => expect(reconcile).toHaveBeenCalledOnce());
  expect(reconcile.mock.calls[0]![0]).toBe(proposalId);
  expect(reconcile.mock.calls[0]![1]).toMatchObject({ expected_outcome_digest: testDigest, reviewed_by: "operator" });
  expect(effect).not.toHaveBeenCalled(); expect(onPending.mock.calls[0]![0].operation_job_id).toBe(proposalId);
});
it("reloads unknown reconciliation without automatically making a new evidence request", async () => {
  const pending = pendingFixture(); storeFileAccessReconciliationPending(pending);
  vi.spyOn(fileAccessApi, "reconciliation").mockRejectedValue(new Error("Receipt not observed"));
  const reconcile = vi.spyOn(fileAccessApi, "reconcile"); const onPending = vi.fn();
  mount(<FileAccessReconciliation pending={pending} disabled={false} onPending={onPending} onError={vi.fn()} />);
  await screen.findByText("Reconciliation receipt unavailable");
  expect(screen.getByRole("button", { name: "Resubmit original evidence request" })).toBeEnabled();
  expect(reconcile).not.toHaveBeenCalled(); expect(readFileAccessReconciliationPending()).toEqual(pending); expect(onPending).not.toHaveBeenCalled();
});
it("clears a recovered request only from its exact completed saved receipt", async () => {
  const pending = pendingFixture(); storeFileAccessReconciliationPending(pending);
  vi.spyOn(fileAccessApi, "reconciliation").mockResolvedValue({ schema_version: "bluefire.file-access-reconciliation.v1", operation_job_id: proposalId, receipt: receiptFixture() });
  const reconcile = vi.spyOn(fileAccessApi, "reconcile"); const onPending = vi.fn();
  mount(<FileAccessReconciliation pending={pending} disabled={false} onPending={onPending} onError={vi.fn()} />);
  await waitFor(() => expect(onPending).toHaveBeenCalledWith(undefined));
  expect(readFileAccessReconciliationPending()).toBeUndefined(); expect(reconcile).not.toHaveBeenCalled();
});
it("does not clear a same-ID receipt carrying another reviewed actor", async () => {
  const pending = pendingFixture(); storeFileAccessReconciliationPending(pending);
  const receipt = receiptFixture(); receipt.submitted_request.reviewed_by = "other";
  vi.spyOn(fileAccessApi, "reconciliation").mockResolvedValue({ schema_version: "bluefire.file-access-reconciliation.v1", operation_job_id: proposalId, receipt });
  const onPending = vi.fn();
  mount(<FileAccessReconciliation pending={pending} disabled={false} onPending={onPending} onError={vi.fn()} />);
  await waitFor(() => expect(fileAccessApi.reconciliation).toHaveBeenCalled());
  expect(readFileAccessReconciliationPending()).toEqual(pending); expect(onPending).not.toHaveBeenCalled();
});
