import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, useLocation } from "react-router-dom";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { FileAccessPage } from "../src/pages/FileAccess";
import { MACOS_FILE_ACCESS_PACK } from "../src/lib/composition";
import { fileAccessApi, readFileAccessPending, readFileAccessReconciliationPending, storeFileAccessPending, storeFileAccessReconciliationPending, type FileAccessOperationEnvelope, type FileAccessSubmission } from "../src/lib/file-access";
import { macOSControlFixture, macOSDigest, macOSOperationFixture, macOSOwner, macOSReviewFixture, macOSStatusFixture } from "./macos-file-access-fixture";
import { fileAccessControlFixture, fileAccessOperationFixture, fileAccessReviewFixture, fileAccessStatusFixture, fileAccessSubmissionFixture } from "./file-access-fixture";

vi.mock("../src/lib/api", () => ({ DEMO_MODE: false, request: vi.fn(), ApiError: class extends Error {} }));

function CurrentLocation() { const location = useLocation(); return <output data-testid="current-location">{location.pathname}{location.search}</output>; }

function mount(path = `/file-access?control=${macOSOwner}`, trackLocation = false) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><FileAccessPage />{trackLocation ? <CurrentLocation /> : null}</MemoryRouter></QueryClientProvider>);
}

beforeEach(() => {
  localStorage.clear();
  vi.spyOn(fileAccessApi, "status").mockResolvedValue(macOSStatusFixture());
  vi.spyOn(fileAccessApi, "list").mockResolvedValue({ schema_version: "bluefire.file-access-control-list.v1", controls: [{ platform: "macos", control_owner_id: macOSOwner, status: "created", revision: 1 }] });
  vi.spyOn(fileAccessApi, "control").mockResolvedValue(macOSControlFixture());
  vi.spyOn(fileAccessApi, "operation").mockRejectedValue(new Error("No saved operation response"));
  vi.spyOn(fileAccessApi, "review").mockImplementation(async request => macOSReviewFixture(request.operation as "baseline" | "harden" | "rollback"));
  vi.spyOn(fileAccessApi, "submit").mockRejectedValue(new Error("Unexpected submission"));
  vi.spyOn(fileAccessApi, "importSetup").mockResolvedValue(macOSControlFixture());
  vi.spyOn(fileAccessApi, "reconcile").mockRejectedValue(new Error("Reconciliation unavailable"));
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it("preserves objective context when opening read-only macOS operation history", async () => {
  const control = macOSControlFixture("uncertain");
  vi.mocked(fileAccessApi.status).mockResolvedValue(macOSStatusFixture(false));
  vi.mocked(fileAccessApi.control).mockResolvedValue(control);
  mount(`/file-access?goal=file-access&context=retained&source=original&keep=1&control=${macOSOwner}&operation=other-operation`, true);

  await screen.findByText("Workspace custody is unresolved");
  const link = screen.getByRole("link", { name: /Operation 1: Verify baseline access/ });
  fireEvent.click(link);
  await waitFor(() => {
    const location = new URL(screen.getByTestId("current-location").textContent!, "http://local.test");
    expect(location.pathname).toBe("/file-access");
    expect(location.searchParams.get("goal")).toBe("file-access");
    expect(location.searchParams.get("context")).toBe("retained");
    expect(location.searchParams.get("source")).toBe("original");
    expect(location.searchParams.get("keep")).toBe("1");
    expect(location.searchParams.get("control")).toBe(macOSOwner);
    expect(location.searchParams.get("operation")).toBe(control.operations[0]!.job_id);
  });
  expect(screen.getByRole("complementary", { name: "Selected objective" })).toBeInTheDocument();
  expect(within(screen.getByRole("region", { name: "Saved macOS workspace control" })).queryByRole("button")).not.toBeInTheDocument();
  expect(fileAccessApi.review).not.toHaveBeenCalled();
  expect(fileAccessApi.submit).not.toHaveBeenCalled();
  expect(fileAccessApi.reconcile).not.toHaveBeenCalled();
});

it("preserves objective context when opening read-only reconciliation under macOS status", async () => {
  const operation = fileAccessOperationFixture();
  operation.job.state = "interrupted";
  operation.reconciliation = { outcome_digest: macOSDigest(), state: "unknown", available: true };
  const pending = { operation_job_id: operation.job.job_id, control_owner_id: operation.control!.control_owner_id, body: { submission_id: "44444444-4444-4444-8444-444444444444", expected_outcome_digest: macOSDigest(), reviewed_by: "synthetic-reviewer" } };
  storeFileAccessReconciliationPending(pending);
  vi.mocked(fileAccessApi.control).mockResolvedValue(fileAccessControlFixture());
  vi.mocked(fileAccessApi.operation).mockResolvedValue(operation);
  const receipt = vi.spyOn(fileAccessApi, "reconciliation");
  mount(`/file-access?goal=file-access&context=retained&source=original&keep=1&control=${pending.control_owner_id}&operation=other-operation`, true);

  const link = await screen.findByRole("link", { name: "Open original operation" });
  fireEvent.click(link);
  await waitFor(() => {
    const location = new URL(screen.getByTestId("current-location").textContent!, "http://local.test");
    expect(location.pathname).toBe("/file-access");
    expect(location.searchParams.get("goal")).toBe("file-access");
    expect(location.searchParams.get("context")).toBe("retained");
    expect(location.searchParams.get("source")).toBe("original");
    expect(location.searchParams.get("keep")).toBe("1");
    expect(location.searchParams.get("control")).toBe(pending.control_owner_id);
    expect(location.searchParams.get("operation")).toBe(pending.operation_job_id);
  });
  expect(screen.getByRole("complementary", { name: "Selected objective" })).toBeInTheDocument();
  expect(screen.getByText("Saved evidence request is read-only")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /review original task evidence|resubmit original evidence request|read original task evidence/i })).not.toBeInTheDocument();
  expect(readFileAccessReconciliationPending()).toEqual(pending);
  expect(receipt).not.toHaveBeenCalled();
  expect(fileAccessApi.review).not.toHaveBeenCalled();
  expect(fileAccessApi.submit).not.toHaveBeenCalled();
  expect(fileAccessApi.reconcile).not.toHaveBeenCalled();
});

it("opens the distinct Mac composition workspace only from a settled hardened control", async () => {
  vi.mocked(fileAccessApi.control).mockResolvedValue(macOSControlFixture("hardened"));
  mount();
  expect(await screen.findByRole("link", { name: "Open composition workspace" })).toHaveAttribute("href", `/composition?${new URLSearchParams({ control: macOSOwner, pack: MACOS_FILE_ACCESS_PACK })}`);
  expect(fileAccessApi.submit).not.toHaveBeenCalled();
});

it("removes Mac composition entry during a status refresh and keeps its control history", async () => {
  vi.mocked(fileAccessApi.control).mockResolvedValue(macOSControlFixture("hardened"));
  let resolveStatus!: (value: ReturnType<typeof macOSStatusFixture>) => void;
  const nextStatus = new Promise<ReturnType<typeof macOSStatusFixture>>(resolve => { resolveStatus = resolve; });
  mount();
  await screen.findByRole("link", { name: "Open composition workspace" });
  vi.mocked(fileAccessApi.status).mockReturnValue(nextStatus);
  fireEvent.click(screen.getByRole("button", { name: "Refresh state" }));
  await waitFor(() => expect(screen.queryByRole("link", { name: "Open composition workspace" })).not.toBeInTheDocument());
  expect(screen.getByRole("heading", { name: "Recorded baseline" })).toBeInTheDocument();
  resolveStatus(macOSStatusFixture(false));
  await screen.findByText("Live setup is not ready");
  expect(screen.queryByRole("link", { name: "Open composition workspace" })).not.toBeInTheDocument();
  expect(screen.getByRole("link", { name: /Operation 1: Verify baseline access/ })).toBeInTheDocument();
  expect(fileAccessApi.submit).not.toHaveBeenCalled();
});

it.each(["baseline", "pending", "uncertain"] as const)("does not offer Mac composition for a %s control", async state => {
  const control = macOSControlFixture(state === "baseline" ? "baseline_verified" : state === "uncertain" ? "uncertain" : "hardened");
  if (state === "pending") control.usage_state = "pending";
  vi.mocked(fileAccessApi.control).mockResolvedValue(control);
  mount();
  if (state === "pending") {
    // A pending Mac response must be uncertain, never a retained hardened state.
    await screen.findByText("Retained control unavailable");
  } else {
    await screen.findByRole("region", { name: "Saved macOS workspace control" });
  }
  expect(screen.queryByRole("link", { name: /composition/i })).not.toBeInTheDocument();
});

it("imports only the original setup selection supplied by tagged macOS status", async () => {
  const status = macOSStatusFixture();
  vi.mocked(fileAccessApi.status).mockResolvedValue(status);
  mount("/file-access");
  fireEvent.click(await screen.findByRole("button", { name: "Save original workspace setup" }));
  await waitFor(() => expect(fileAccessApi.importSetup).toHaveBeenCalledOnce());
  expect(fileAccessApi.importSetup).toHaveBeenCalledWith({ enrollment_id: status.enrollment!.enrollment_id, enrollment_digest: status.enrollment!.enrollment_digest });
  expect(await screen.findByRole("region", { name: "Saved macOS workspace control" })).toBeInTheDocument();
  expect(screen.queryByRole("textbox")).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Review generated resource" })).not.toBeInTheDocument();
});

it.each([
  ["created", "baseline", "baseline_verified"],
  ["baseline_verified", "harden", "hardened"],
  ["hardened", "rollback", "rolled_back"],
] as const)("submits one explicit %s to %s operation through the existing review", async (before, operation, after) => {
  const original = macOSControlFixture(before);
  let current = original;
  vi.mocked(fileAccessApi.control).mockImplementation(async () => current);
  const reviewed = macOSReviewFixture(operation, original);
  vi.mocked(fileAccessApi.review).mockResolvedValue(reviewed);
  vi.mocked(fileAccessApi.submit).mockImplementation(async (body: FileAccessSubmission) => {
    current = macOSControlFixture(after);
    return macOSOperationFixture(body, current);
  });
  mount();
  const label = operation === "baseline" ? "verify baseline access" : operation === "harden" ? "apply owner-only access" : "restore baseline access";
  fireEvent.click(await screen.findByRole("button", { name: `Review ${label}` }));
  expect(await screen.findByText(reviewed.effect)).toBeInTheDocument();
  expect(fileAccessApi.review).toHaveBeenCalledWith({ operation, control_owner_id: macOSOwner });
  const review = screen.getByRole("region", { name: "File-access operation review" });
  fireEvent.change(within(review).getByLabelText("Operation reviewed by"), { target: { value: "operator" } });
  fireEvent.click(within(review).getByRole("checkbox"));
  fireEvent.click(within(review).getByRole("button", { name: operation === "baseline" ? "Verify baseline access" : operation === "harden" ? "Apply owner-only access" : "Restore baseline access" }));
  await waitFor(() => expect(fileAccessApi.submit).toHaveBeenCalledOnce());
  expect(vi.mocked(fileAccessApi.submit).mock.calls[0]![0]).toMatchObject({ review: { operation, control_owner_id: macOSOwner }, review_digest: reviewed.review_digest, reviewed_by: "operator" });
  if (after === "hardened") expect(await screen.findByRole("link", { name: "Open composition workspace" })).toHaveAttribute("href", `/composition?${new URLSearchParams({ control: macOSOwner, pack: MACOS_FILE_ACCESS_PACK })}`);
  else expect(screen.queryByRole("link", { name: /composition/i })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /reset|generated resource/i })).not.toBeInTheDocument();
});

it("shows unknown custody and its original history read-only without reconciliation", async () => {
  const control = macOSControlFixture("uncertain");
  const operation = macOSOperationFixture(undefined, control);
  operation.job.state = "interrupted";
  operation.reconciliation = { outcome_digest: macOSDigest(), state: "unknown", available: false };
  vi.mocked(fileAccessApi.control).mockResolvedValue(control);
  vi.mocked(fileAccessApi.operation).mockResolvedValue(operation);
  mount(`/file-access?control=${macOSOwner}&operation=${operation.job.job_id}`);
  expect(await screen.findByText("Workspace custody is unresolved")).toBeInTheDocument();
  const saved = screen.getByRole("region", { name: "Saved macOS workspace control" });
  expect(within(saved).getByText("Recorded baseline")).toBeInTheDocument();
  expect(within(saved).getByRole("link", { name: /Operation 1: Verify baseline access/ })).toBeInTheDocument();
  expect(within(saved).queryByRole("button")).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /review original task evidence|reconcile|reset/i })).not.toBeInTheDocument();
  expect(fileAccessApi.reconcile).not.toHaveBeenCalled();
  expect(fileAccessApi.submit).not.toHaveBeenCalled();
});

it("retains an unconfirmed Mac request for status checks without offering resubmission", async () => {
  const operation = macOSOperationFixture();
  storeFileAccessPending({ id: operation.job.job_id, body: operation.job.progress.submitted_request as FileAccessSubmission });
  mount();
  expect(await screen.findByRole("button", { name: "Check saved operation" })).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Resubmit original request" })).not.toBeInTheDocument();
  expect(fileAccessApi.submit).not.toHaveBeenCalled();
});

it.each(["unavailable", "expired"] as const)("keeps saved evidence read-only when the original workspace is %s", async state => {
  const status = macOSStatusFixture(state !== "unavailable");
  if (status.enrollment) status.enrollment.expires_at_ms = Date.now() - 1000;
  vi.mocked(fileAccessApi.status).mockResolvedValue(status);
  vi.mocked(fileAccessApi.control).mockResolvedValue({ ...macOSControlFixture("hardened"), allowed_operations: [] });
  mount();
  expect(await screen.findByText("Original workspace unavailable")).toBeInTheDocument();
  expect(screen.getByRole("heading", { name: "macOS protected workspace" })).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /save original|review restore|review generated|reset/i })).not.toBeInTheDocument();
  expect(screen.queryByRole("link", { name: /composition/i })).not.toBeInTheDocument();
});

it.each(["control", "enrollment"] as const)("disables an acknowledged review after its %s binding changes", async binding => {
  let current = macOSControlFixture("baseline_verified");
  let status = macOSStatusFixture();
  vi.mocked(fileAccessApi.control).mockImplementation(async () => current);
  vi.mocked(fileAccessApi.status).mockImplementation(async () => status);
  const reviewed = macOSReviewFixture("harden", current);
  vi.mocked(fileAccessApi.review).mockResolvedValue(reviewed);
  mount();
  fireEvent.click(await screen.findByRole("button", { name: "Review apply owner-only access" }));
  await screen.findByText(reviewed.effect);
  fireEvent.change(screen.getByLabelText("Operation reviewed by"), { target: { value: "operator" } });
  fireEvent.click(screen.getByRole("checkbox"));
  if (binding === "control") current = { ...current, control_digest: macOSDigest("9") };
  else status = { ...status, enrollment: { ...status.enrollment!, enrollment_digest: macOSDigest("9") } };
  fireEvent.click(screen.getByRole("button", { name: "Refresh state" }));
  expect(await screen.findByText("Control changed")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Apply owner-only access" })).toBeDisabled();
  expect(fileAccessApi.submit).not.toHaveBeenCalled();
});

it("rejects an unsupported platform without presenting an import or control action", async () => {
  vi.mocked(fileAccessApi.status).mockResolvedValue({ ...macOSStatusFixture(), platform: "unsupported" } as unknown as ReturnType<typeof macOSStatusFixture>);
  vi.mocked(fileAccessApi.control).mockResolvedValue({ ...macOSControlFixture(), platform: "unsupported" } as unknown as ReturnType<typeof macOSControlFixture>);
  mount();
  expect(await screen.findByText("Retained control unavailable")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /save original|review verify|review generated/i })).not.toBeInTheDocument();
  expect(fileAccessApi.importSetup).not.toHaveBeenCalled();
});

it("refuses a Mac operation envelope that advertises reconciliation", async () => {
  const response: FileAccessOperationEnvelope = macOSOperationFixture(undefined, macOSControlFixture("uncertain"));
  response.job.state = "interrupted";
  response.reconciliation = { outcome_digest: macOSDigest(), state: "unknown", available: true };
  vi.mocked(fileAccessApi.control).mockResolvedValue(macOSControlFixture("uncertain"));
  vi.mocked(fileAccessApi.operation).mockResolvedValue(response);
  mount(`/file-access?control=${macOSOwner}&operation=${response.job.job_id}`);
  expect(await screen.findByText("Saved operation unavailable")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Review original task evidence" })).not.toBeInTheDocument();
  expect(fileAccessApi.reconcile).not.toHaveBeenCalled();
});

it.each([true, false])("keeps a saved Linux reset read-only under macOS status, available=%s", async available => {
  const control = fileAccessControlFixture();
  control.allowed_operations = ["reset"];
  control.operations = [fileAccessOperationFixture().job];
  vi.mocked(fileAccessApi.status).mockResolvedValue(macOSStatusFixture(available));
  vi.mocked(fileAccessApi.control).mockResolvedValue(control);
  mount(`/file-access?control=${control.control_owner_id}`);
  expect(await screen.findByText("Saved control is read-only")).toBeInTheDocument();
  const saved = screen.getByRole("region", { name: "Retained file-access control" });
  expect(within(saved).getByText("Verified baseline")).toBeInTheDocument();
  expect(within(saved).getByRole("link", { name: /Operation 1: Restore baseline access/ })).toBeInTheDocument();
  expect(within(saved).queryByRole("button")).not.toBeInTheDocument();
  expect(screen.queryByRole("link", { name: /composition/i })).not.toBeInTheDocument();
  expect(fileAccessApi.review).not.toHaveBeenCalled();
  expect(fileAccessApi.submit).not.toHaveBeenCalled();
});

it.each([true, false])("retains an old Linux pending request without resubmission under macOS status, available=%s", async available => {
  const control = fileAccessControlFixture();
  const body = fileAccessSubmissionFixture();
  const pending = { id: fileAccessOperationFixture().job.job_id, body };
  storeFileAccessPending(pending);
  vi.mocked(fileAccessApi.status).mockResolvedValue(macOSStatusFixture(available));
  vi.mocked(fileAccessApi.control).mockResolvedValue(control);
  mount(`/file-access?control=${control.control_owner_id}`);
  await screen.findByRole("heading", { name: "macOS protected workspace" });
  expect(screen.getByRole("button", { name: "Check saved operation" })).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Resubmit original request" })).not.toBeInTheDocument();
  expect(readFileAccessPending()).toEqual(pending);
  expect(fileAccessApi.submit).not.toHaveBeenCalled();
});

it.each([true, false])("keeps an old Linux reconciliation read-only under macOS status, available=%s", async available => {
  const operation = fileAccessOperationFixture();
  operation.job.state = "interrupted";
  operation.reconciliation = { outcome_digest: macOSDigest(), state: "unknown", available: true };
  const pending = { operation_job_id: operation.job.job_id, control_owner_id: operation.control!.control_owner_id, body: { submission_id: "44444444-4444-4444-8444-444444444444", expected_outcome_digest: macOSDigest(), reviewed_by: "synthetic-reviewer" } };
  storeFileAccessReconciliationPending(pending);
  vi.mocked(fileAccessApi.status).mockResolvedValue(macOSStatusFixture(available));
  vi.mocked(fileAccessApi.control).mockResolvedValue(fileAccessControlFixture());
  vi.mocked(fileAccessApi.operation).mockResolvedValue(operation);
  const receipt = vi.spyOn(fileAccessApi, "reconciliation");
  mount(`/file-access?control=${pending.control_owner_id}&operation=${pending.operation_job_id}`);
  expect(await screen.findByText("Saved evidence request is read-only")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Open original operation" })).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /review original task evidence|resubmit original evidence request|read original task evidence/i })).not.toBeInTheDocument();
  expect(readFileAccessReconciliationPending()).toEqual(pending);
  expect(receipt).not.toHaveBeenCalled();
  expect(fileAccessApi.reconcile).not.toHaveBeenCalled();
});

it.each([true, false])("disables an acknowledged Linux reset throughout a deferred macOS status refresh, available=%s", async available => {
  const control = fileAccessControlFixture();
  control.allowed_operations = ["reset"];
  type Status = Awaited<ReturnType<typeof fileAccessApi.status>>;
  let resolveStatus!: (value: Status) => void;
  const nextStatus = new Promise<Status>(resolve => { resolveStatus = resolve; });
  let refreshing = false;
  vi.mocked(fileAccessApi.status).mockImplementation(async () => refreshing ? nextStatus : fileAccessStatusFixture());
  vi.mocked(fileAccessApi.control).mockResolvedValue(control);
  const reviewed = { ...fileAccessReviewFixture(), operation: "reset" as const, effect: "Reset only the original generated Linux resource." };
  vi.mocked(fileAccessApi.review).mockResolvedValue(reviewed);
  mount(`/file-access?control=${control.control_owner_id}`);
  fireEvent.click(await screen.findByRole("button", { name: "Review reset generated resource" }));
  await screen.findByText(reviewed.effect);
  fireEvent.change(screen.getByLabelText("Operation reviewed by"), { target: { value: "operator" } });
  fireEvent.click(screen.getByRole("checkbox"));
  expect(screen.getByRole("button", { name: "Reset generated resource" })).toBeEnabled();
  refreshing = true;
  fireEvent.click(screen.getByRole("button", { name: "Refresh state" }));
  await waitFor(() => expect(screen.getByRole("button", { name: "Reset generated resource" })).toBeDisabled());
  fireEvent.click(screen.getByRole("button", { name: "Reset generated resource" }));
  expect(fileAccessApi.submit).not.toHaveBeenCalled();
  expect(screen.getByRole("region", { name: "Retained file-access control" })).toBeInTheDocument();
  expect(screen.queryByRole("link", { name: /composition/i })).not.toBeInTheDocument();
  resolveStatus(macOSStatusFixture(available));
  await screen.findByText("Saved control is read-only");
  const submit = screen.getByRole("button", { name: "Reset generated resource" });
  expect(submit).toBeDisabled();
  expect(screen.queryByRole("link", { name: /composition/i })).not.toBeInTheDocument();
  fireEvent.click(submit);
  expect(fileAccessApi.submit).not.toHaveBeenCalled();
});

it.each([true, false])("removes acknowledged Linux reconciliation throughout a deferred macOS status refresh, available=%s", async available => {
  const operation = fileAccessOperationFixture();
  operation.job.state = "interrupted";
  operation.reconciliation = { outcome_digest: macOSDigest(), state: "unknown", available: true };
  type Status = Awaited<ReturnType<typeof fileAccessApi.status>>;
  let resolveStatus!: (value: Status) => void;
  const nextStatus = new Promise<Status>(resolve => { resolveStatus = resolve; });
  let refreshing = false;
  vi.mocked(fileAccessApi.status).mockImplementation(async () => refreshing ? nextStatus : fileAccessStatusFixture());
  vi.mocked(fileAccessApi.control).mockResolvedValue(fileAccessControlFixture());
  vi.mocked(fileAccessApi.operation).mockResolvedValue(operation);
  mount(`/file-access?control=${operation.control!.control_owner_id}&operation=${operation.job.job_id}`);
  fireEvent.click(await screen.findByRole("button", { name: "Review original task evidence" }));
  fireEvent.change(screen.getByLabelText("Evidence review by"), { target: { value: "operator" } });
  fireEvent.click(screen.getByRole("checkbox"));
  expect(screen.getByRole("button", { name: "Read original task evidence" })).toBeEnabled();
  refreshing = true;
  fireEvent.click(screen.getByRole("button", { name: "Refresh state" }));
  await waitFor(() => expect(screen.queryByRole("button", { name: "Read original task evidence" })).not.toBeInTheDocument());
  expect(screen.queryByRole("button", { name: "Review original task evidence" })).not.toBeInTheDocument();
  expect(screen.getByRole("region", { name: "Saved operation" })).toBeInTheDocument();
  expect(fileAccessApi.reconcile).not.toHaveBeenCalled();
  resolveStatus(macOSStatusFixture(available));
  await screen.findByText("Saved control is read-only");
  expect(screen.queryByRole("button", { name: /review original task evidence|read original task evidence|resubmit original evidence request/i })).not.toBeInTheDocument();
  expect(fileAccessApi.reconcile).not.toHaveBeenCalled();
});
