import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { FileAccessPage } from "../src/pages/FileAccess";
import { FileAccessReview } from "../src/components/FileAccessReview";
import { CompositionAttempts } from "../src/components/CompositionAttempts";
import { CompositionCapabilities, CompositionSetup } from "../src/components/CompositionReview";
import { compositionApi, FILE_ACCESS_PACK } from "../src/lib/composition";
import { fileAccessApi, readFileAccessPending, readFileAccessReconciliationPending, storeFileAccessPending, type FileAccessOperationEnvelope, type LinuxFileAccessControl, type WindowsPairedFileAccessControl, type WindowsSetupFileAccessControl, type WindowsSetupFileAccessStatus, type WindowsPairFileAccessStatus } from "../src/lib/file-access";
import { request } from "../src/lib/api";
import { controlId, ownerId, proposalId } from "./composition-fixture";
import { fileAccessCompositionReviewFixture, fileAccessControlFixture, fileAccessObjectiveFixture, fileAccessObservationFixture, fileAccessOperationFixture, fileAccessReviewFixture, fileAccessStatusFixture, fileAccessSubmissionFixture } from "./file-access-fixture";

vi.mock("../src/lib/api", () => ({ DEMO_MODE: false, request: vi.fn(), ApiError: class extends Error {} }));
const windowsSetupStatus = (): WindowsSetupFileAccessStatus => ({
  schema_version: "bluefire.file-access-status.v1", available: false,
  problem: { code: "windows_native_admission_unavailable", message: "Protected setup is verified. Native task admission is not yet available." },
  enrollment: null, allowed_operations: [],
  setup: { enrollment_id: "win-file-enrollment-0123456789abcdef0123456789abcdef", enrollment_digest: "sha256:" + "a".repeat(64), expires_at_ms: Date.now() + 60000, verification: "protected_setup_only" },
});
const windowsSetupControl = (): WindowsSetupFileAccessControl => ({
  schema_version: "bluefire.windows-file-access-control.v1", platform: "windows",
  control_owner_id: "win-file-control-0123456789abcdef0123456789abcdef", control_digest: "sha256:" + "b".repeat(64),
  revision: 1, status: "setup_verified", expires_at_ms: Date.now() + 60000,
  provenance: { kind: "protected_setup", enrollment_id: "win-file-enrollment-0123456789abcdef0123456789abcdef", enrollment_digest: "sha256:" + "a".repeat(64), setup_receipt_digest: "sha256:" + "c".repeat(64) },
  resource: { resource_id: "windows-resource", resource_generation: "0123456789abcdef0123456789abcdef", expected_sha256: "sha256:" + "d".repeat(64), size_bytes: 1024, protection: "reader_readable" },
  baseline: null, operations: [], allowed_operations: [], task_usage_state: "none", account_object_cleanup: "required",
});
const windowsPairStatus = (): WindowsPairFileAccessStatus => ({ schema_version: "bluefire.file-access-status.v1", available: true, problem: null, enrollment: null, allowed_operations: [], setup: windowsSetupStatus().setup });
const windowsPairJob = (controlIdValue = windowsSetupControl().control_owner_id) => {
  const job = fileAccessOperationFixture().job;
  const submitted = { ...fileAccessSubmissionFixture(), submission_id: "dddddddd-dddd-dddd-dddd-dddddddddddd", review: { operation: "baseline" as const, control_owner_id: controlIdValue } };
  job.job_id = `job-${submitted.submission_id.replaceAll("-", "")}`;
  job.progress.submitted_request = submitted;
  return job;
};
const windowsPairBaseline = () => ({ schema_version: "bluefire.windows-file-readable-baseline.v2" as const, non_owner: "allowed" as const, owner: "allowed" as const, size_bytes: 1024, sha256: "sha256:" + "d".repeat(64), resource_generation: "0123456789abcdef0123456789abcdef", observed_at: new Date().toISOString(), native_cleanup: "verified" as const, owned_job_cleanup: "verified" as const, independent_observation: false as const, baseline_digest: "sha256:" + "e".repeat(64) });
const windowsPairControl = (state: "setup" | "uncertain" | "settled" = "setup"): WindowsPairedFileAccessControl => {
  const setup = windowsSetupControl();
  return { ...setup, schema_version: "bluefire.windows-file-access-control.v2", revision: state === "settled" ? 2 : 1,
    status: state === "uncertain" ? "uncertain" : state === "settled" ? "baseline_verified" : "setup_verified",
    baseline: state === "settled" ? windowsPairBaseline() : null, operations: state === "setup" ? [] : [windowsPairJob()],
    allowed_operations: state === "setup" ? ["baseline"] : [], task_usage_state: state === "setup" ? "none" : state === "uncertain" ? "unresolved" : "settled" };
};
function mount(element: React.ReactNode, path = "/file-access") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return { ...render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}>{element}</MemoryRouter></QueryClientProvider>), client };
}
beforeEach(() => {
  localStorage.clear();
  vi.mocked(request).mockReset();
  vi.spyOn(fileAccessApi, "status").mockResolvedValue(fileAccessStatusFixture());
  vi.spyOn(fileAccessApi, "list").mockResolvedValue({ schema_version: "bluefire.file-access-control-list.v1", controls: [{ control_owner_id: controlId, status: "hardened", revision: 3 }] });
  vi.spyOn(fileAccessApi, "control").mockResolvedValue(fileAccessControlFixture());
  vi.spyOn(fileAccessApi, "operation").mockRejectedValue(new Error("No saved confirmation yet"));
  vi.spyOn(fileAccessApi, "review").mockResolvedValue(fileAccessReviewFixture());
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it("posts only the selected verified setup through the ordinary authenticated request helper", async () => {
  const body = { enrollment_id: windowsSetupStatus().setup.enrollment_id, enrollment_digest: "sha256:" + "a".repeat(64) };
  const saved = windowsSetupControl();
  vi.mocked(request).mockResolvedValue(saved);
  await expect(fileAccessApi.importSetup(body)).resolves.toEqual(saved);
  expect(request).toHaveBeenCalledWith("/file-access/setup-import", { method: "POST", body: JSON.stringify(body) });
});

it("imports Windows setup only after an explicit save and opens the non-executable saved control", async () => {
  const status = windowsSetupStatus();
  const saved = windowsSetupControl();
  vi.mocked(fileAccessApi.status).mockResolvedValue(status);
  vi.spyOn(fileAccessApi, "importSetup").mockResolvedValue(saved);
  vi.spyOn(fileAccessApi, "control").mockResolvedValue(saved);
  const imported = vi.mocked(fileAccessApi.importSetup);
  mount(<FileAccessPage />);
  expect(await screen.findByRole("heading", { name: "Windows protected setup" })).toBeInTheDocument();
  expect(imported).not.toHaveBeenCalled();
  expect(screen.getByRole("button", { name: "Save verified setup" })).toBeEnabled();
  expect(screen.queryByRole("button", { name: /baseline|harden|rollback|reset/i })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Save verified setup" }));
  expect(await screen.findByRole("heading", { name: "Saved Windows setup" })).toBeInTheDocument();
  expect(imported).toHaveBeenCalledWith({ enrollment_id: status.setup.enrollment_id, enrollment_digest: status.setup.enrollment_digest });
  expect(fileAccessApi.control).toHaveBeenCalledWith(saved.control_owner_id);
  expect(screen.getByText("Baseline not established")).toBeInTheDocument();
  expect(screen.getByText("Task usage").nextElementSibling).toHaveTextContent("None");
  expect(screen.getByText("Account and object cleanup").nextElementSibling).toHaveTextContent("Required");
  expect(screen.queryByText(/owner UID|probe UID|record count|observed mode/i)).not.toBeInTheDocument();
});

it("imports a paired setup and permits only a current, explicitly reviewed baseline", async () => {
  const status = windowsPairStatus();
  let current = windowsPairControl();
  vi.mocked(fileAccessApi.status).mockResolvedValue(status);
  vi.spyOn(fileAccessApi, "importSetup").mockImplementation(async () => current);
  vi.mocked(fileAccessApi.control).mockImplementation(async () => current);
  vi.mocked(fileAccessApi.list).mockResolvedValue({ schema_version: "bluefire.file-access-control-list.v1", controls: [] });
  vi.spyOn(fileAccessApi, "review").mockImplementation(async request => ({ ...fileAccessReviewFixture(), operation: request.operation, control_owner_id: request.control_owner_id, control_digest: current.control_digest }));
  const submit = vi.spyOn(fileAccessApi, "submit").mockImplementation(async body => {
    const job = fileAccessOperationFixture().job;
    job.job_id = `job-${body.submission_id.replaceAll("-", "")}`; job.progress.submitted_request = body;
    current = { ...windowsPairControl("settled"), operations: [job] };
    return { schema_version: "bluefire.file-access-operation.v1", job, control: current, reconciliation: null, reconciliation_receipt: null };
  });
  mount(<FileAccessPage />);
  fireEvent.click(await screen.findByRole("button", { name: "Save verified setup" }));
  expect(await screen.findByRole("heading", { name: "Saved Windows paired control" })).toBeInTheDocument();
  expect(screen.getByText("Baseline not established")).toBeInTheDocument();
  await waitFor(() => expect(screen.getByRole("button", { name: "Review paired baseline" })).toBeEnabled());
  expect(screen.queryByRole("button", { name: /harden|rollback|reset|compose/i })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Review paired baseline" }));
  expect(await screen.findByText(fileAccessReviewFixture().effect)).toBeInTheDocument();
  expect(fileAccessApi.review).toHaveBeenCalledWith({ operation: "baseline", control_owner_id: current.control_owner_id });
  fireEvent.change(screen.getByRole("textbox", { name: "Operation reviewed by" }), { target: { value: "reviewer" } });
  fireEvent.click(screen.getByRole("checkbox")); fireEvent.click(screen.getByRole("button", { name: "Verify baseline access" }));
  await waitFor(() => expect(submit).toHaveBeenCalledOnce());
  expect(submit.mock.calls[0]![0].review).toEqual({ operation: "baseline", control_owner_id: current.control_owner_id });
  expect(await screen.findByText("Recorded paired baseline")).toBeInTheDocument();
  expect(screen.getByText("Independent observation").nextElementSibling).toHaveTextContent("No");
  expect(screen.getByText("Native cleanup").nextElementSibling).toHaveTextContent("Verified");
  expect(screen.queryByRole("region", { name: "Verified operation reads" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /harden|rollback|reset|compose/i })).not.toBeInTheDocument();
});

it("disables an open baseline review when the original paired setup expires", async () => {
  const status = windowsPairStatus();
  const control = windowsPairControl();
  const expired = { ...status, setup: { ...status.setup, expires_at_ms: Date.now() - 1 } };
  vi.mocked(fileAccessApi.status).mockResolvedValueOnce(status).mockResolvedValueOnce(expired);
  vi.mocked(fileAccessApi.control).mockResolvedValue(control);
  vi.mocked(fileAccessApi.list).mockResolvedValue({ schema_version: "bluefire.file-access-control-list.v1", controls: [{ control_owner_id: control.control_owner_id, status: "setup_verified", revision: 1, platform: "windows" }] });
  vi.spyOn(fileAccessApi, "review").mockImplementation(async request => ({ ...fileAccessReviewFixture(), operation: request.operation, control_owner_id: request.control_owner_id, control_digest: control.control_digest }));
  const submit = vi.spyOn(fileAccessApi, "submit");
  mount(<FileAccessPage />, `/file-access?control=${control.control_owner_id}`);
  fireEvent.click(await screen.findByRole("button", { name: "Review paired baseline" }));
  expect(await screen.findByText(fileAccessReviewFixture().effect)).toBeInTheDocument();
  const actor = screen.getByRole("textbox", { name: "Operation reviewed by" });
  fireEvent.change(actor, { target: { value: "original-reviewer" } });
  fireEvent.click(screen.getByRole("checkbox"));
  fireEvent.click(screen.getByRole("button", { name: "Refresh state" }));
  await waitFor(() => expect(screen.getByText("Setup needs fresh verification")).toBeInTheDocument());
  expect(screen.getByRole("textbox", { name: "Operation reviewed by" })).toHaveValue("original-reviewer");
  expect(screen.getByRole("checkbox")).toBeChecked();
  expect(screen.getByRole("button", { name: "Verify baseline access" })).toBeDisabled();
  expect(fileAccessApi.review).toHaveBeenCalledWith({ operation: "baseline", control_owner_id: control.control_owner_id });
  expect(submit).not.toHaveBeenCalled();
  expect(readFileAccessPending()).toBeUndefined();
});

it("keeps an open baseline review bound to its original setup after identity replacement", async () => {
  const status = windowsPairStatus();
  const control = windowsPairControl();
  const replacement = { ...status, setup: { ...status.setup, enrollment_id: "win-file-enrollment-fedcba9876543210fedcba9876543210", enrollment_digest: "sha256:" + "f".repeat(64) } };
  vi.mocked(fileAccessApi.status).mockResolvedValueOnce(status).mockResolvedValueOnce(replacement);
  vi.mocked(fileAccessApi.control).mockResolvedValue(control);
  vi.mocked(fileAccessApi.list).mockResolvedValue({ schema_version: "bluefire.file-access-control-list.v1", controls: [{ control_owner_id: control.control_owner_id, status: "setup_verified", revision: 1, platform: "windows" }] });
  vi.spyOn(fileAccessApi, "review").mockImplementation(async request => ({ ...fileAccessReviewFixture(), operation: request.operation, control_owner_id: request.control_owner_id, control_digest: control.control_digest }));
  const submit = vi.spyOn(fileAccessApi, "submit");
  mount(<FileAccessPage />, `/file-access?control=${control.control_owner_id}`);
  fireEvent.click(await screen.findByRole("button", { name: "Review paired baseline" }));
  expect(await screen.findByText(fileAccessReviewFixture().effect)).toBeInTheDocument();
  fireEvent.change(screen.getByRole("textbox", { name: "Operation reviewed by" }), { target: { value: "original-reviewer" } });
  fireEvent.click(screen.getByRole("checkbox"));
  fireEvent.click(screen.getByRole("button", { name: "Refresh state" }));
  await waitFor(() => expect(fileAccessApi.status).toHaveBeenCalledTimes(2));
  expect(screen.getByRole("textbox", { name: "Operation reviewed by" })).toHaveValue("original-reviewer");
  expect(screen.getByRole("checkbox")).toBeChecked();
  expect(screen.getByRole("button", { name: "Verify baseline access" })).toBeDisabled();
  expect(fileAccessApi.review).toHaveBeenCalledWith({ operation: "baseline", control_owner_id: control.control_owner_id });
  expect(submit).not.toHaveBeenCalled();
  expect(readFileAccessPending()).toBeUndefined();
});

it("keeps an uncertain paired setup read-only and offers evidence review only for its original operation", async () => {
  const control = windowsPairControl("uncertain"); const job = control.operations[0]!;
  vi.mocked(fileAccessApi.status).mockResolvedValue(windowsPairStatus());
  vi.mocked(fileAccessApi.control).mockResolvedValue(control);
  vi.mocked(fileAccessApi.operation).mockResolvedValue({ schema_version: "bluefire.file-access-operation.v1", job, control, reconciliation: { outcome_digest: "sha256:" + "f".repeat(64), state: "unknown", available: true }, reconciliation_receipt: null });
  mount(<FileAccessPage />, `/file-access?control=${control.control_owner_id}&operation=${job.job_id}`);
  expect(await screen.findByText("Original baseline attempt is unresolved")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Review original task evidence" })).toBeEnabled();
  expect(screen.queryByRole("button", { name: "Review paired baseline" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /harden|rollback|reset|compose/i })).not.toBeInTheDocument();
});

it("shows a no-effect baseline attempt as history without offering another baseline", async () => {
  const control = windowsPairControl();
  const job = windowsPairJob();
  job.state = "failed";
  const noEffect = { ...control, operations: [job], allowed_operations: [], task_usage_state: "none" as const };
  vi.mocked(fileAccessApi.status).mockResolvedValue(windowsPairStatus());
  vi.mocked(fileAccessApi.control).mockResolvedValue(noEffect);
  vi.mocked(fileAccessApi.list).mockResolvedValue({ schema_version: "bluefire.file-access-control-list.v1", controls: [{ control_owner_id: control.control_owner_id, status: "setup_verified", revision: 1, platform: "windows" }] });
  mount(<FileAccessPage />, `/file-access?control=${control.control_owner_id}`);
  expect(await screen.findByText("The saved attempt did not establish a baseline. This one-shot control cannot be submitted again.")).toBeInTheDocument();
  expect(screen.getByText("Saved baseline operations")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Review paired baseline" })).not.toBeInTheDocument();
});

it("does not offer an old verified setup after its fresh observation fails", async () => {
  vi.mocked(fileAccessApi.status).mockResolvedValue(windowsSetupStatus());
  const imported = vi.spyOn(fileAccessApi, "importSetup");
  mount(<FileAccessPage />);
  expect(await screen.findByRole("button", { name: "Save verified setup" })).toBeEnabled();
  vi.mocked(fileAccessApi.status).mockRejectedValue(new Error("Fresh setup observation failed"));
  fireEvent.click(screen.getByRole("button", { name: "Refresh state" }));
  expect(await screen.findByText("Fresh setup observation failed")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Save verified setup" })).not.toBeInTheDocument();
  expect(screen.queryByText("Setup verified")).not.toBeInTheDocument();
  expect(screen.getByText("Setup needs fresh verification")).toBeInTheDocument();
  expect(screen.queryByText("Windows task access is unavailable")).not.toBeInTheDocument();
  expect(imported).not.toHaveBeenCalled();
});

it("keeps an unconfirmed save uncertain and repeats only the same setup selection", async () => {
  const status = windowsSetupStatus();
  const saved = windowsSetupControl();
  vi.mocked(fileAccessApi.status).mockResolvedValue(status);
  vi.mocked(fileAccessApi.control).mockResolvedValue(saved);
  const imported = vi.spyOn(fileAccessApi, "importSetup")
    .mockRejectedValueOnce(new Error("Response connection lost"))
    .mockResolvedValueOnce(saved);
  mount(<FileAccessPage />);
  fireEvent.click(await screen.findByRole("button", { name: "Save verified setup" }));
  expect(await screen.findByText("Setup save was not confirmed")).toBeInTheDocument();
  expect(screen.queryByRole("heading", { name: "Saved Windows setup" })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Save verified setup" }));
  expect(await screen.findByRole("heading", { name: "Saved Windows setup" })).toBeInTheDocument();
  const selection = { enrollment_id: status.setup.enrollment_id, enrollment_digest: status.setup.enrollment_digest };
  expect(imported.mock.calls).toEqual([[selection], [selection]]);
  expect(screen.queryByText("Setup save was not confirmed")).not.toBeInTheDocument();
});

it("projects unavailable enrollment without inventing setup readiness or identity controls", async () => {
  vi.mocked(fileAccessApi.status).mockResolvedValue({ schema_version: "bluefire.file-access-status.v1", available: false, problem: { code: "not_enrolled", message: "An owner-approved prepared session is required." }, enrollment: null, allowed_operations: [] });
  const submit = vi.spyOn(fileAccessApi, "submit");
  mount(<FileAccessPage />);
  expect(await screen.findByText("An owner-approved prepared session is required.")).toBeInTheDocument();
  expect(screen.getByText("Unavailable")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Review generated resource" })).not.toBeInTheDocument();
  expect(screen.queryByRole("textbox")).not.toBeInTheDocument(); expect(submit).not.toHaveBeenCalled();
});
it("requires an explicit reviewed operation, unchecked consent and actor", async () => {
  const send = vi.fn(); const body = fileAccessSubmissionFixture().review;
  mount(<FileAccessReview request={body} disabled={false} onSubmit={send} onClose={vi.fn()} />);
  const action = await screen.findByRole("button", { name: "Restore baseline access" });
  expect(action).toBeDisabled(); expect(screen.getByRole("checkbox")).not.toBeChecked();
  fireEvent.click(screen.getByRole("checkbox")); expect(action).toBeDisabled();
  fireEvent.change(screen.getByRole("textbox", { name: "Operation reviewed by" }), { target: { value: "operator" } });
  fireEvent.click(action); expect(send).toHaveBeenCalledOnce();
  expect(send.mock.calls[0]![0]).toMatchObject({ review: body, review_digest: fileAccessReviewFixture().review_digest, reviewed_by: "operator" });
});
it("leaves an expired operation review non-executable", async () => {
  vi.mocked(fileAccessApi.review).mockResolvedValue({ ...fileAccessReviewFixture(), expires_at_ms: Date.now() - 1 });
  mount(<FileAccessReview request={fileAccessSubmissionFixture().review} disabled={false} onSubmit={vi.fn()} onClose={vi.fn()} />);
  await screen.findByText("Review expired");
  expect(screen.getByRole("button", { name: "Restore baseline access" })).toBeDisabled();
});
it("reloads retained hardening with historical baseline and no automatic operation", async () => {
  const submit = vi.spyOn(fileAccessApi, "submit");
  mount(<FileAccessPage />, `/file-access?control=${controlId}`);
  const link = await screen.findByRole("link", { name: "Open composition workspace" });
  expect(link).toHaveAttribute("href", `/composition?control=${controlId}&pack=${FILE_ACCESS_PACK}`);
  expect(screen.getByText(/Baseline reads are historical/)).toBeInTheDocument();
  expect(screen.queryByText("Permission denied")).not.toBeInTheDocument();
  expect(fileAccessApi.review).not.toHaveBeenCalled(); expect(submit).not.toHaveBeenCalled();
});
it("shows restored access only from the separately verified operation observation", async () => {
  const value = fileAccessOperationFixture(); const control = fileAccessControlFixture();
  value.job.progress.verified_observation = { schema_version: "bluefire.file-access-control-observation.v1", operation: "rollback", non_owner: "allowed", owner: "allowed", resource_generation: control.resource!.resource_generation, record_count: 8, sha256: control.resource!.sha256, mode: "0640", source_digest: control.control_digest, observed_at_ms: Date.now() };
  vi.mocked(fileAccessApi.operation).mockResolvedValue(value);
  mount(<FileAccessPage />, `/file-access?control=${controlId}&operation=${proposalId}`);
  await screen.findByRole("heading", { name: "Verified restored access" });
  expect(screen.getByText("Fresh non-owner read").nextElementSibling).toHaveTextContent("Allowed");
  expect(screen.getByText("Source binding")).toBeInTheDocument();
});
it.each([["failed", "rollback", "Recovered restored-access evidence"], ["interrupted", "baseline", "Recovered baseline-read evidence"], ["cancelled", "rollback", "Recovered restored-access evidence"]] as const)("labels recovered %s %s evidence and retains the original job history", async (state, operation, heading) => {
  const value = fileAccessOperationFixture(); value.job.state = state;
  value.job.progress.submitted_request = { ...fileAccessSubmissionFixture(), review: { operation, control_owner_id: controlId } };
  value.job.progress.verified_observation = fileAccessObservationFixture(operation);
  value.reconciliation = { outcome_digest: fileAccessReviewFixture().review_digest, state: "complete", available: false };
  vi.mocked(fileAccessApi.operation).mockResolvedValue(value);
  const submit = vi.spyOn(fileAccessApi, "submit"); const reconcile = vi.spyOn(fileAccessApi, "reconcile");
  mount(<FileAccessPage />, `/file-access?control=${controlId}&operation=${proposalId}`);
  await screen.findByRole("heading", { name: heading });
  const saved = within(screen.getByRole("region", { name: "Saved operation" }));
  expect(saved.getByText("Job state").nextElementSibling).toHaveTextContent(state[0]!.toUpperCase() + state.slice(1));
  expect(screen.getByText("Recovered non-owner read").nextElementSibling).toHaveTextContent("Allowed");
  expect(screen.getByText("Recovered owner read").nextElementSibling).toHaveTextContent("Allowed");
  expect(screen.queryByText("Fresh non-owner read")).not.toBeInTheDocument();
  expect(screen.queryByText("Operation unsettled")).not.toBeInTheDocument();
  expect(submit).not.toHaveBeenCalled(); expect(reconcile).not.toHaveBeenCalled();
});
it("offers only reviewed reset after a partial seed-only create with no fabricated baseline", async () => {
  const value = fileAccessOperationFixture(); value.job.state = "interrupted";
  value.job.progress.submitted_request = { ...fileAccessSubmissionFixture(), review: { operation: "create", control_owner_id: null } };
  value.reconciliation = { outcome_digest: fileAccessReviewFixture().review_digest, state: "settled_partial", available: false };
  const control = value.control!; control.control_owner_id = proposalId; control.status = "recovery_required";
  control.resource = null; control.baseline = null; control.allowed_operations = ["reset"]; control.operations = [value.job];
  vi.mocked(fileAccessApi.operation).mockResolvedValue(value); vi.mocked(fileAccessApi.control).mockResolvedValue(control);
  vi.mocked(fileAccessApi.list).mockResolvedValue({ schema_version: "bluefire.file-access-control-list.v1", controls: [control] });
  vi.mocked(fileAccessApi.review).mockResolvedValue({ ...fileAccessReviewFixture(), operation: "reset", control_owner_id: proposalId, effect: "Reset the retained original generated artifacts." });
  const submit = vi.spyOn(fileAccessApi, "submit"); const reconcile = vi.spyOn(fileAccessApi, "reconcile");
  mount(<FileAccessPage />, `/file-access?control=${proposalId}&operation=${proposalId}`);
  await screen.findByText("Partial operation settled");
  const retained = within(await screen.findByRole("region", { name: "Retained file-access control" }));
  expect(retained.getByText("Recovery required")).toBeInTheDocument();
  expect(retained.getByText("No completed generated resource is reported.")).toBeInTheDocument();
  expect(retained.getByText("Baseline not established")).toBeInTheDocument();
  expect(retained.getAllByRole("button")).toHaveLength(1);
  const reset = retained.getByRole("button", { name: "Review reset generated resource" }); expect(reset).toBeEnabled();
  expect(screen.queryByRole("region", { name: "Verified operation reads" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Review original task evidence" })).not.toBeInTheDocument();
  expect(screen.queryByRole("link", { name: /composition/i })).not.toBeInTheDocument();
  expect(fileAccessApi.review).not.toHaveBeenCalled(); expect(submit).not.toHaveBeenCalled(); expect(reconcile).not.toHaveBeenCalled();
  fireEvent.click(reset);
  expect(await screen.findByRole("button", { name: "Reset generated resource" })).toBeDisabled();
  expect(fileAccessApi.review).toHaveBeenCalledWith({ operation: "reset", control_owner_id: proposalId });
  expect(screen.getByRole("checkbox")).not.toBeChecked(); expect(submit).not.toHaveBeenCalled();
});
it("keeps a previously verified baseline historical when partial recovery requires reset", async () => {
  const control = fileAccessControlFixture(); control.status = "recovery_required"; control.allowed_operations = ["reset"]; control.resource = null;
  vi.mocked(fileAccessApi.control).mockResolvedValue(control);
  mount(<FileAccessPage />, `/file-access?control=${controlId}`);
  await screen.findByText("Reset required");
  expect(screen.getByText(/Baseline reads are historical/)).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Inspect composition history" })).toBeInTheDocument();
  expect(screen.queryByRole("link", { name: "Open composition workspace" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Review restore baseline access" })).not.toBeInTheDocument();
  expect(screen.queryByRole("region", { name: "Verified operation reads" })).not.toBeInTheDocument();
});
it.each(["settled_partial", "complete"] as const)("projects %s after the exact completed evidence receipt without replaying the effect", async outcome => {
  const initial = fileAccessOperationFixture(); initial.job.state = "interrupted";
  initial.reconciliation = { outcome_digest: fileAccessReviewFixture().review_digest, state: "unknown", available: true };
  const initialControl = initial.control as LinuxFileAccessControl;
  initialControl.status = "uncertain"; initialControl.usage_state = "pending"; initialControl.allowed_operations = []; initialControl.operations = [initial.job];
  let current = initial;
  vi.mocked(fileAccessApi.operation).mockImplementation(async () => current);
  vi.mocked(fileAccessApi.control).mockImplementation(async () => current.control!);
  vi.mocked(fileAccessApi.list).mockImplementation(async () => {
    const control = current.control as LinuxFileAccessControl;
    return { schema_version: "bluefire.file-access-control-list.v1", controls: [{ control_owner_id: control.control_owner_id, status: control.status, revision: control.revision }] };
  });
  vi.spyOn(fileAccessApi, "reconciliation").mockImplementation(async (operationId, submissionId) => {
    if (!current.reconciliation_receipt || current.reconciliation_receipt.submission_id !== submissionId) throw new Error("Receipt not saved yet");
    return { schema_version: "bluefire.file-access-reconciliation.v1", operation_job_id: operationId, receipt: current.reconciliation_receipt };
  });
  const reconcile = vi.spyOn(fileAccessApi, "reconcile").mockImplementation(async (_id, body) => {
    const recovered = structuredClone(initial);
    recovered.reconciliation = { outcome_digest: `sha256:${"e".repeat(64)}`, state: outcome, available: false };
    recovered.reconciliation_receipt = { submission_id: body.submission_id, submitted_request: body, state: "completed", problem: null };
    const recoveredControl = recovered.control as LinuxFileAccessControl;
    recoveredControl.usage_state = "settled"; recoveredControl.revision += 1;
    if (outcome === "settled_partial") {
      recoveredControl.status = "recovery_required"; recoveredControl.allowed_operations = ["reset"]; recoveredControl.resource = null;
    } else {
      recoveredControl.status = "rolled_back"; recoveredControl.allowed_operations = ["harden", "baseline", "reset"]; recoveredControl.resource!.mode = "0640";
      recovered.job.progress.verified_observation = fileAccessObservationFixture();
    }
    current = recovered; return recovered;
  });
  const submit = vi.spyOn(fileAccessApi, "submit");
  mount(<FileAccessPage />, `/file-access?control=${controlId}&operation=${proposalId}`);
  fireEvent.click(await screen.findByRole("button", { name: "Review original task evidence" }));
  fireEvent.change(screen.getByRole("textbox", { name: "Evidence review by" }), { target: { value: "operator" } });
  fireEvent.click(screen.getByRole("checkbox")); fireEvent.click(screen.getByRole("button", { name: "Read original task evidence" }));
  if (outcome === "settled_partial") {
    await screen.findByText("Partial operation settled");
    expect(await screen.findByRole("button", { name: "Review reset generated resource" })).toBeEnabled();
    expect(screen.queryByRole("region", { name: "Verified operation reads" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Review restore baseline access" })).not.toBeInTheDocument();
  } else {
    await screen.findByRole("heading", { name: "Recovered restored-access evidence" });
    expect(screen.getByText("Recovered non-owner read").nextElementSibling).toHaveTextContent("Allowed");
  }
  await waitFor(() => expect(readFileAccessReconciliationPending()).toBeUndefined());
  expect(screen.queryByText("Evidence request confirmation pending")).not.toBeInTheDocument();
  expect(within(screen.getByRole("region", { name: "Saved operation" })).getByText("Job state").nextElementSibling).toHaveTextContent("Interrupted");
  expect(screen.getByText(/Baseline reads are historical/)).toBeInTheDocument();
  expect(reconcile).toHaveBeenCalledOnce();
  expect(reconcile.mock.calls[0]![1]).toMatchObject({ expected_outcome_digest: initial.reconciliation!.outcome_digest, reviewed_by: "operator" });
  expect(submit).not.toHaveBeenCalled(); expect(fileAccessApi.review).not.toHaveBeenCalled();
});
it("recovers an unknown request after reload without replay or replacement", async () => {
  storeFileAccessPending({ id: proposalId, body: fileAccessSubmissionFixture() });
  const submit = vi.spyOn(fileAccessApi, "submit");
  mount(<FileAccessPage />);
  await screen.findByText("Operation confirmation pending");
  expect(await screen.findByRole("button", { name: "Resubmit original request" })).toBeEnabled();
  expect(submit).not.toHaveBeenCalled();
  expect(readFileAccessPending()?.body).toEqual(fileAccessSubmissionFixture());
});
it("does not show another control's operation evidence from a mismatched saved link", async () => {
  const value = fileAccessOperationFixture();
  value.reconciliation = { outcome_digest: fileAccessReviewFixture().review_digest, state: "unknown", available: true };
  vi.mocked(fileAccessApi.operation).mockResolvedValue(value);
  const other = fileAccessControlFixture(); other.control_owner_id = ownerId;
  vi.mocked(fileAccessApi.control).mockResolvedValue(other);
  mount(<FileAccessPage />, `/file-access?control=${ownerId}&operation=${proposalId}`);
  await screen.findByText("Saved operation unavailable");
  expect(screen.queryByRole("region", { name: "Saved operation" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Review original task evidence" })).not.toBeInTheDocument();
});
it("clears pending only after the exact server submission is observed", async () => {
  storeFileAccessPending({ id: proposalId, body: fileAccessSubmissionFixture() });
  vi.mocked(fileAccessApi.operation).mockResolvedValue(fileAccessOperationFixture());
  mount(<FileAccessPage />);
  await waitFor(() => expect(readFileAccessPending()).toBeUndefined());
  expect(await screen.findByRole("region", { name: "Saved operation" })).toBeInTheDocument();
});
it("keeps a substituted actor pending even when operation and control IDs match", async () => {
  storeFileAccessPending({ id: proposalId, body: fileAccessSubmissionFixture() });
  const value = fileAccessOperationFixture(); value.job.progress.submitted_request = { ...fileAccessSubmissionFixture(), reviewed_by: "someone else" };
  vi.mocked(fileAccessApi.operation).mockResolvedValue(value);
  mount(<FileAccessPage />);
  await screen.findByRole("region", { name: "Saved operation" });
  expect(readFileAccessPending()).toBeDefined(); expect(screen.getByText("Operation confirmation pending")).toBeInTheDocument();
});
it("binds a late operation response to its original control after navigation", async () => {
  const second = fileAccessControlFixture(); second.control_owner_id = ownerId; second.resource!.resource_generation = "second-generation";
  vi.mocked(fileAccessApi.list).mockResolvedValue({ schema_version: "bluefire.file-access-control-list.v1", controls: [fileAccessControlFixture(), second].map(({ control_owner_id, status, revision }) => ({ control_owner_id, status, revision })) });
  vi.mocked(fileAccessApi.control).mockImplementation(async id => id === ownerId ? second : fileAccessControlFixture());
  let finish!: (value: FileAccessOperationEnvelope) => void;
  const submit = vi.spyOn(fileAccessApi, "submit").mockReturnValue(new Promise(resolve => { finish = resolve; }));
  const { client } = mount(<FileAccessPage />, `/file-access?control=${controlId}`);
  fireEvent.click(await screen.findByRole("button", { name: "Review restore baseline access" }));
  fireEvent.change(await screen.findByRole("textbox", { name: "Operation reviewed by" }), { target: { value: "reviewer" } });
  fireEvent.click(screen.getByRole("checkbox")); fireEvent.click(screen.getByRole("button", { name: "Restore baseline access" }));
  await waitFor(() => expect(submit).toHaveBeenCalledOnce());
  fireEvent.click(screen.getByRole("link", { name: `Open generated file access, Hardened, revision 3, reference ${ownerId.slice(-8)}` }));
  await screen.findByText("second-generation");
  const response = fileAccessOperationFixture();
  const sent = submit.mock.calls[0]![0]; response.job.job_id = `job-${sent.submission_id.replaceAll("-", "")}`; response.job.progress.submitted_request = sent;
  await act(async () => finish(response));
  expect(screen.getByText("second-generation")).toBeInTheDocument();
  expect(client.getQueryData(["file-access-control", ownerId])).toEqual(second);
  expect(readFileAccessPending()).toBeDefined();
});
it.each([["allowed", "Allowed"], ["permission_denied", "Permission denied"], ["unknown", "Unknown"]] as const)("shows the actual fresh %s endpoint result without receiver fields", (decision, label) => {
  const value = fileAccessObjectiveFixture(decision);
  mount(<CompositionAttempts objective={value} />);
  expect(screen.getByText("Fresh non-owner read").nextElementSibling).toHaveTextContent(label);
  expect(screen.getByText("Probe request cleanup")).toBeInTheDocument();
  expect(screen.queryByText("Receiver cleanup")).not.toBeInTheDocument();
  if (decision !== "permission_denied") expect(screen.queryByText("Objective established")).not.toBeInTheDocument();
});
it("uses the exact v2 request and file-access scope in the existing grant review", async () => {
  const value = fileAccessCompositionReviewFixture(); const review = vi.spyOn(compositionApi, "review").mockResolvedValue(value);
  mount(<CompositionSetup control={controlId} pack={FILE_ACCESS_PACK} disabled={false} onSubmit={vi.fn()} />);
  fireEvent.change(screen.getByRole("textbox", { name: "Objective question" }), { target: { value: value.objective.question } });
  fireEvent.click(screen.getByRole("button", { name: "Review finite delegation" }));
  await screen.findByRole("button", { name: "Issue capability grant" });
  expect(review).toHaveBeenCalledWith({ schema_version: "bluefire.composition-review-request.v2", pack: FILE_ACCESS_PACK, control_owner_id: controlId, question: value.objective.question, limits: null });
  expect(screen.queryByText("Destination")).not.toBeInTheDocument(); expect(screen.getByText("Retained file access")).toBeInTheDocument();
});
it("never renders receiver policy or port for endpoint capabilities", () => {
  mount(<CompositionCapabilities review={fileAccessCompositionReviewFixture()} />);
  expect(screen.queryByText("Retained policy")).not.toBeInTheDocument();
  expect(screen.queryByText(/Loopback port/)).not.toBeInTheDocument();
});
