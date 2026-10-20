import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, useLocation } from "react-router-dom";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { FileAccessPage } from "../src/pages/FileAccess";
import { fileAccessApi, readFileAccessReconciliationPending, type FileAccessOperationEnvelope, type FileAccessReview, type FileAccessSubmission, type WindowsCorrectionFileAccessControl, type WindowsPairFileAccessStatus } from "../src/lib/file-access";
import { request } from "../src/lib/api";
import type { CompositionJob } from "../src/lib/composition";

vi.mock("../src/lib/api", () => ({ DEMO_MODE: false, request: vi.fn(), ApiError: class extends Error {} }));

const owner = "win-file-control-0123456789abcdef0123456789abcdef";
const enrollment = "win-file-enrollment-0123456789abcdef0123456789abcdef";
const digest = (char: string) => `sha256:${char.repeat(64)}`;
const subId = (char: string) => `${char.repeat(8)}-${char.repeat(4)}-4${char.repeat(3)}-8${char.repeat(3)}-${char.repeat(12)}`;
const baselineTime = "2026-10-13T12:00:00.000Z";

function job(operation: "baseline" | "harden", char: string, state: CompositionJob["state"] = "completed"): CompositionJob {
  const submission_id = subId(char);
  return {
    job_id: `job-${submission_id.replaceAll("-", "")}`,
    kind: "file_access.operation",
    state,
    request: {},
    progress: { submitted_request: {
      submission_id,
      review: { operation, control_owner_id: owner },
      review_digest: digest("b"),
      reviewed_by: "synthetic-reviewer",
    } },
  } as CompositionJob;
}

function control(revision: 2 | 3 = 2, state: "settled" | "unknown" = "settled", expires = Date.now() + 60_000): WindowsCorrectionFileAccessControl {
  const baseline = {
    schema_version: "bluefire.windows-file-readable-baseline.v2" as const,
    non_owner: "allowed" as const,
    owner: "allowed" as const,
    size_bytes: 1024,
    sha256: digest("c"),
    resource_generation: "0123456789abcdef0123456789abcdef",
    observed_at: baselineTime,
    native_cleanup: "verified" as const,
    owned_job_cleanup: "verified" as const,
    independent_observation: false as const,
    baseline_digest: digest("d"),
  };
  const baselineOperation = job("baseline", "1");
  const correctionOperation = job("harden", "2", state === "unknown" ? "interrupted" : "completed");
  return {
    schema_version: "bluefire.windows-file-access-control.v3",
    platform: "windows",
    control_owner_id: owner,
    control_digest: digest("e"),
    revision,
    status: state === "unknown" ? "uncertain" : revision === 2 ? "baseline_verified" : "hardened",
    expires_at_ms: expires,
    provenance: { kind: "protected_setup", enrollment_id: enrollment, enrollment_digest: digest("f"), setup_receipt_digest: digest("0") },
    resource: {
      resource_id: "synthetic-windows-resource",
      resource_generation: baseline.resource_generation,
      expected_sha256: baseline.sha256,
      size_bytes: baseline.size_bytes,
      protection: state === "unknown" ? "unknown" : revision === 2 ? "reader_readable" : "metadata_only",
    },
    baseline,
    operations: revision === 2
      ? state === "unknown" ? [baselineOperation, correctionOperation] : [baselineOperation]
      : [baselineOperation, correctionOperation],
    allowed_operations: revision === 2 && state === "settled" ? ["harden"] : [],
    task_usage_state: state === "unknown" ? "unresolved" : "settled",
    account_object_cleanup: "required",
    correction: revision === 3 && state === "settled" ? {
      binding_digest: digest("1"), before_descriptor_sha256: digest("2"), after_descriptor_sha256: digest("3"), owned_control_cleanup: "verified",
    } : null,
    retest: revision === 3 && state === "settled" ? {
      schema_version: "bluefire.windows-file-correction-observation.v3",
      non_owner: "data_access_denied",
      owner: "allowed",
      size_bytes: baseline.size_bytes,
      sha256: baseline.sha256,
      observed_at: "2026-10-13T12:00:05.000Z",
      native_cleanup: "verified",
      owned_job_cleanup: "verified",
      independent_observation: false,
      evidence_digest: digest("4"),
    } : null,
  };
}

function status(expires = Date.now() + 60_000): WindowsPairFileAccessStatus {
  return {
    schema_version: "bluefire.file-access-status.v1", available: true, problem: null, enrollment: null, allowed_operations: [],
    setup: { enrollment_id: enrollment, enrollment_digest: digest("f"), expires_at_ms: expires, verification: "protected_setup_only" },
  };
}

function review(controlValue: WindowsCorrectionFileAccessControl, expires = Date.now() + 60_000): FileAccessReview {
  return {
    schema_version: "bluefire.file-access-control-review.v1", operation: "harden", control_owner_id: owner,
    context_digest: digest("a"), enrollment_digest: controlValue.provenance.enrollment_digest,
    control_digest: controlValue.control_digest, expires_at_ms: expires,
    effect: "Apply the reviewed Windows file-access correction and verify its paired result.", review_digest: digest("b"),
  };
}

function envelope(body: FileAccessSubmission, current: WindowsCorrectionFileAccessControl): FileAccessOperationEnvelope {
  const submitted = body;
  const jobValue = {
    job_id: `job-${body.submission_id.replaceAll("-", "")}`,
    kind: "file_access.operation",
    state: "completed",
    request: {},
    progress: { submitted_request: submitted },
  } as CompositionJob;
  return { schema_version: "bluefire.file-access-operation.v1", job: jobValue, control: current, reconciliation: null, reconciliation_receipt: null };
}

function mount(path = `/file-access?control=${owner}`) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return { ...render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><FileAccessPage /><CurrentLocation /></MemoryRouter></QueryClientProvider>), client };
}
function CurrentLocation() { const location = useLocation(); return <output data-testid="current-location">{location.pathname}{location.search}</output>; }

beforeEach(() => {
  localStorage.clear();
  vi.mocked(request).mockReset();
  vi.spyOn(fileAccessApi, "status").mockResolvedValue(status());
  vi.spyOn(fileAccessApi, "list").mockResolvedValue({ schema_version: "bluefire.file-access-control-list.v1", controls: [{ control_owner_id: owner, platform: "windows", status: "baseline_verified", revision: 2 }] });
  vi.spyOn(fileAccessApi, "control").mockResolvedValue(control());
  vi.spyOn(fileAccessApi, "operation").mockRejectedValue(new Error("No saved operation response"));
  vi.spyOn(fileAccessApi, "review").mockImplementation(async () => review(control()));
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it("submits one explicit harden review bound to the original owner and digest", async () => {
  const baseline = control();
  let current = baseline;
  vi.mocked(fileAccessApi.control).mockImplementation(async () => current);
  const reviewed = review(baseline);
  const getReview = vi.spyOn(fileAccessApi, "review").mockResolvedValue(reviewed);
  const submit = vi.spyOn(fileAccessApi, "submit").mockImplementation(async body => {
    current = control(3);
    return envelope(body, current);
  });
  mount();

  fireEvent.click(await screen.findByRole("button", { name: "Review Windows access change" }));
  expect(await screen.findByText(reviewed.effect)).toBeInTheDocument();
  expect(getReview).toHaveBeenCalledOnce();
  expect(getReview).toHaveBeenCalledWith({ operation: "harden", control_owner_id: owner });
  fireEvent.change(screen.getByLabelText("Operation reviewed by"), { target: { value: "operator" } });
  fireEvent.click(screen.getByRole("checkbox"));
  fireEvent.click(screen.getByRole("button", { name: "Apply owner-only access" }));

  await waitFor(() => expect(submit).toHaveBeenCalledOnce());
  expect(submit.mock.calls[0]![0]).toMatchObject({ review: { operation: "harden", control_owner_id: owner }, review_digest: reviewed.review_digest, reviewed_by: "operator" });
  expect(await screen.findByRole("region", { name: "Windows file-access correction" })).toBeInTheDocument();
  expect(within(screen.getByRole("region", { name: "Windows file-access correction" })).getByText("Retest non-owner data access").nextElementSibling).toHaveTextContent("Denied");
});

it("requires a refreshed review and fresh acknowledgement after the v3 control digest changes", async () => {
  let current = control();
  vi.mocked(fileAccessApi.control).mockImplementation(async () => current);
  let reviewGeneration = 0;
  const getReview = vi.spyOn(fileAccessApi, "review").mockImplementation(async () => {
    reviewGeneration += 1;
    return { ...review(current), control_digest: current.control_digest, review_digest: digest(reviewGeneration === 1 ? "b" : "9") };
  });
  const submit = vi.spyOn(fileAccessApi, "submit").mockImplementation(async body => envelope(body, control(3)));
  mount();

  fireEvent.click(await screen.findByRole("button", { name: "Review Windows access change" }));
  await screen.findByText(/Apply the reviewed Windows file-access correction/);
  fireEvent.change(screen.getByLabelText("Operation reviewed by"), { target: { value: "first-reviewer" } });
  fireEvent.click(screen.getByRole("checkbox"));

  current = { ...current, control_digest: digest("8") };
  fireEvent.click(screen.getByRole("button", { name: "Refresh state" }));
  await screen.findByText("Control changed");
  expect(screen.getByRole("button", { name: "Apply owner-only access" })).toBeDisabled();
  expect(submit).not.toHaveBeenCalled();

  fireEvent.click(screen.getByRole("button", { name: "Refresh operation review" }));
  await waitFor(() => expect(getReview).toHaveBeenCalledTimes(2));
  expect(await screen.findAllByText(digest("8"))).toHaveLength(2);
  expect(screen.getByLabelText("Operation reviewed by")).toHaveValue("");
  expect(screen.getByRole("checkbox")).not.toBeChecked();
  expect(screen.getByRole("button", { name: "Apply owner-only access" })).toBeDisabled();

  fireEvent.change(screen.getByLabelText("Operation reviewed by"), { target: { value: "new-reviewer" } });
  fireEvent.click(screen.getByRole("checkbox"));
  fireEvent.click(screen.getByRole("button", { name: "Apply owner-only access" }));
  await waitFor(() => expect(submit).toHaveBeenCalledOnce());
  expect(submit.mock.calls[0]![0]).toMatchObject({ review_digest: digest("9"), reviewed_by: "new-reviewer", review: { operation: "harden", control_owner_id: owner } });
});

it("disables an open review when the setup is expired or replaced", async () => {
  const current = control();
  vi.mocked(fileAccessApi.control).mockResolvedValue(current);
  const getStatus = vi.mocked(fileAccessApi.status);
  const submit = vi.spyOn(fileAccessApi, "submit");
  mount();
  fireEvent.click(await screen.findByRole("button", { name: "Review Windows access change" }));
  await screen.findByText(/Apply the reviewed Windows file-access correction/);
  fireEvent.change(screen.getByLabelText("Operation reviewed by"), { target: { value: "operator" } });
  fireEvent.click(screen.getByRole("checkbox"));

  getStatus.mockResolvedValue(status(Date.now() - 1000));
  fireEvent.click(screen.getByRole("button", { name: "Refresh state" }));
  await waitFor(() => expect(screen.getByRole("button", { name: "Apply owner-only access" })).toBeDisabled());
  expect(submit).not.toHaveBeenCalled();
});

it("disables an open review when its setup identity is replaced", async () => {
  vi.mocked(fileAccessApi.control).mockResolvedValue(control());
  const getStatus = vi.mocked(fileAccessApi.status);
  const submit = vi.spyOn(fileAccessApi, "submit");
  mount();
  fireEvent.click(await screen.findByRole("button", { name: "Review Windows access change" }));
  await screen.findByText(/Apply the reviewed Windows file-access correction/);
  fireEvent.change(screen.getByLabelText("Operation reviewed by"), { target: { value: "operator" } });
  fireEvent.click(screen.getByRole("checkbox"));

  getStatus.mockResolvedValue({ ...status(), setup: { ...status().setup, enrollment_id: "win-file-enrollment-fedcba9876543210fedcba9876543210", enrollment_digest: digest("9") } });
  fireEvent.click(screen.getByRole("button", { name: "Refresh state" }));
  await waitFor(() => expect(screen.getByRole("button", { name: "Apply owner-only access" })).toBeDisabled());
  expect(submit).not.toHaveBeenCalled();
});

it("keeps baseline reads distinct from hardened denial, owner access, and cleanup proof", async () => {
  const hardened = control(3);
  vi.mocked(fileAccessApi.control).mockResolvedValue(hardened);
  vi.mocked(fileAccessApi.list).mockResolvedValue({ schema_version: "bluefire.file-access-control-list.v1", controls: [{ control_owner_id: owner, platform: "windows", status: "hardened", revision: 3 }] });
  mount();

  const region = await screen.findByRole("region", { name: "Windows file-access correction" });
  expect(within(region).getByText("Baseline non-owner read").nextElementSibling).toHaveTextContent("Allowed");
  expect(within(region).getByText("Baseline owner read").nextElementSibling).toHaveTextContent("Allowed");
  expect(within(region).getByText("Retest non-owner data access").nextElementSibling).toHaveTextContent("Denied");
  expect(within(region).getByText("Retest owner read").nextElementSibling).toHaveTextContent("Allowed, content unchanged");
  expect(within(region).getByText("Control-worker cleanup").nextElementSibling).toHaveTextContent("Verified");
  expect(within(region).getByText("Retest native cleanup").nextElementSibling).toHaveTextContent("Verified");
  expect(within(region).getByText("Retest owned-job cleanup").nextElementSibling).toHaveTextContent("Verified");
  expect(within(region).getByText("Account and object cleanup").nextElementSibling).toHaveTextContent("Required");
  expect(within(region).getByText("Independent observation").nextElementSibling).toHaveTextContent("No");
  expect(within(region).queryByText(/uid|mode|linux/i)).not.toBeInTheDocument();
  expect(within(region).queryByRole("button", { name: /review|rollback|reset|harden/i })).not.toBeInTheDocument();
});

it("preserves selected objective and unrelated query context from v3 operation history", async () => {
  const hardened = control(3);
  vi.mocked(fileAccessApi.control).mockResolvedValue(hardened);
  mount(`/file-access?goal=file-access&context=retained&source=setup&control=${owner}&keep=1`);

  fireEvent.click(await screen.findByText("Saved control operations"));
  const link = await screen.findByRole("link", { name: "Baseline attempt" });
  fireEvent.click(link);
  await waitFor(() => {
    const location = new URL(screen.getByTestId("current-location").textContent!, "http://local.test");
    expect(location.searchParams.get("goal")).toBe("file-access");
    expect(location.searchParams.get("context")).toBe("retained");
    expect(location.searchParams.get("source")).toBe("setup");
    expect(location.searchParams.get("keep")).toBe("1");
    expect(location.searchParams.get("control")).toBe(owner);
    expect(location.searchParams.get("operation")).toBe(job("baseline", "1").job_id);
  });
});

it("explicitly reads an unknown correction attempt without replaying it or claiming success", async () => {
  const uncertain = control(2, "unknown");
  const hardenJob = uncertain.operations[1]!;
  const outcomeDigest = digest("7");
  const original: FileAccessOperationEnvelope = {
    schema_version: "bluefire.file-access-operation.v1",
    job: hardenJob,
    control: uncertain,
    reconciliation: { outcome_digest: outcomeDigest, state: "unknown", available: true },
    reconciliation_receipt: null,
  };
  vi.mocked(fileAccessApi.control).mockResolvedValue(uncertain);
  vi.mocked(fileAccessApi.list).mockResolvedValue({ schema_version: "bluefire.file-access-control-list.v1", controls: [{ control_owner_id: owner, platform: "windows", status: "uncertain", revision: 2 }] });
  vi.mocked(fileAccessApi.operation).mockResolvedValue(original);
  const submit = vi.spyOn(fileAccessApi, "submit");
  const reconcile = vi.spyOn(fileAccessApi, "reconcile").mockImplementation(async (_jobId, body) => ({
    ...original,
    reconciliation_receipt: { submission_id: body.submission_id, submitted_request: body, state: "completed", problem: null },
  }));
  mount(`/file-access?control=${owner}&operation=${hardenJob.job_id}`);

  const region = await screen.findByRole("region", { name: "Windows file-access correction" });
  expect(within(region).getByText("Protection").nextElementSibling).toHaveTextContent("Unknown");
  expect(within(region).getByText("Original attempt is unresolved")).toBeInTheDocument();
  expect(within(region).queryByRole("button", { name: /review|rollback|reset|harden/i })).not.toBeInTheDocument();
  expect(await screen.findByRole("region", { name: "Saved operation" })).toBeInTheDocument();
  fireEvent.click(await screen.findByRole("button", { name: "Review original task evidence" }));
  expect(await screen.findByText(/does not repeat its mutation/)).toBeInTheDocument();
  fireEvent.change(screen.getByRole("textbox", { name: "Evidence review by" }), { target: { value: "evidence-reviewer" } });
  fireEvent.click(screen.getByRole("checkbox"));
  fireEvent.click(screen.getByRole("button", { name: "Read original task evidence" }));

  await waitFor(() => expect(reconcile).toHaveBeenCalledOnce());
  expect(reconcile.mock.calls[0]![0]).toBe(hardenJob.job_id);
  expect(reconcile.mock.calls[0]![1]).toMatchObject({ expected_outcome_digest: outcomeDigest, reviewed_by: "evidence-reviewer" });
  await waitFor(() => expect(readFileAccessReconciliationPending()).toBeUndefined());
  expect(screen.getByText("Original attempt is unresolved")).toBeInTheDocument();
  expect(within(region).getByText("Protection").nextElementSibling).toHaveTextContent("Unknown");
  expect(within(region).getByText("Account and object cleanup").nextElementSibling).toHaveTextContent("Required");
  expect(within(region).queryByText("Retest native cleanup")).not.toBeInTheDocument();
  expect(screen.queryByRole("region", { name: "Verified operation reads" })).not.toBeInTheDocument();
  expect(submit).not.toHaveBeenCalled();
});

it("retains historical paired proof when live status is unavailable without offering mutation", async () => {
  const historical = control(3, "settled", Date.now() - 1000);
  vi.mocked(fileAccessApi.status).mockRejectedValue(new Error("Status unavailable"));
  vi.mocked(fileAccessApi.control).mockResolvedValue(historical);
  vi.mocked(fileAccessApi.list).mockResolvedValue({ schema_version: "bluefire.file-access-control-list.v1", controls: [{ control_owner_id: owner, platform: "windows", status: "hardened", revision: 3 }] });
  const submit = vi.spyOn(fileAccessApi, "submit");
  mount();

  const region = await screen.findByRole("region", { name: "Windows file-access correction" });
  expect(within(region).getByText("Historical")).toBeInTheDocument();
  expect(within(region).getByText("Retest non-owner data access").nextElementSibling).toHaveTextContent("Denied");
  expect(within(region).getByText("Retest owner read").nextElementSibling).toHaveTextContent("Allowed, content unchanged");
  expect(within(region).queryByRole("button", { name: /review|rollback|reset|harden/i })).not.toBeInTheDocument();
  expect(submit).not.toHaveBeenCalled();
});

it("keeps a missing harden response pending and resubmits the exact original identity only", async () => {
  const baseline = control();
  vi.mocked(fileAccessApi.control).mockResolvedValue(baseline);
  vi.spyOn(fileAccessApi, "review").mockResolvedValue(review(baseline));
  const submit = vi.spyOn(fileAccessApi, "submit")
    .mockRejectedValueOnce(new Error("Response lost"))
    .mockImplementation(async body => envelope(body, control(3)));
  mount();

  fireEvent.click(await screen.findByRole("button", { name: "Review Windows access change" }));
  await screen.findByText(/Apply the reviewed Windows file-access correction/);
  fireEvent.change(screen.getByLabelText("Operation reviewed by"), { target: { value: "operator" } });
  fireEvent.click(screen.getByRole("checkbox"));
  fireEvent.click(screen.getByRole("button", { name: "Apply owner-only access" }));
  await screen.findByText("Operation confirmation pending");
  expect(screen.getByText("Operation not confirmed")).toBeInTheDocument();
  const first = submit.mock.calls[0]![0];
  expect(screen.getByRole("button", { name: "Resubmit original request" })).toBeEnabled();

  fireEvent.click(screen.getByRole("button", { name: "Resubmit original request" }));
  await waitFor(() => expect(submit).toHaveBeenCalledTimes(2));
  expect(submit.mock.calls[1]![0]).toEqual(first);
  await waitFor(() => expect(localStorage.getItem("bluefire.file-access.pending.v1")).toBeNull());
  expect(submit.mock.calls[1]![0].submission_id).toBe(first.submission_id);
});
