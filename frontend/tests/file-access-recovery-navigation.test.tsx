import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation } from "react-router-dom";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { FileAccessPage } from "../src/pages/FileAccess";
import { request } from "../src/lib/api";
import { fileAccessApi, type FileAccessOperationEnvelope, type FileAccessSubmission } from "../src/lib/file-access";
import { controlId, testDigest } from "./composition-fixture";
import { fileAccessControlFixture, fileAccessOperationFixture, fileAccessStatusFixture, fileAccessSubmissionFixture } from "./file-access-fixture";

vi.mock("../src/lib/api", () => ({ DEMO_MODE: false, request: vi.fn(), ApiError: class extends Error {} }));

function savedOperation(submissionId: string, operation: FileAccessSubmission["review"]["operation"], state: string) {
  const value = fileAccessOperationFixture().job;
  value.job_id = `job-${submissionId.replaceAll("-", "")}`;
  value.state = state;
  value.progress.submitted_request = { ...fileAccessSubmissionFixture(), submission_id: submissionId, review: { operation, control_owner_id: controlId } };
  return value;
}
const first = () => savedOperation("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee", "harden", "interrupted");
const second = () => savedOperation("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "rollback", "failed");
function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  function Location() { const location = useLocation(); return <output data-testid="location">{location.pathname}{location.search}</output>; }
  return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/file-access?goal=file-access&context=original&control=${controlId}`]}><FileAccessPage /><Location /></MemoryRouter></QueryClientProvider>);
}
function uncertainControl() {
  return { ...fileAccessControlFixture(), status: "uncertain" as const, usage_state: "unknown" as const, allowed_operations: [], operations: [first(), second()] };
}
beforeEach(() => {
  localStorage.clear();
  vi.mocked(request).mockReset();
  vi.spyOn(fileAccessApi, "status").mockResolvedValue(fileAccessStatusFixture());
  vi.spyOn(fileAccessApi, "list").mockResolvedValue({ schema_version: "bluefire.file-access-control-list.v1", controls: [] });
  vi.spyOn(fileAccessApi, "control").mockResolvedValue(uncertainControl());
  vi.spyOn(fileAccessApi, "review");
  vi.spyOn(fileAccessApi, "submit");
  vi.spyOn(fileAccessApi, "reconcile");
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it("shows every exact saved candidate in recorded order without selecting or guessing an operation", async () => {
  mount();
  const retained = within(await screen.findByRole("region", { name: "Retained file-access control" }));
  const navigation = within(retained.getByRole("navigation", { name: "Inspect saved operations" }));
  const links = navigation.getAllByRole("link");
  expect(links.map(link => link.textContent)).toEqual([
    "Inspect operation 1 Apply owner-only access Interrupted",
    "Inspect operation 2 Restore baseline access Failed",
  ]);
  expect(links.map(link => link.getAttribute("href"))).toEqual([first(), second()].map(job => `/file-access?goal=file-access&context=original&control=${controlId}&operation=${job.job_id}`));
  for (const job of [first(), second()]) {
    const reference = navigation.getByText(job.job_id).closest("details");
    expect(reference).not.toHaveAttribute("open");
    expect(links.every(link => !link.textContent?.includes(job.job_id))).toBe(true);
  }
  expect(retained.getByText("Saved control operations").closest("details")).not.toHaveAttribute("open");
  expect(screen.getByTestId("location")).not.toHaveTextContent("operation=");
  expect(request).not.toHaveBeenCalled();
  expect(fileAccessApi.review).not.toHaveBeenCalled();
  expect(fileAccessApi.submit).not.toHaveBeenCalled();
  expect(fileAccessApi.reconcile).not.toHaveBeenCalled();
});

it.each([true, false])("keyboard navigation reads only the selected original operation; reconciliation available=%s keeps its gate", async available => {
  const user = userEvent.setup();
  const selected = second();
  const envelope: FileAccessOperationEnvelope = { ...fileAccessOperationFixture(), job: selected, control: uncertainControl(), reconciliation: { outcome_digest: testDigest, state: "unknown", available } };
  vi.mocked(request).mockImplementation(async (path, options) => {
    expect(path).toBe(`/file-access/operations/${selected.job_id}`);
    expect(options).toBeUndefined();
    return envelope;
  });
  mount();
  const navigation = within(await screen.findByRole("navigation", { name: "Inspect saved operations" }));
  const link = navigation.getByRole("link", { name: "Inspect operation 2 Restore baseline access Failed" });
  link.focus();
  expect(link).toHaveFocus();
  await user.keyboard("{Enter}");
  await screen.findByRole("region", { name: "Saved operation" });
  expect(screen.getByTestId("location")).toHaveTextContent(`control=${controlId}&operation=${selected.job_id}`);
  expect(request).toHaveBeenCalled();
  expect(fileAccessApi.review).not.toHaveBeenCalled();
  expect(fileAccessApi.submit).not.toHaveBeenCalled();
  expect(fileAccessApi.reconcile).not.toHaveBeenCalled();
  if (available) {
    await user.click(await screen.findByRole("button", { name: "Review original task evidence" }));
    const read = screen.getByRole("button", { name: "Read original task evidence" });
    expect(read).toBeDisabled();
    const acknowledgement = screen.getByRole("checkbox");
    expect(acknowledgement).not.toBeChecked();
    await user.click(acknowledgement);
    expect(read).toBeDisabled();
    await user.type(screen.getByRole("textbox", { name: "Evidence review by" }), "reviewer");
    expect(read).toBeEnabled();
    expect(fileAccessApi.reconcile).not.toHaveBeenCalled();
    expect(fileAccessApi.submit).not.toHaveBeenCalled();
  } else {
    expect(screen.queryByRole("button", { name: "Review original task evidence" })).not.toBeInTheDocument();
    expect(screen.queryByRole("textbox", { name: "Evidence review by" })).not.toBeInTheDocument();
  }
});

it("promotes recorded operations beside reset-required guidance without requesting reset or reconciliation", async () => {
  vi.mocked(fileAccessApi.control).mockResolvedValue({ ...uncertainControl(), status: "recovery_required", usage_state: "settled", allowed_operations: ["reset"] });
  mount();
  await screen.findByText("Reset required");
  expect(screen.getByRole("navigation", { name: "Inspect saved operations" })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Review reset generated resource" })).toBeEnabled();
  expect(request).not.toHaveBeenCalled();
  expect(fileAccessApi.review).not.toHaveBeenCalled();
  expect(fileAccessApi.submit).not.toHaveBeenCalled();
  expect(fileAccessApi.reconcile).not.toHaveBeenCalled();
});

it("keeps saved-operation reads reachable when current host readiness is unavailable", async () => {
  const user = userEvent.setup();
  const selected = first();
  const saved = { ...uncertainControl(), status: "recovery_required" as const, usage_state: "settled" as const, allowed_operations: ["reset" as const] };
  vi.mocked(fileAccessApi.status).mockRejectedValue(new Error("Current host status unavailable"));
  vi.mocked(fileAccessApi.control).mockResolvedValue(saved);
  vi.mocked(request).mockImplementation(async (path, options) => {
    expect(path).toBe(`/file-access/operations/${selected.job_id}`);
    expect(options).toBeUndefined();
    return { ...fileAccessOperationFixture(), job: selected, control: saved, reconciliation: { outcome_digest: testDigest, state: "unknown", available: true } };
  });
  mount();
  await screen.findByText("Task access could not be checked");
  const navigation = within(await screen.findByRole("navigation", { name: "Inspect saved operations" }));
  expect(request).not.toHaveBeenCalled();
  const link = navigation.getByRole("link", { name: "Inspect operation 1 Apply owner-only access Interrupted" });
  link.focus();
  await user.keyboard("{Enter}");
  await screen.findByRole("region", { name: "Saved operation" });
  expect(request).toHaveBeenCalled();
  expect(screen.queryByRole("button", { name: "Review reset generated resource" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Review original task evidence" })).not.toBeInTheDocument();
  expect(fileAccessApi.review).not.toHaveBeenCalled();
  expect(fileAccessApi.submit).not.toHaveBeenCalled();
  expect(fileAccessApi.reconcile).not.toHaveBeenCalled();
});

it.each(["settled", "missing operations"])("does not invent recovery candidates for %s saved work", async kind => {
  vi.mocked(fileAccessApi.control).mockResolvedValue(kind === "settled" ? { ...fileAccessControlFixture(), operations: [first()] } : { ...uncertainControl(), operations: [] });
  mount();
  await screen.findByRole("region", { name: "Retained file-access control" });
  expect(screen.queryByRole("navigation", { name: "Inspect saved operations" })).not.toBeInTheDocument();
  expect(request).not.toHaveBeenCalled();
});
