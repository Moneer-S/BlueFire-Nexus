import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation } from "react-router-dom";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { SavedDefensiveWork } from "../src/components/SavedDefensiveWork";
import { api } from "../src/lib/api";
import { adSmbApi } from "../src/lib/ad-smb";
import { fileAccessApi, type FileAccessControlList } from "../src/lib/file-access";
import type { ReceiverTestList } from "../src/lib/receiver-defense-types";
import { loadSavedWork } from "../src/lib/saved-defensive-work";
import { s3Api } from "../src/lib/s3-access";
import { rawAdList, rawAdWorkflow } from "./ad-smb-fixture";

const owner = `job-${"1".repeat(32)}`;
const receiver = (): ReceiverTestList => ({ schema_version: "bluefire.receiver-defense-list.v1", jobs: [{ job_id: owner, title: "Retained redaction test", status: "blocked", phase: "protected", updated_at: null, native_path: "https://invalid.test/ignored" }], truncated: false, next_cursor: null });
const clients: QueryClient[] = [];
beforeEach(() => {
  vi.spyOn(api, "receiverTests").mockResolvedValue(receiver());
  vi.spyOn(fileAccessApi, "list").mockResolvedValue({ schema_version: "bluefire.file-access-control-list.v1", controls: [{ control_owner_id: owner, status: "recovery_required", revision: 3 }] });
  vi.spyOn(adSmbApi, "list").mockResolvedValue(rawAdList([rawAdWorkflow({ pending: `job-${"2".repeat(32)}` })]));
  vi.spyOn(s3Api, "list").mockResolvedValue({ schema_version: "bluefire.s3-exercise-list.v1", exercises: [{ workflow_job_id: owner, name: "Synthetic bucket exercise", bucket: "generated-example", policy_state: "hardened", updated_at: "2026-10-11T00:00:00Z" }], truncated: false });
});
afterEach(() => { clients.splice(0).forEach(client => client.clear()); });
function Location() { return <output aria-label="Location">{useLocation().search}</output>; }
function mount(path = "/", client = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } } })) {
  clients.push(client);
  return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><SavedDefensiveWork /><Location /></MemoryRouter></QueryClientProvider>);
}

it("opens the exact saved handoff without trusting supplied navigation or reading other families", async () => {
  const create = vi.spyOn(api, "createReceiverTest"), prepare = vi.spyOn(api, "prepareReceiver");
  localStorage.setItem("retained-draft", "unchanged");
  mount();
  expect(await screen.findByRole("link", { name: /Retained redaction test/ })).toHaveAttribute("href", `/compare?receiver_job=${owner}`);
  expect(screen.getByText("Blocked")).toBeVisible();
  expect(fileAccessApi.list).not.toHaveBeenCalled(); expect(adSmbApi.list).not.toHaveBeenCalled(); expect(s3Api.list).not.toHaveBeenCalled();
  expect(create).not.toHaveBeenCalled(); expect(prepare).not.toHaveBeenCalled();
  expect(localStorage.getItem("retained-draft")).toBe("unchanged");
});

it.each([
  ["file", "File access", "Generated file access", `/file-access?control=${owner}`, "Recovery required"],
  ["domain", "Domain access", "member.lab.example.test", `/ad-smb?workflow=${owner}`, "Unsettled operation"],
  ["cloud", "S3 access", "Synthetic bucket exercise", `/s3-access?exercise=${owner}`, "Hardened"],
])("restores the %s family from its URL with exact saved-work links", async (family, tab, title, href, status) => {
  mount(`/?work=${family}&context=retained`);
  expect(screen.getByRole("tab", { name: tab })).toHaveAttribute("aria-selected", "true");
  expect(await screen.findByRole("link", { name: new RegExp(title) })).toHaveAttribute("href", href);
  expect(screen.getByText(status)).toBeVisible(); expect(screen.getByText("Recorded state")).toBeVisible();
  expect(api.receiverTests).not.toHaveBeenCalled();
  expect(screen.queryByText(/Ready|Prevented|Objective completed/)).not.toBeInTheDocument();
  if (family === "domain") expect(screen.getByText(/Synthetic fixture/)).toBeVisible();
});

it("switches families with keyboard focus and retains unrelated URL context", async () => {
  const user = userEvent.setup(); mount("/?context=retained");
  await screen.findByText("Retained redaction test");
  screen.getByRole("tab", { name: "Data handoff" }).focus();
  await user.keyboard("{ArrowRight}");
  expect(screen.getByRole("tab", { name: "File access" })).toHaveFocus();
  expect(await screen.findByText("Generated file access")).toBeVisible();
  expect(screen.getByLabelText("Location")).toHaveTextContent("?context=retained&work=file");
  await user.keyboard("{End}");
  expect(screen.getByRole("tab", { name: "S3 access" })).toHaveFocus();
  await screen.findByText("Synthetic bucket exercise");
  await user.keyboard("{Home}");
  expect(screen.getByRole("tab", { name: "Data handoff" })).toHaveFocus();
});

it("shows unavailable history separately from empty history and retries just that family", async () => {
  vi.mocked(fileAccessApi.list).mockRejectedValueOnce(new Error("Saved controls unavailable"))
    .mockResolvedValue({ schema_version: "bluefire.file-access-control-list.v1", controls: [] });
  const user = userEvent.setup(); mount("/?work=file");
  expect(await screen.findByText("File access history unavailable")).toBeVisible();
  expect(screen.queryByText("No saved file access work.")).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Try again" }));
  expect(await screen.findByText("No saved file access work.")).toBeVisible();
  expect(fileAccessApi.list).toHaveBeenCalledTimes(2); expect(api.receiverTests).not.toHaveBeenCalled();
});

it("keeps late results bound to their original family", async () => {
  let finish!: (value: ReceiverTestList) => void;
  vi.mocked(api.receiverTests).mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  const user = userEvent.setup(); mount();
  await user.click(screen.getByRole("tab", { name: "File access" }));
  await screen.findByText("Generated file access");
  await act(async () => finish(receiver()));
  expect(screen.queryByText("Retained redaction test")).not.toBeInTheDocument();
  expect(screen.getByText("Recovery required")).toBeVisible();
});

it("preserves cached records on refresh failure and marks them as stale", async () => {
  const user = userEvent.setup(); mount(); await screen.findByText("Retained redaction test");
  vi.mocked(api.receiverTests).mockRejectedValue(new Error("Service stopped"));
  await user.click(screen.getByRole("button", { name: "Refresh data handoff history" }));
  expect(await screen.findByText("Previously loaded records. Their current state could not be checked.")).toBeVisible();
  expect(screen.getByRole("link", { name: /Retained redaction test/ })).toBeVisible();
  expect(screen.queryByText("No saved data handoff work.")).not.toBeInTheDocument();
});

it("bounds the overview rows and exposes omitted history without claiming it is empty", async () => {
  const value = receiver(); value.jobs = Array.from({ length: 8 }, (_, index) => ({ ...value.jobs[0]!, job_id: `job-${String(index).repeat(32)}`, title: `Saved handoff ${index}` }));
  vi.mocked(api.receiverTests).mockResolvedValue(value); mount();
  await screen.findByText("Saved handoff 0");
  expect(within(screen.getByRole("tabpanel")).getAllByRole("listitem")).toHaveLength(5);
  expect(screen.getByText("More saved records are available in this workflow.")).toBeVisible();
  expect(screen.getByRole("link", { name: "Open data handoff workspace" })).toHaveAttribute("href", "/compare?receiver=1");
});

it("shows the newest five file controls without reordering the server list", async () => {
  const controls = Array.from({ length: 8 }, (_, index) => ({
    control_owner_id: `job-${String(index + 1).repeat(32)}`, status: "recovery_required" as const, revision: index + 1,
  }));
  const value: FileAccessControlList = { schema_version: "bluefire.file-access-control-list.v1", controls };
  const originalIds = controls.map(control => control.control_owner_id);
  vi.mocked(fileAccessApi.list).mockResolvedValue(value);

  const result = await loadSavedWork("file");

  expect(result.rows.map(row => row.id)).toEqual(originalIds.slice(-5).reverse());
  expect(result.more).toBe(true);
  expect(value.controls).toBe(controls);
  expect(value.controls.map(control => control.control_owner_id)).toEqual(originalIds);
});

it("shows the newest five domain workflows without reordering the server list", async () => {
  const value = rawAdList(Array.from({ length: 8 }, (_, index) => rawAdWorkflow({ id: `job-${String(index + 1).repeat(32)}` })));
  const workflows = value.workflows;
  const originalIds = workflows.map(item => item.workflow_job_id);
  vi.mocked(adSmbApi.list).mockResolvedValue(value);

  const result = await loadSavedWork("domain");

  expect(result.rows.map(row => row.id)).toEqual(originalIds.slice(-5).reverse());
  expect(result.more).toBe(true);
  expect(value.workflows).toBe(workflows);
  expect(value.workflows.map(item => item.workflow_job_id)).toEqual(originalIds);
});

it("refuses invalid saved identities without creating links from them", async () => {
  const value = receiver(); value.jobs[0]!.job_id = "../../arbitrary";
  vi.mocked(api.receiverTests).mockResolvedValue(value); mount();
  expect(await screen.findByText("Data handoff history unavailable")).toBeVisible();
  expect(screen.queryByRole("link", { name: /Retained redaction test/ })).not.toBeInTheDocument();
});

it("does not dispatch a mutation when opening a saved scope or recovering its list", async () => {
  const submit = vi.spyOn(fileAccessApi, "submit"), reconcile = vi.spyOn(fileAccessApi, "reconcile"), review = vi.spyOn(fileAccessApi, "review");
  const user = userEvent.setup(); mount("/?work=file");
  await screen.findByText("Generated file access");
  await user.click(screen.getByRole("button", { name: "Refresh file access history" }));
  await waitFor(() => expect(fileAccessApi.list).toHaveBeenCalledTimes(2));
  expect(submit).not.toHaveBeenCalled(); expect(reconcile).not.toHaveBeenCalled(); expect(review).not.toHaveBeenCalled();
});
