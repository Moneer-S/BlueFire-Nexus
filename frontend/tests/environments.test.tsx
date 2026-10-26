import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { EnvironmentsPage } from "../src/pages/Environments";
import { api } from "../src/lib/api";
import { adSmbApi } from "../src/lib/ad-smb";
import { fileAccessApi, type WindowsSetupFileAccessStatus } from "../src/lib/file-access";
import { s3Api } from "../src/lib/s3-access";
import { rawAdEnvironments, rawAdList } from "./ad-smb-fixture";
import { s3Environment, s3Hash } from "./s3-access-fixture";

vi.mock("../src/lib/api", async importOriginal => {
  const actual = await importOriginal<typeof import("../src/lib/api")>();
  return { ...actual, DEMO_MODE: false, api: {
    catalog: vi.fn(), resources: vi.fn(), aiAuthorizations: vi.fn(),
  } };
});

const digest = (value: string) => `sha256:${value.repeat(64)}`;
const resource = (kind: string, id: string, status: string, document: Record<string, unknown> = {}) => ({ kind, id, status, digest: digest("a"), created_at: "2026-10-20T00:00:00Z", updated_at: "2026-10-20T00:00:00Z", document });
const catalogWithProviderExpiry = (expiresAt: number) => ({ schema_version: "catalog.v1", modes: [], ai: { enabled: true, independent_of_mode: true, authority: "local", providers: [{ provider_id: "provider.local.v1", kind: "openai_responses", model: "test-model", health: { state: "ready", lab_session_expires_at_ms: expiresAt } }] }, behaviors: [], actions: [], runner_profiles: [] });
const windowsSetup = (): WindowsSetupFileAccessStatus => ({
  schema_version: "bluefire.file-access-status.v1" as const, available: false,
  problem: { code: "windows_native_admission_unavailable", message: "Protected setup is verified. Native task admission is not available." },
  enrollment: null, allowed_operations: [],
  setup: { enrollment_id: "win-file-enrollment-0123456789abcdef0123456789abcdef", enrollment_digest: digest("b"), expires_at_ms: Date.now() + 60_000, verification: "protected_setup_only" as const },
});

function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return { ...render(<QueryClientProvider client={client}><MemoryRouter><EnvironmentsPage /></MemoryRouter></QueryClientProvider>), client };
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.spyOn(s3Api, "environments").mockResolvedValue({ schema_version: "bluefire.s3-environments.v1", environments: [{ environment: structuredClone(s3Environment), available: true, problem: null, context_digest: s3Hash }], problem: null });
  vi.spyOn(fileAccessApi, "status").mockResolvedValue(windowsSetup());
  vi.spyOn(fileAccessApi, "list").mockResolvedValue({ schema_version: "bluefire.file-access-control-list.v1", controls: [{ control_owner_id: `win-file-control-${"c".repeat(32)}`, status: "setup_verified", revision: 1, platform: "windows" }] });
  vi.spyOn(adSmbApi, "environments").mockResolvedValue(rawAdEnvironments());
  vi.spyOn(adSmbApi, "list").mockResolvedValue(rawAdList());
  vi.mocked(api.catalog).mockResolvedValue({ schema_version: "catalog.v1", modes: [], ai: { enabled: true, independent_of_mode: true, authority: "local", providers: [{ provider_id: "provider.local.v1", kind: "openai_responses", model: "test-model", health: { state: "ready" } }] }, behaviors: [], actions: [], runner_profiles: [] });
  vi.mocked(api.resources).mockImplementation(async kind => ({ schema_version: "bluefire.resource-list.v1", kind, resources: kind === "runner-profiles" ? [resource(kind, "profile.execute.v1", "active")] : kind === "model-providers" ? [resource(kind, "provider.local.v1", "active")] : [] }));
  vi.mocked(api.aiAuthorizations).mockResolvedValue({ schema_version: "bluefire.ai-live-authorizations.v1", context: { kind: "direct", binding_digest: null, expires_at_ms: null, provider: null }, authorizations: [] });
});

afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.useRealTimers(); });

it("shows checked environment readiness separately from saved setup and links to canonical tools", async () => {
  mount();
  expect(await screen.findByText("Synthetic S3 review")).toBeVisible();
  expect(screen.getByText("Setup saved")).toBeVisible();
  expect(screen.getByText(/Protected setup is verified/)).toBeVisible();
  expect(screen.getByText("1 saved control.")).toBeVisible();
  expect(screen.getAllByText("Ready for review").length).toBe(1);
  expect(screen.getAllByText("Expired").length).toBeGreaterThan(0);
  expect(screen.getByText(/Synthetic fixture/)).toBeVisible();
  expect(screen.getByRole("link", { name: "Open S3 access" })).toHaveAttribute("href", "/s3-access");
  expect(screen.getByRole("link", { name: "Open file access" })).toHaveAttribute("href", "/file-access");
  expect(screen.getByRole("link", { name: "Open AD share access" })).toHaveAttribute("href", "/ad-smb");
  expect(screen.getByRole("link", { name: "Open Runners" })).toHaveAttribute("href", "/runners");
  expect(screen.getByRole("link", { name: "Open model connection settings" })).toHaveAttribute("href", "/settings#model-connection");
  expect(screen.getAllByText("Inventory details")).toHaveLength(3);
  fireEvent.click(screen.getAllByText("Inventory details")[0]!);
  expect(screen.getByText("0 catalog profiles · 1 active saved profiles · 1 saved profile records.")).toBeVisible();
});

it("keeps independent sections visible when one local status source fails", async () => {
  vi.mocked(s3Api.environments).mockRejectedValueOnce(new Error("S3 status unavailable"));
  vi.mocked(adSmbApi.environments).mockRejectedValueOnce(new Error("AD status unavailable"));
  mount();
  expect(await screen.findByText("Setup saved")).toBeVisible();
  expect(await screen.findByText("S3 enrollment unavailable")).toBeVisible();
  expect(await screen.findByText("AD environment readiness unavailable")).toBeVisible();
});

it("keeps the all-empty overview compact, truthful, and actionable", async () => {
  const cloudProblem = "No S3 environment is enrolled. Account, roles, generated objects, protected runtime and finite spending authority are required.";
  vi.mocked(s3Api.environments).mockResolvedValue({ schema_version: "bluefire.s3-environments.v1", environments: [], problem: cloudProblem });
  vi.mocked(fileAccessApi.list).mockResolvedValue({ schema_version: "bluefire.file-access-control-list.v1", controls: [] });
  vi.mocked(adSmbApi.environments).mockResolvedValue({ native_execution_available: false, environments: [] });
  vi.mocked(adSmbApi.list).mockResolvedValue(rawAdList([]));

  mount();

  expect(await screen.findByText(cloudProblem, { exact: true })).toBeVisible();
  expect(screen.getAllByText(cloudProblem, { exact: true })).toHaveLength(1);
  expect(await screen.findByText(/Native execution: not reported available/)).toBeVisible();
  expect(screen.getByText("0 saved controls.")).toBeVisible();
  expect(screen.getByText("History")).toBeVisible();
  expect(screen.getByRole("link", { name: "Open S3 access" })).toHaveAttribute("href", "/s3-access");
  expect(screen.getByRole("link", { name: "Open file access" })).toHaveAttribute("href", "/file-access");
  expect(screen.getByRole("link", { name: "Open AD share access" })).toHaveAttribute("href", "/ad-smb");
});

it("uses read APIs only and does not treat synthetic AD setup as native availability", async () => {
  mount();
  expect(await screen.findByText(/Native execution: not reported available/)).toBeVisible();
  expect(api.resources).toHaveBeenCalledWith("runner-profiles");
  expect(api.resources).toHaveBeenCalledWith("runners");
  expect(api.resources).toHaveBeenCalledWith("model-providers");
  expect(s3Api.environments).toHaveBeenCalledTimes(1);
  expect(fileAccessApi.status).toHaveBeenCalledTimes(1);
  expect(adSmbApi.environments).toHaveBeenCalledTimes(1);
  expect(adSmbApi.list).toHaveBeenCalledTimes(1);
  expect(api.aiAuthorizations).toHaveBeenCalledTimes(1);
});

it("marks provider lab readiness expired initially and when its known session expires", async () => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2030-01-01T00:00:00Z"));
  vi.mocked(api.catalog).mockResolvedValue(catalogWithProviderExpiry(Date.now() - 1));
  mount();
  await act(async () => { await vi.advanceTimersByTimeAsync(0); });
  expect(screen.getByText("Session expired")).toBeVisible();

  cleanup();
  vi.mocked(api.catalog).mockResolvedValue(catalogWithProviderExpiry(Date.now() + 100));
  mount();
  await act(async () => { await vi.advanceTimersByTimeAsync(0); });
  expect(screen.getByText("Ready")).toBeVisible();
  await act(async () => { await vi.advanceTimersByTimeAsync(101); });
  expect(screen.getByText("Session expired")).toBeVisible();
});

it("rechecks provider readiness if the wall clock moves behind a scheduled expiry", async () => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2030-01-01T00:00:00Z"));
  vi.mocked(api.catalog).mockResolvedValue(catalogWithProviderExpiry(Date.now() + 100));
  mount();
  await act(async () => { await vi.advanceTimersByTimeAsync(0); });
  expect(screen.getByText("Ready")).toBeVisible();

  vi.setSystemTime(Date.now() - 1);
  await act(async () => { await vi.advanceTimersByTimeAsync(100); });
  expect(screen.getByText("Ready")).toBeVisible();
  await act(async () => { await vi.advanceTimersByTimeAsync(1); });
  expect(screen.getByText("Session expired")).toBeVisible();
});

it("rechecks provider readiness after a clamped long expiry timer", async () => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2030-01-01T00:00:00Z"));
  vi.mocked(api.catalog).mockResolvedValue(catalogWithProviderExpiry(Date.now() + 2_147_483_652));
  mount();
  await act(async () => { await vi.advanceTimersByTimeAsync(0); });
  expect(screen.getByText("Ready")).toBeVisible();

  await act(async () => { await vi.advanceTimersByTimeAsync(2_147_483_647); });
  expect(screen.getByText("Ready")).toBeVisible();
  await act(async () => { await vi.advanceTimersByTimeAsync(5); });
  expect(screen.getByText("Session expired")).toBeVisible();
});

it("cancels the provider expiry timer when the environments page unmounts", async () => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2030-01-01T00:00:00Z"));
  vi.mocked(api.catalog).mockResolvedValue(catalogWithProviderExpiry(Date.now() + 100));
  const view = mount();
  await act(async () => { await vi.advanceTimersByTimeAsync(0); });
  expect(vi.getTimerCount()).toBeGreaterThan(0);

  view.unmount();
  view.client.clear();
  expect(vi.getTimerCount()).toBe(0);
});

it("does not preserve available file-access copy after setup expiration", async () => {
  const setup = windowsSetup();
  vi.mocked(fileAccessApi.status).mockResolvedValue({ ...setup, available: true, problem: null, setup: { ...setup.setup, expires_at_ms: Date.now() - 1 } });
  mount();
  expect(await screen.findByText("Saved setup has expired.")).toBeVisible();
  const fileSection = screen.getByRole("region", { name: "File access" });
  expect(within(fileSection).getByText("Expired")).toBeVisible();
  expect(within(fileSection).queryByText("Available for reviewed file operations.")).not.toBeInTheDocument();

  cleanup();
  vi.mocked(fileAccessApi.status).mockResolvedValue({ ...setup, available: true, problem: null, setup: { ...setup.setup, expires_at_ms: Date.now() + 300 } });
  mount();
  expect(await screen.findByText("Available for review")).toBeVisible();
  expect(await screen.findByText("Saved setup has expired.", {}, { timeout: 2_000 })).toBeVisible();
  expect(within(screen.getByRole("region", { name: "File access" })).queryByText("Available for reviewed file operations.")).not.toBeInTheDocument();
});

it("reports a valid enrollment without available operations as unavailable, not expired", async () => {
  vi.mocked(fileAccessApi.status).mockResolvedValue({ schema_version: "bluefire.file-access-status.v1", available: false, problem: { code: "native_admission_unavailable", message: "Enrollment is current, but native admission is unavailable." }, enrollment: { enrollment_id: "current-enrollment", enrollment_digest: digest("d"), expires_at_ms: Date.now() + 60_000, owner_uid: 1000, probe_uid: 1002 }, allowed_operations: [] });
  mount();
  const fileSection = screen.getByRole("region", { name: "File access" });
  expect(await within(fileSection).findByText("Unavailable")).toBeVisible();
  expect(within(fileSection).getByText("Enrollment is current, but native admission is unavailable.")).toBeVisible();
  expect(within(fileSection).queryByText("Expired")).not.toBeInTheDocument();
});
