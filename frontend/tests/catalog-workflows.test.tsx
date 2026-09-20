import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog } from "../src/lib/demo";
import { BehaviorsPage, RunnerProfilesPage } from "../src/pages/CatalogPages";
import type { ActionDefinition, RunnerProfile } from "../src/types";

const action: ActionDefinition = { id: "sandbox.cleanup.v1", title: "Clean up experiment files", purpose: "Remove created files.", safety_tier: "safe", capabilities: ["filesystem.write"], platforms: ["windows", "linux", "macos"], inputs: [], outputs: [], parameters: [] };
const gzip: ActionDefinition = { ...action, id: "sandbox.collection.atomic-gzip.v1", title: "Compress selected records — Atomic gzip", cleanup_action_id: action.id, platforms: ["linux"] };
const chmod: ActionDefinition = { ...action, id: "sandbox.permission.chmod.v1", title: "Change sample file permissions", safety_tier: "controlled", capabilities: ["filesystem.write"], platforms: ["linux"] };
const profile: RunnerProfile = { id: "sample-template.v1", mode: "execute", environment_type: "disposable", platforms: ["windows", "linux", "macos"], scope: ["sandbox.workspace"], network_allowlist: [], capabilities: ["filesystem.write"], safety_tiers: ["safe"], approval_required: true, enabled_actions: [action.id, gzip.id], blocked_actions: [], cleanup_policy: "always", runner_binary: { env: "REVIEWED_RUNNER_BINARY" }, sandbox_root: { env: "REVIEWED_WORKSPACE_ROOT" }, budgets: { max_seconds: 120, max_steps: 20, max_bytes: 8388608 }, secrets: {} };
const chmodProfile: RunnerProfile = { ...profile, id: "chmod-profile.v1", platforms: ["linux"], enabled_actions: ["sandbox.permission.chmod.v1"] };
function setup(page: "profiles" | "methods" = "profiles", selectedProfile: RunnerProfile = profile, resources: unknown[] = [], catalogProfiles: RunnerProfile[] = [selectedProfile]) {
  const catalog = { ...demoCatalog, runner_profiles: catalogProfiles, actions: [action, gzip, chmod] };
  vi.spyOn(api, "catalog").mockResolvedValue(catalog);
  vi.spyOn(api, "resources").mockResolvedValue({ schema_version: "v1", kind: "runner-profiles", resources } as never);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter>{page === "profiles" ? <RunnerProfilesPage/> : <BehaviorsPage/>}</MemoryRouter></QueryClientProvider>);
}

it("does not offer native setup for an active Execute profile", async () => {
  setup("profiles", chmodProfile, [{ id: chmodProfile.id, status: "active", document: chmodProfile }]);
  expect(await screen.findByText("Deactivate this profile before changing its GNU chmod binding.")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Set up GNU chmod" })).not.toBeInTheDocument();
});

it("does not offer native setup for a Simulate profile", async () => {
  setup("profiles", { ...chmodProfile, mode: "simulate" }, [{ id: chmodProfile.id, status: "draft", document: { ...chmodProfile, mode: "simulate" } }]);
  await screen.findByText("simulate");
  expect(screen.queryByRole("button", { name: "Set up GNU chmod" })).not.toBeInTheDocument();
});

it("configures a baseline with its existing identity and saves an inactive draft", async () => {
  setup(); const user = userEvent.setup(); const save = vi.spyOn(api, "saveResource").mockResolvedValue({ schema_version: "v1", resource: { kind: "runner-profiles", id: profile.id, document: profile as unknown as Record<string, unknown>, status: "draft", digest: "sha256:test", created_at: "2026-09-20", updated_at: "2026-09-20" } }); const activate = vi.spyOn(api, "activateResource");
  await user.click(await screen.findByRole("button", { name: "Configure methods" }));
  const dialog = within(screen.getByRole("dialog"));
  expect(dialog.getByDisplayValue(profile.id)).toHaveAttribute("readonly");
  await user.click(dialog.getByRole("button", { name: "Save profile draft" }));
  await waitFor(() => expect(save).toHaveBeenCalledWith("runner-profiles", profile.id, expect.objectContaining({ id: profile.id }), "draft"));
  expect(activate).not.toHaveBeenCalled();
});

it("edits a managed profile absent from the catalog without losing its binding", async () => {
  const custom: RunnerProfile = { ...chmodProfile, id: "managed-custom.v1", safety_tiers: ["controlled"], native_tool_installations: [{ schema_version: "bluefire.native-tool-installation.v1", adapter_id: "sandbox.permission.chmod.v1", adapter_version: "1.0.0", adapter_contract_digest: "sha256:" + "a".repeat(64), tool_id: "gnu.coreutils.chmod.v1", tool_version: "9.4", platform: "linux", architecture: "x86_64", content_sha256: "sha256:" + "b".repeat(64), size_bytes: 1234, installation_location: "/usr/bin/chmod" }] };
  setup("profiles", custom, [{ id: custom.id, status: "draft", document: custom }], []);
  const user = userEvent.setup(); const save = vi.spyOn(api, "saveResource").mockResolvedValue({ schema_version: "v1", resource: { kind: "runner-profiles", id: custom.id, document: custom as unknown as Record<string, unknown>, status: "draft", digest: "sha256:test", created_at: "2026-09-20", updated_at: "2026-09-20" } }); const activate = vi.spyOn(api, "activateResource");
  await user.click(await screen.findByRole("button", { name: "Configure methods" }));
  const dialog = within(screen.getByRole("dialog"));
  expect(dialog.getByDisplayValue(custom.id)).toHaveAttribute("readonly");
  expect(dialog.getByRole("button", { name: "Save profile draft" })).toBeEnabled();
  await user.click(dialog.getByRole("button", { name: "Save profile draft" }));
  await waitFor(() => expect(save).toHaveBeenCalledWith("runner-profiles", custom.id, expect.objectContaining({ native_tool_installations: custom.native_tool_installations }), "draft"));
  expect(activate).not.toHaveBeenCalled();
});

it("requires a real template, filters methods by platform, and retains a refused profile for retry", async () => {
  setup(); const user = userEvent.setup();
  let reject!: (error: Error) => void;
  const pending = new Promise<Awaited<ReturnType<typeof api.saveResource>>>((_, no) => { reject = no; });
  const save = vi.spyOn(api, "saveResource").mockReturnValueOnce(pending);
  const activate = vi.spyOn(api, "activateResource");
  await user.click(await screen.findByRole("button", { name: "New profile" }));
  const dialog = within(screen.getByRole("dialog"));
  expect(dialog.getByRole("button", { name: "Save profile draft" })).toBeDisabled();
  await user.selectOptions(dialog.getByLabelText(/^Configuration template/), profile.id);
  expect(dialog.getByLabelText("Platform")).toHaveValue("windows");
  expect(dialog.getByLabelText(/^Runner binary environment reference/)).toHaveValue("REVIEWED_RUNNER_BINARY");
  expect(dialog.getByLabelText("Sandbox root environment reference")).toHaveValue("REVIEWED_WORKSPACE_ROOT");
  expect(dialog.queryByRole("checkbox", { name: "Compress selected records: Atomic gzip" })).not.toBeInTheDocument();
  expect(dialog.getByRole("checkbox", { name: action.title })).toBeChecked();
  await user.selectOptions(dialog.getByLabelText("Platform"), "linux");
  expect(dialog.getByRole("checkbox", { name: "Compress selected records: Atomic gzip" })).toBeChecked();
  await user.click(dialog.getByRole("checkbox", { name: action.title }));
  expect(dialog.getByRole("alert")).toHaveTextContent("Select the cleanup method");
  expect(dialog.getByRole("button", { name: "Save profile draft" })).toBeDisabled();
  await user.click(dialog.getByRole("checkbox", { name: action.title }));
  await user.click(dialog.getByRole("checkbox", { name: "Compress selected records: Atomic gzip" }));
  await user.clear(dialog.getByLabelText("Time (seconds)"));
  await user.type(dialog.getByLabelText("Time (seconds)"), "60");
  await user.click(dialog.getByRole("button", { name: "Save profile draft" }));
  await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
  expect(dialog.getByRole("button", { name: "Saving" })).toBeDisabled();
  expect(save).toHaveBeenCalledWith("runner-profiles", "local-experiment.v1", expect.objectContaining({ platforms: ["linux"], enabled_actions: [action.id], approval_required: true, scope: ["sandbox.workspace"], budgets: { ...profile.budgets, max_seconds: 60 } }), "draft");
  expect(activate).not.toHaveBeenCalled();
  await act(async () => reject(new Error("Profile ID already exists.")));
  expect(await dialog.findByRole("alert")).toHaveTextContent("already exists");
  expect(dialog.getByLabelText("Profile ID")).toHaveFocus();
  expect(dialog.getByLabelText("Time (seconds)")).toHaveValue(60);
  save.mockImplementationOnce(async (kind, id, document, status) => ({ schema_version: "v1", resource: { kind, id, document, status: status!, digest: "sha256:test", created_at: "2026-09-08", updated_at: "2026-09-08" } }));
  await user.clear(dialog.getByLabelText("Profile ID")); await user.type(dialog.getByLabelText("Profile ID"), "my-profile.v1");
  await user.click(dialog.getByRole("button", { name: "Save profile draft" }));
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  expect(screen.getByRole("button", { name: "New profile" })).toHaveFocus();
  expect(activate).not.toHaveBeenCalled();
});

it("keeps research ideas separate from executable method selection", async () => {
  setup("methods"); const user = userEvent.setup();
  const filter = await screen.findByRole("combobox", { name: "Item type" });
  expect(filter).toHaveValue("methods");
  expect(screen.queryByRole("button", { name: /Credential-access detection research/ })).not.toBeInTheDocument();
  await user.selectOptions(filter, "research");
  expect(screen.getAllByText("Research only").length).toBeGreaterThan(0);
  expect(screen.queryByText("Executable method")).not.toBeInTheDocument();
});
