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

it("offers only the two enabled native-tool setups on an inactive Linux profile", async () => {
  const dual: RunnerProfile = { ...chmodProfile, enabled_actions: [chmod.id, gzip.id, "sandbox.unreviewed-tool.v1"] };
  setup("profiles", dual, [{ id: dual.id, status: "draft", document: dual }]);
  expect(await screen.findByRole("button", { name: `Set up GNU chmod for Chmod profile (${dual.id})` })).toBeEnabled();
  expect(screen.getByRole("button", { name: `Set up GNU gzip for Chmod profile (${dual.id})` })).toBeEnabled();
  expect(screen.getAllByRole("button", { name: /^Set up GNU/ })).toHaveLength(2);
  expect(screen.getByText("GNU chmod binding")).toBeVisible();
  expect(screen.getByText("GNU gzip binding")).toBeVisible();
});

it.each(["active", "simulate", "baseline", "other-platform", "disabled-method"])("does not offer gzip setup for a %s profile", async reason => {
  const selected: RunnerProfile = { ...chmodProfile, enabled_actions: reason === "disabled-method" ? [chmod.id] : [gzip.id], mode: reason === "simulate" ? "simulate" : "execute", platforms: reason === "other-platform" ? ["windows"] : ["linux"] };
  setup("profiles", selected, reason === "baseline" ? [] : [{ id: selected.id, status: reason === "active" ? "active" : "draft", document: selected }]);
  await screen.findByRole("heading", { name: "Chmod profile" });
  expect(screen.queryByRole("button", { name: /^Set up GNU gzip/ })).not.toBeInTheDocument();
  if (reason === "active") expect(screen.getByText("Deactivate this profile before changing its GNU gzip binding.")).toBeVisible();
});

it("configures a baseline with its existing identity and saves an inactive draft", async () => {
  setup(); const user = userEvent.setup(); const save = vi.spyOn(api, "saveResource").mockResolvedValue({ schema_version: "v1", resource: { kind: "runner-profiles", id: profile.id, document: profile as unknown as Record<string, unknown>, status: "draft", digest: "sha256:test", created_at: "2026-09-20", updated_at: "2026-09-20" } }); const activate = vi.spyOn(api, "activateResource");
  await user.click(await screen.findByRole("button", { name: "Configure methods for Sample template (sample-template.v1)" }));
  const dialog = within(screen.getByRole("dialog"));
  expect(dialog.getByDisplayValue(profile.id)).toHaveAttribute("readonly");
  await user.click(dialog.getByRole("button", { name: "Save profile draft" }));
  await waitFor(() => expect(save).toHaveBeenCalledWith("runner-profiles", profile.id, expect.objectContaining({ id: profile.id }), "draft"));
  expect(activate).not.toHaveBeenCalled();
});

it("explicitly selects optional gzip from a native-only default before setup", async () => {
  const baseline: RunnerProfile = { ...profile, enabled_actions: [action.id] };
  setup("profiles", baseline);
  const user = userEvent.setup();
  const save = vi.spyOn(api, "saveResource").mockResolvedValue({ schema_version: "v1", resource: { kind: "runner-profiles", id: baseline.id, document: baseline as unknown as Record<string, unknown>, status: "draft", digest: "sha256:test", created_at: "2026-09-22", updated_at: "2026-09-22" } });
  const activate = vi.spyOn(api, "activateResource");
  const inspect = vi.spyOn(api, "inspectNativeToolCandidate");
  await user.click(await screen.findByRole("button", { name: "Configure methods for Sample template (sample-template.v1)" }));
  const dialog = within(screen.getByRole("dialog"));
  await user.selectOptions(dialog.getByLabelText("Platform"), "linux");
  const choice = dialog.getByRole("checkbox", { name: "Compress selected records: Atomic gzip" });
  expect(choice).not.toBeChecked();
  await user.click(choice);
  await user.click(dialog.getByRole("button", { name: "Save profile draft" }));
  await waitFor(() => expect(save).toHaveBeenCalledWith("runner-profiles", baseline.id, expect.objectContaining({ platforms: ["linux"], enabled_actions: [action.id, gzip.id], native_tool_installations: undefined }), "draft"));
  expect(inspect).not.toHaveBeenCalled();
  expect(activate).not.toHaveBeenCalled();
});

it("requires a versioned profile ID before saving and preserves configuration while correcting it", async () => {
  setup();
  const user = userEvent.setup();
  const id = "gzip-ui-1440x900-example.v1";
  const save = vi.spyOn(api, "saveResource").mockResolvedValue({ schema_version: "v1", resource: { kind: "runner-profiles", id, document: { ...profile, id } as unknown as Record<string, unknown>, status: "draft", digest: "sha256:test", created_at: "2026-09-20", updated_at: "2026-09-20" } });
  const activate = vi.spyOn(api, "activateResource");
  await user.click(await screen.findByRole("button", { name: "New profile" }));
  const dialog = within(screen.getByRole("dialog", { name: "Draft runner profile" }));
  await user.selectOptions(dialog.getByLabelText(/^Configuration template/), profile.id);
  await user.selectOptions(dialog.getByLabelText("Platform"), "linux");
  const input = dialog.getByRole("textbox", { name: "Profile ID" });
  expect(dialog.getByText("Use a lowercase, versioned ID, for example local-experiment.v1.")).toBeVisible();
  for (const invalid of ["gzip-ui-1440x900-example", "Uppercase.v1", "two__separators.v1", "invalid-version.v0"]) {
    await user.clear(input);
    await user.type(input, invalid);
    await user.click(dialog.getByRole("button", { name: "Save profile draft" }));
    expect(input).toBeInvalid();
    expect(input).toHaveValue(invalid);
    expect(save).not.toHaveBeenCalled();
    expect(dialog.getByLabelText("Platform")).toHaveValue("linux");
    expect(dialog.getByRole("checkbox", { name: "Compress selected records: Atomic gzip" })).toBeChecked();
  }
  await user.clear(input);
  await user.type(input, id);
  expect(input).toBeValid();
  await user.click(dialog.getByRole("button", { name: "Save profile draft" }));
  await waitFor(() => expect(save).toHaveBeenCalledWith("runner-profiles", id, expect.objectContaining({ id, platforms: ["linux"], enabled_actions: [action.id, gzip.id] }), "draft"));
  expect(activate).not.toHaveBeenCalled();
});

it("edits a managed profile absent from the catalog without losing its binding", async () => {
  const custom: RunnerProfile = { ...chmodProfile, id: "managed-custom.v1", safety_tiers: ["controlled"], native_tool_installations: [{ schema_version: "bluefire.native-tool-installation.v1", adapter_id: "sandbox.permission.chmod.v1", adapter_version: "1.0.0", adapter_contract_digest: "sha256:" + "a".repeat(64), tool_id: "gnu.coreutils.chmod.v1", tool_version: "9.4", platform: "linux", architecture: "x86_64", content_sha256: "sha256:" + "b".repeat(64), size_bytes: 1234, installation_location: "/usr/bin/chmod" }] };
  setup("profiles", custom, [{ id: custom.id, status: "draft", document: custom }], []);
  const user = userEvent.setup(); const save = vi.spyOn(api, "saveResource").mockResolvedValue({ schema_version: "v1", resource: { kind: "runner-profiles", id: custom.id, document: custom as unknown as Record<string, unknown>, status: "draft", digest: "sha256:test", created_at: "2026-09-20", updated_at: "2026-09-20" } }); const activate = vi.spyOn(api, "activateResource");
  await user.click(await screen.findByRole("button", { name: "Configure methods for Managed custom (managed-custom.v1)" }));
  const dialog = within(screen.getByRole("dialog"));
  expect(dialog.getByDisplayValue(custom.id)).toHaveAttribute("readonly");
  expect(dialog.getByRole("button", { name: "Save profile draft" })).toBeEnabled();
  await user.click(dialog.getByRole("button", { name: "Save profile draft" }));
  await waitFor(() => expect(save).toHaveBeenCalledWith("runner-profiles", custom.id, expect.objectContaining({ native_tool_installations: custom.native_tool_installations }), "draft"));
  expect(activate).not.toHaveBeenCalled();
});

it("keeps colliding profile names distinguishable across baseline, draft, and active controls", async () => {
  const baseline: RunnerProfile = { ...chmodProfile, id: "lab-profile.v1", safety_tiers: ["controlled"] };
  const draft: RunnerProfile = { ...baseline, id: "lab_profile.v1" };
  const active: RunnerProfile = { ...baseline, id: "lab-profile.v2" };
  setup("profiles", baseline, [
    { id: draft.id, status: "draft", document: draft },
    { id: active.id, status: "active", document: active },
  ], [baseline]);
  const user = userEvent.setup();
  const activate = vi.spyOn(api, "activateResource").mockResolvedValue({ schema_version: "v1", resource: { kind: "runner-profiles", id: draft.id, document: draft as unknown as Record<string, unknown>, status: "active", digest: "sha256:test", created_at: "2026-09-20", updated_at: "2026-09-20" } });
  const deactivate = vi.spyOn(api, "deactivateResource");
  const save = vi.spyOn(api, "saveResource");
  for (const candidate of [baseline, draft, active]) {
    const card = within(await screen.findByRole("region", { name: `Lab profile (${candidate.id})` }));
    expect(card.getByRole("heading", { name: "Lab profile" })).toBeVisible();
    expect(card.getByText("Profile ID")).toBeVisible();
    expect(card.getByText(candidate.id, { exact: true })).toBeVisible();
  }
  const draftCard = within(screen.getByRole("region", { name: `Lab profile (${draft.id})` }));
  const activeCard = within(screen.getByRole("region", { name: `Lab profile (${active.id})` }));
  const setupButton = draftCard.getByRole("button", { name: "Set up GNU chmod for Lab profile (lab_profile.v1)" });
  expect(setupButton).toBeEnabled();
  expect(activeCard.queryByRole("button", { name: /Configure methods|Set up GNU chmod/ })).not.toBeInTheDocument();
  expect(activeCard.getByRole("button", { name: "Deactivate Lab profile (lab-profile.v2)" })).toBeEnabled();
  await user.click(setupButton);
  const setupDialog = within(screen.getByRole("dialog"));
  expect(setupDialog.getByText(draft.id, { exact: true })).toBeVisible();
  expect(setupDialog.getByRole("button", { name: "Save tool binding" })).toBeDisabled();
  await user.click(setupDialog.getByRole("button", { name: "Cancel" }));
  await user.click(draftCard.getByRole("button", { name: "Configure methods for Lab profile (lab_profile.v1)" }));
  const dialog = within(screen.getByRole("dialog"));
  expect(dialog.getByRole("heading", { name: "Configure Lab profile" })).toBeVisible();
  expect(dialog.getByText(draft.id, { exact: true })).toBeVisible();
  expect(dialog.getByLabelText(/^Profile ID/)).toHaveValue(draft.id);
  expect(dialog.getByLabelText(/^Profile ID/)).toHaveAttribute("readonly");
  await user.click(dialog.getByRole("button", { name: "Cancel" }));
  await user.click(draftCard.getByRole("button", { name: "Validate & activate Lab profile (lab_profile.v1)" }));
  await waitFor(() => expect(activate).toHaveBeenCalledExactlyOnceWith("runner-profiles", draft.id));
  expect(deactivate).not.toHaveBeenCalled();
  expect(save).not.toHaveBeenCalled();
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
