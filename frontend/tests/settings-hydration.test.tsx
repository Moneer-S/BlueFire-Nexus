import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { SettingsPage } from "../src/pages/SettingsHelp";
import { buildUiPreferenceDocument, ProductProvider, useProduct } from "../src/state/ProductContext";

vi.mock("../src/components/ProviderSetup", () => ({ ProviderSetup: () => null }));
vi.mock("../src/components/BuildDiagnostics", () => ({ BuildDiagnostics: () => null }));

function Witness() {
  const { theme, newRunDefaults, runConfig } = useProduct();
  return <><output aria-label="Preference witness">{JSON.stringify({ theme, ...newRunDefaults })}</output><output aria-label="Current run">{JSON.stringify(runConfig)}</output></>;
}
function setup() {
  localStorage.clear();
  let finish!: (response: Awaited<ReturnType<typeof api.settings>>) => void;
  vi.spyOn(api, "settings").mockReturnValue(new Promise(resolve => { finish = resolve; }));
  const save = vi.spyOn(api, "saveSetting").mockImplementation(async (key, value) => ({ schema_version: "bluefire.setting.v1", setting: { key, value, updated_at: "2026-09-09T07:00:00Z" } }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter><SettingsPage/><Witness/></MemoryRouter></ProductProvider></QueryClientProvider>);
  return { user: userEvent.setup(), save, finish: async () => act(async () => finish({ schema_version: "bluefire.settings.v1", settings: [{ key: "ui.preferences", value: buildUiPreferenceDocument("light", "execute", "auto"), updated_at: "2026-09-08T07:00:00Z" }] })) };
}
const current = () => JSON.parse(screen.getByLabelText("Preference witness").textContent!);

it.each(["theme", "mode", "autonomy"] as const)("preserves a touched %s while hydrating untouched preferences", async field => {
  const { user, finish } = setup();
  const run = screen.getByLabelText("Current run").textContent;
  if (field === "theme") await user.click(screen.getByRole("button", { name: /System.*Follow operating system/ }));
  if (field === "mode") {
    await user.selectOptions(screen.getByRole("combobox", { name: "Effect mode" }), "execute");
    await user.selectOptions(screen.getByRole("combobox", { name: "Effect mode" }), "simulate");
  }
  if (field === "autonomy") await user.selectOptions(screen.getByRole("combobox", { name: "AI autonomy" }), "assist");
  await finish();
  await waitFor(() => {
    expect(current()).toEqual({ theme: field === "theme" ? "system" : "light", mode: field === "mode" ? "simulate" : "execute", autonomy: field === "autonomy" ? "assist" : "auto" });
    // Rendering the hydrated state precedes ProductProvider's persistence effect.
    // Wait for both observable results before treating hydration as complete.
    expect(JSON.parse(localStorage.getItem("bluefire.local.run-config.v1")!)).toMatchObject({ theme: current().theme, effect_mode: current().mode, autonomy: current().autonomy });
  });
  expect(screen.getByLabelText("Current run").textContent).toBe(run);
});

it("preserves an imported preference document when initial settings arrive later", async () => {
  const { user, finish } = setup();
  await user.upload(screen.getByLabelText("Import UI preferences file"), new File([JSON.stringify(buildUiPreferenceDocument("system", "simulate", "assist"))], "preferences.json", { type: "application/json" }));
  await screen.findByText(/Theme and future run defaults were imported/);
  await finish();
  expect(current()).toEqual({ theme: "system", mode: "simulate", autonomy: "assist" });
});

it("does not replace explicitly saved browser preferences with an older pending read", async () => {
  const { user, save, finish } = setup();
  const preferences = current();
  await user.click(screen.getByRole("button", { name: "Save settings" }));
  await waitFor(() => expect(save).toHaveBeenCalledExactlyOnceWith("ui.preferences", buildUiPreferenceDocument(preferences.theme, preferences.mode, preferences.autonomy)));
  await finish();
  expect(current()).toEqual(preferences);
});

function setupDeferredSave() {
  localStorage.clear();
  vi.spyOn(api, "settings").mockResolvedValue({ schema_version: "bluefire.settings.v1", settings: [] });
  let release!: () => void;
  const submitted: unknown[] = [];
  const save = vi.spyOn(api, "saveSetting").mockImplementation((key, value) => {
    submitted.push(value);
    return new Promise(resolve => {
      release = () => resolve({ schema_version: "bluefire.setting.v1", setting: { key, value, updated_at: "2026-09-09T07:00:00Z" } });
    });
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter><SettingsPage/><Witness/></MemoryRouter></ProductProvider></QueryClientProvider>);
  return { user: userEvent.setup(), save, submitted, release: async () => act(async () => release()) };
}

it("does not call a pending save successful for values edited after it was submitted", async () => {
  const { user, submitted, release } = setupDeferredSave();
  await user.selectOptions(screen.getByRole("combobox", { name: "AI autonomy" }), "assist");
  const sent = current();
  await user.click(screen.getByRole("button", { name: /Save settings/ }));
  // The operator keeps working while the request is in flight.
  await user.selectOptions(screen.getByRole("combobox", { name: "AI autonomy" }), "auto");
  await release();
  // What was serialized is what was submitted, not what the form now shows.
  expect(submitted).toHaveLength(1);
  expect(submitted[0]).toMatchObject({ autonomy: "assist" });
  expect(sent.autonomy).toBe("assist");
  // The newer value is neither discarded nor announced as durable.
  expect(current().autonomy).toBe("auto");
  expect(await screen.findByText(/newer unsaved changes/)).toBeTruthy();
  expect(screen.queryByText(/^Preferences saved durably/)).toBeNull();
});

it("does not call a pending save successful for a document imported after it was submitted", async () => {
  const { user, submitted, release } = setupDeferredSave();
  await user.click(screen.getByRole("button", { name: /Save settings/ }));
  await user.upload(screen.getByLabelText("Import UI preferences file"), new File([JSON.stringify(buildUiPreferenceDocument("dark", "execute", "assist"))], "preferences.json", { type: "application/json" }));
  // Importing reads the file asynchronously; the save must not be released until the
  // imported values are actually in the form, or this races on a slower machine.
  await waitFor(() => expect(current()).toMatchObject({ theme: "dark", mode: "execute", autonomy: "assist" }));
  await release();
  expect(submitted).toHaveLength(1);
  expect(submitted[0]).not.toMatchObject({ theme: "dark", effect_mode: "execute", autonomy: "assist" });
  // The imported values survive and are reported as still unsaved.
  expect(current()).toMatchObject({ theme: "dark", mode: "execute", autonomy: "assist" });
  expect(await screen.findByText(/newer unsaved changes/)).toBeTruthy();
});

it("reports a save as durable when the form still matches what was submitted", async () => {
  const { user, submitted, release } = setupDeferredSave();
  await user.selectOptions(screen.getByRole("combobox", { name: "AI autonomy" }), "assist");
  await user.click(screen.getByRole("button", { name: /Save settings/ }));
  await release();
  expect(submitted).toHaveLength(1);
  expect(await screen.findByText(/Preferences saved durably/)).toBeTruthy();
  expect(screen.queryByText(/newer unsaved changes/)).toBeNull();
});
