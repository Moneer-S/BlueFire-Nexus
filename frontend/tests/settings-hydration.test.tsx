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
  await waitFor(() => expect(current()).toEqual({ theme: field === "theme" ? "system" : "light", mode: field === "mode" ? "simulate" : "execute", autonomy: field === "autonomy" ? "assist" : "auto" }));
  expect(screen.getByLabelText("Current run").textContent).toBe(run);
  expect(JSON.parse(localStorage.getItem("bluefire.local.run-config.v1")!)).toMatchObject({ theme: current().theme, effect_mode: current().mode, autonomy: current().autonomy });
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
