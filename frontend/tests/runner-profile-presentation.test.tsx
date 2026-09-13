import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog } from "../src/lib/demo";
import { profileChoiceLabel, profileLabel } from "../src/lib/run-review-labels";
import { RunnersPage } from "../src/pages/CatalogPages";

it.each([
  ["sandbox-execute.v1", "Workspace actions"],
  ["sandbox-observe-only.v1", "Read-only observation"],
  ["custom-lab.v2", "Custom lab"],
  ["constructor", "Constructor"],
  ["__proto__", " proto "],
])("keeps the readable profile fallback a string for %s", (id, expected) => {
  expect(profileLabel(id)).toBe(expected);
});

it("disambiguates readable custom names with their exact identities", () => {
  const profiles = [{ id: "custom-lab.v1" }, { id: "custom-lab.v2" }];
  expect(profileChoiceLabel(profiles[0]!.id, profiles)).toBe("Custom lab · custom-lab.v1");
  expect(profileChoiceLabel(profiles[1]!.id, profiles)).toBe("Custom lab · custom-lab.v2");
});

it.each([{ stored: false, source: "catalog baseline" }, { stored: true, source: "stored" }])("names $source profile cards and keeps exact diagnostics and probe targets", async ({ stored }) => {
  const profile = demoCatalog.runner_profiles.find(item => item.id === "sandbox-execute.v1")!;
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  vi.spyOn(api, "resources").mockImplementation(async kind => ({ schema_version: "bluefire.resource-list.v1", kind, resources: stored && kind === "runner-profiles" ? [{ kind, id: profile.id, status: "active", document: { ...profile }, digest: "test-digest", created_at: "", updated_at: "" }] : [] }));
  const status = vi.spyOn(api, "runnerStatus").mockImplementation(async selected => ({ schema_version: "bluefire.runner-lifecycle-status.v1", state: "stopped", runner_id: "runner.test.v1", profile_id: selected!, loopback_only: true, enrollment: "active", process: "absent", runner: null, health: null }));
  const probe = vi.spyOn(api, "probeRunnerProfile").mockResolvedValue({ schema_version: "bluefire.runner-probe.v1", profile_id: profile.id, version: null, platform: "linux", actions: [], health: { state: "unavailable", message: "The selected runner is not available." } });
  const start = vi.spyOn(api, "startRunner"); const bootstrap = vi.spyOn(api, "bootstrapRunner");
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={["/runners"]}><RunnersPage/></MemoryRouter></QueryClientProvider>);
  const user = userEvent.setup();
  const title = await screen.findByRole("heading", { name: "Workspace actions" });
  const card = within(title.closest(".runner-card")! as HTMLElement);
  expect(screen.getByRole("heading", { name: "Runners", level: 1 })).toBeVisible();
  expect(screen.queryByText("Execution boundary")).not.toBeInTheDocument();
  expect(screen.queryByText("Bounded probe boundary")).not.toBeInTheDocument();
  expect(screen.getByText(/Probe health & inventory checks/).tagName).toBe("P");
  expect(card.getByText(profile.id, { selector: "code" })).not.toBeVisible();
  await user.click(card.getByText("Profile identity"));
  expect(card.getByText(profile.id, { selector: "code" })).toBeVisible();
  const selector = screen.getByRole("combobox", { name: "Experiment runner profile" });
  const option = screen.getByRole("option", { name: /^Workspace actions ·/ });
  expect(option).toHaveValue(profile.id);
  expect(status).not.toHaveBeenCalled(); expect(probe).not.toHaveBeenCalled();
  await user.selectOptions(selector, option);
  await waitFor(() => expect(status).toHaveBeenCalledWith(profile.id));
  expect(selector).toHaveValue(profile.id);
  const selectedIdentity = screen.getByText("Selected profile identity").parentElement!;
  await user.click(screen.getByText("Selected profile identity"));
  expect(within(selectedIdentity).getByText(profile.id)).toBeVisible();
  if (stored) {
    expect(card.getByRole("link", { name: "Inspect this profile’s runner" })).toHaveAttribute("href", `/runners?profile=${profile.id}`);
    await user.click(card.getByRole("button", { name: "Probe health & inventory" }));
    await waitFor(() => expect(probe).toHaveBeenCalledExactlyOnceWith(profile.id));
    expect(await screen.findByText("The selected runner is not available.")).toBeVisible();
    expect(screen.getAllByRole("heading", { name: "Workspace actions" })).toHaveLength(2);
    expect(screen.queryByRole("heading", { name: profile.id })).not.toBeInTheDocument();
  }
  expect(start).not.toHaveBeenCalled(); expect(bootstrap).not.toHaveBeenCalled();
});
