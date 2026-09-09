import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog } from "../src/lib/demo";
import { ActionsPage, RunnersPage } from "../src/pages/CatalogPages";

const cases = [
  { kind: "runners", trigger: "Register record", save: "Save runner record", idLabel: "Runner record ID", nameLabel: "Display label", initialId: "runner.local-sandbox.v1", nextId: "runner.corrected.v1" },
  { kind: "plugins", trigger: "Add manifest", save: "Save strict manifest", idLabel: "Plugin ID", nameLabel: "Display name", initialId: "plugin.local-review.v1", nextId: "plugin.corrected.v1" },
] as const;
const clients: QueryClient[] = [];
afterEach(() => { clients.splice(0).forEach((client) => client.clear()); });
function mount(kind: "runners" | "plugins") {
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  vi.spyOn(api, "resources").mockResolvedValue({ schema_version: "v1", kind, resources: [] });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  clients.push(client);
  render(<QueryClientProvider client={client}><MemoryRouter>{kind === "runners" ? <RunnersPage/> : <ActionsPage/>}</MemoryRouter></QueryClientProvider>);
}

it.each(cases)("retains a refused $kind form, locks pending edits/dismissal, and closes only after a successful retry", async (test) => {
  mount(test.kind); const user = userEvent.setup();
  let reject!: (error: Error) => void;
  const pending = new Promise<Awaited<ReturnType<typeof api.saveResource>>>((_, no) => { reject = no; });
  const save = vi.spyOn(api, "saveResource").mockReturnValueOnce(pending);
  const effects = [vi.spyOn(api, "activateResource"), vi.spyOn(api, "bootstrapRunner"), vi.spyOn(api, "startRunner"), vi.spyOn(api, "probeRunnerProfile")];
  await user.click(await screen.findByRole("button", { name: test.trigger }));
  const originalDialog = screen.getByRole("dialog"); const dialog = within(originalDialog);
  const name = dialog.getByLabelText(test.nameLabel);
  await user.clear(name); await user.type(name, "Retained reviewed metadata");
  if (test.kind === "plugins") await user.type(dialog.getByLabelText(/^Reviewed SHA-256/), "ab".repeat(32));
  await user.click(dialog.getByRole("button", { name: test.save }));
  await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
  expect(screen.getByRole("dialog")).toBe(originalDialog);
  expect(dialog.getByRole("button", { name: "Saving" })).toBeDisabled();
  expect(dialog.getByRole("button", { name: "Cancel" })).toBeDisabled();
  expect(dialog.getByRole("button", { name: "Close dialog" })).toBeDisabled();
  for (const control of originalDialog.querySelectorAll("input, select")) expect(control).toBeDisabled();
  await user.type(name, " unwanted pending edit");
  await user.click(dialog.getByRole("button", { name: "Cancel" }));
  await user.click(dialog.getByRole("button", { name: "Close dialog" }));
  await user.keyboard("{Escape}");
  fireEvent.pointerDown(document.querySelector(".dialog-overlay")!, { pointerType: "mouse", button: 0 });
  fireEvent.submit(name.closest("form")!);
  expect(screen.getByRole("dialog")).toBe(originalDialog);
  expect(name).toHaveValue("Retained reviewed metadata"); expect(save).toHaveBeenCalledTimes(1);
  await act(async () => reject(new Error("This record ID already exists. Choose a new ID.")));
  expect(await dialog.findByRole("alert")).toHaveTextContent("record ID already exists");
  await waitFor(() => expect(dialog.getByLabelText(test.idLabel)).toHaveFocus());
  expect(name).toHaveValue("Retained reviewed metadata"); expect(name).toBeEnabled();
  expect(dialog.getByLabelText(test.idLabel)).toHaveValue(test.initialId);
  if (test.kind === "plugins") expect(dialog.getByLabelText(/^Reviewed SHA-256/)).toHaveValue("ab".repeat(32));
  let accept!: (value: Awaited<ReturnType<typeof api.saveResource>>) => void;
  save.mockImplementationOnce(() => new Promise((yes) => { accept = yes; }));
  await user.clear(dialog.getByLabelText(test.idLabel)); await user.type(dialog.getByLabelText(test.idLabel), test.nextId);
  await user.click(dialog.getByRole("button", { name: test.save }));
  await waitFor(() => expect(save).toHaveBeenCalledTimes(2));
  expect(screen.getByRole("dialog")).toBe(originalDialog);
  const [kind, id, savedDocument, status] = save.mock.calls[1]!;
  expect(kind).toBe(test.kind); expect(id).toBe(test.nextId);
  if (test.kind === "runners") {
    expect(savedDocument).toEqual({ label: "Retained reviewed metadata", platform: "linux", transport: "local", binary_reference: { env: "BLUEFIRE_RUNNER_BINARY" }, connectivity: "not_verified" });
    expect(status).toBe("draft");
  } else {
    expect(savedDocument).toMatchObject({ name: "Retained reviewed metadata", enabled: false, trust: "untrusted", integrity: { algorithm: "sha256", digest: "ab".repeat(32) }, permissions: ["catalog.read"], capabilities: [], behavior_ids: [], action_ids: [], provenance: { derived: false, notes: "Locally reviewed declarative metadata; executable loading remains disabled." } });
  }
  await act(async () => accept({ schema_version: "v1", resource: { kind, id, document: savedDocument, status: status ?? "draft", digest: "sha256:test", created_at: "2026-09-09", updated_at: "2026-09-09" } }));
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  expect(screen.getByRole("button", { name: test.trigger })).toHaveFocus();
  await user.click(screen.getByRole("button", { name: test.trigger }));
  const nextDialog = within(screen.getByRole("dialog"));
  await user.clear(nextDialog.getByLabelText(test.nameLabel)); await user.type(nextDialog.getByLabelText(test.nameLabel), "Next unsaved record");
  expect(nextDialog.getByLabelText(test.nameLabel)).toHaveValue("Next unsaved record");
  expect(nextDialog.queryByRole("alert")).not.toBeInTheDocument(); expect(save).toHaveBeenCalledTimes(2);
  effects.forEach((effect) => expect(effect).not.toHaveBeenCalled());
});

it.each(cases)("keeps native validation and ordinary cancellation for $kind", async (test) => {
  mount(test.kind); const user = userEvent.setup(); const save = vi.spyOn(api, "saveResource");
  await user.click(await screen.findByRole("button", { name: test.trigger }));
  const dialog = within(screen.getByRole("dialog"));
  const invalid = dialog.getByLabelText(test.kind === "runners" ? /^Binary environment reference/ : /^Reviewed SHA-256/);
  await user.clear(invalid); await user.type(invalid, "invalid reference!");
  await user.click(dialog.getByRole("button", { name: test.save }));
  expect(invalid).toBeInvalid(); expect(save).not.toHaveBeenCalled();
  expect(screen.getByRole("dialog")).toBeVisible();
  await user.click(dialog.getByRole("button", { name: "Cancel" }));
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: test.trigger })).toHaveFocus();
});
