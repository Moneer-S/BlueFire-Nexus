import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog } from "../src/lib/demo";
import { RunnersPage } from "../src/pages/CatalogPages";
import type { RunnerLifecycleStatus } from "../src/types";

const revoked: RunnerLifecycleStatus = {
  schema_version: "bluefire.runner-lifecycle-status.v1",
  state: "revoked",
  runner_id: "runner.test.v1",
  profile_id: "sandbox-execute.v1",
  loopback_only: true,
  enrollment: "revoked",
  process: "absent",
  runner: null,
  health: null,
};

afterEach(() => vi.unstubAllGlobals());

async function openRemoval() {
  // Every API surface used here is mocked; unexpected requests cannot reach a service.
  vi.stubGlobal("fetch", vi.fn(() => { throw new Error("Unexpected request in removal UI test"); }));
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  vi.spyOn(api, "resources").mockImplementation(async kind => ({ schema_version: "bluefire.resource-list.v1", kind, resources: [] }));
  vi.spyOn(api, "runnerStatus").mockResolvedValue(revoked);
  const remove = vi.spyOn(api, "removeRunner").mockResolvedValue({ ...revoked, state: "unbootstrapped", enrollment: "absent" });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={["/runners?profile=sandbox-execute.v1"]}><RunnersPage/></MemoryRouter></QueryClientProvider>);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Remove revoked trust" }));
  const dialog = screen.getByRole("dialog", { name: "Remove revoked runner trust" });
  const input = within(dialog).getByRole("textbox", { name: "Runner ID" });
  return { user, dialog, input, remove };
}

it("keeps the full confirmation and refusal in the open dialog until a successful retry", async () => {
  const { user, dialog, input, remove } = await openRemoval();
  remove.mockRejectedValueOnce(new Error("Runner removal is blocked by an outstanding receipt."));
  await user.type(input, revoked.runner_id);
  await user.click(within(dialog).getByRole("button", { name: "Confirm removal" }));
  expect(await within(dialog).findByText("Runner removal is blocked by an outstanding receipt.")).toBeVisible();
  expect(dialog).toBeVisible();
  expect(input).toHaveValue(revoked.runner_id);
  expect(input).toBeEnabled();
  expect(remove).toHaveBeenCalledExactlyOnceWith(revoked.runner_id);

  await user.click(within(dialog).getByRole("button", { name: "Confirm removal" }));
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  expect(remove).toHaveBeenCalledTimes(2);
  expect(remove).toHaveBeenLastCalledWith(revoked.runner_id);
});

it("blocks duplicate submission, editing and every dialog dismissal while removal is pending", async () => {
  const { user, dialog, input, remove } = await openRemoval();
  let resolveRemoval!: (status: RunnerLifecycleStatus) => void;
  remove.mockImplementation(() => new Promise(resolve => { resolveRemoval = resolve; }));
  await user.type(input, revoked.runner_id);
  const form = input.closest("form")!;
  act(() => { fireEvent.submit(form); fireEvent.submit(form); });
  await waitFor(() => expect(remove).toHaveBeenCalledExactlyOnceWith(revoked.runner_id));
  expect(input).toBeDisabled();
  expect(within(dialog).getByRole("button", { name: "Removing" })).toBeDisabled();
  const cancel = within(dialog).getByRole("button", { name: "Cancel" });
  const close = within(dialog).getByRole("button", { name: "Close dialog" });
  expect(cancel).toBeDisabled();
  expect(close).toBeDisabled();
  await user.click(cancel);
  await user.click(close);
  await user.keyboard("{Escape}");
  const overlay = document.querySelector(".dialog-overlay")!;
  fireEvent.pointerDown(overlay);
  fireEvent.click(overlay);
  expect(dialog).toBeVisible();
  expect(input).toHaveValue(revoked.runner_id);
  expect(remove).toHaveBeenCalledTimes(1);

  await act(async () => resolveRemoval({ ...revoked, state: "unbootstrapped", enrollment: "absent" }));
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
});

it("requires the exact runner identity and resets confirmation only after success", async () => {
  const { user, dialog, input, remove } = await openRemoval();
  const confirm = within(dialog).getByRole("button", { name: "Confirm removal" });
  expect(confirm).toBeDisabled();
  await user.type(input, `${revoked.runner_id} `);
  expect(confirm).toBeDisabled();
  fireEvent.submit(input.closest("form")!);
  expect(remove).not.toHaveBeenCalled();
  await user.clear(input);
  await user.type(input, revoked.runner_id);
  await user.click(confirm);
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  expect(remove).toHaveBeenCalledExactlyOnceWith(revoked.runner_id);

  await user.click(screen.getByRole("button", { name: "Remove revoked trust" }));
  const reopened = screen.getByRole("dialog");
  expect(within(reopened).getByRole("textbox", { name: "Runner ID" })).toHaveValue("");
  expect(within(reopened).getByRole("button", { name: "Confirm removal" })).toBeDisabled();
});
