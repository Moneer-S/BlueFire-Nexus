import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { ReceiverSavedTests } from "../src/components/ReceiverSavedTests";
import { api } from "../src/lib/api";
import { receiverFixtureId } from "./receiver-defense-fixture";

function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter><ReceiverSavedTests /></MemoryRouter></QueryClientProvider>);
  return userEvent.setup();
}
it("finds saved tests without an old browser receipt and pages through the bounded history", async () => {
  const old = `job-${"a".repeat(32)}`;
  const list = vi.spyOn(api, "receiverTests").mockResolvedValueOnce({ schema_version: "bluefire.receiver-defense-list.v1", jobs: [{ job_id: receiverFixtureId, title: "Unfinished handoff", status: "blocked", phase: "protected", updated_at: null, native_path: "/ignore-untrusted-navigation" }], truncated: true, next_cursor: receiverFixtureId })
    .mockResolvedValueOnce({ schema_version: "bluefire.receiver-defense-list.v1", jobs: [{ job_id: old, title: "Earlier control test", status: "completed", phase: null, updated_at: null, native_path: "/ignore-untrusted-navigation" }], truncated: false, next_cursor: null });
  const prepare = vi.spyOn(api, "prepareReceiver"), create = vi.spyOn(api, "createReceiverTest");
  const user = mount();
  expect(await screen.findByRole("link", { name: /Unfinished handoff/ })).toHaveAttribute("href", `/compare?receiver_job=${receiverFixtureId}`);
  await user.click(screen.getByRole("button", { name: "More saved tests" }));
  expect(await screen.findByRole("link", { name: /Earlier control test/ })).toHaveAttribute("href", `/compare?receiver_job=${old}`);
  expect(list).toHaveBeenLastCalledWith(receiverFixtureId);
  expect(screen.getByRole("button", { name: "Previous saved tests" })).toBeEnabled();
  expect(prepare).not.toHaveBeenCalled(); expect(create).not.toHaveBeenCalled();
});

it("keeps a history error visible instead of presenting unavailable tests as an empty history", async () => {
  vi.spyOn(api, "receiverTests").mockRejectedValue(new Error("History unavailable"));
  mount();
  expect(await screen.findByText("History unavailable")).toBeVisible();
  expect(screen.getByRole("button", { name: "Try again" })).toBeEnabled();
});
