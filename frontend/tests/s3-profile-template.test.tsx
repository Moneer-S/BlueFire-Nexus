import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog } from "../src/lib/demo";
import s3Template from "../src/lib/s3-profile-template.json";
import { RunnerProfilesPage } from "../src/pages/CatalogPages";

function setup(resources: unknown[] = []) {
  vi.spyOn(api, "catalog").mockResolvedValue({ ...demoCatalog, runner_profiles: [], actions: [] });
  vi.spyOn(api, "resources").mockResolvedValue({ schema_version: "v1", kind: "runner-profiles", resources } as never);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter><RunnerProfilesPage /></MemoryRouter></QueryClientProvider>);
}

it("creates a durable dedicated S3 draft from an empty catalog without activation", async () => {
  setup();
  const user = userEvent.setup();
  const save = vi.spyOn(api, "saveResource").mockResolvedValue({ resource: { id: "local-experiment.v1", status: "draft" } } as never);
  const activate = vi.spyOn(api, "activateResource");
  const probe = vi.spyOn(api, "probeRunnerProfile");
  await user.click(await screen.findByRole("button", { name: "New profile" }));
  const dialog = within(screen.getByRole("dialog"));
  await user.selectOptions(dialog.getByLabelText(/^Configuration template/), "reserved:s3-access");
  expect(dialog.getByLabelText("Platform")).toHaveValue("linux");
  expect(dialog.getByLabelText("Platform").querySelectorAll("option")).toHaveLength(1);
  expect(dialog.getByText(/S3 access workflow only/)).toBeVisible();
  await user.click(dialog.getByRole("button", { name: "Save profile draft" }));
  const { secrets, ...expected } = s3Template;
  void secrets;
  await waitFor(() => expect(save).toHaveBeenCalledExactlyOnceWith("runner-profiles", "local-experiment.v1", { ...expected, id: "local-experiment.v1", native_tool_installations: undefined }, "draft"));
  expect(activate).not.toHaveBeenCalled();
  expect(probe).not.toHaveBeenCalled();
});

it("reopens an inactive S3 draft without silently dropping its reserved method", async () => {
  setup([{ id: s3Template.id, status: "draft", document: s3Template }]);
  const user = userEvent.setup();
  const save = vi.spyOn(api, "saveResource").mockResolvedValue({ resource: { id: s3Template.id, status: "draft" } } as never);
  await user.click(await screen.findByRole("button", { name: /Configure methods for .*s3-access-template.v1/ }));
  const dialog = within(screen.getByRole("dialog"));
  expect(dialog.getByRole("button", { name: "Save profile draft" })).toBeEnabled();
  await user.click(dialog.getByRole("button", { name: "Save profile draft" }));
  await waitFor(() => expect(save).toHaveBeenCalledWith("runner-profiles", s3Template.id, expect.objectContaining({ enabled_actions: ["owned.aws.s3_access.v1"] }), "draft"));
});
