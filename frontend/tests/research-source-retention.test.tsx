import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog } from "../src/lib/demo";
import { ResearchSourcesPage } from "../src/pages/CatalogPages";

it("keeps the source form and inputs through a refused save and successful retry", async () => {
  const user = userEvent.setup();
  vi.spyOn(api, "resources").mockResolvedValue({ schema_version: "v1", kind: "research-sources", resources: [] });
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  let reject!: (reason: Error) => void;
  const pending = new Promise<Awaited<ReturnType<typeof api.saveResource>>>((_, no) => { reject = no; });
  const save = vi.spyOn(api, "saveResource").mockReturnValueOnce(pending);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter><ResearchSourcesPage /></MemoryRouter></QueryClientProvider>);
  await user.click(await screen.findByRole("button", { name: "Add source" }));
  const form = within(screen.getByRole("dialog", { name: "Add research source" }));
  for (const [label, value] of [
    ["Project/repository", "example/research"], ["Authority", "Example project"],
    ["Pinned HTTPS reference", "https://example.com/research/v1"], ["Version", "1.0"],
    ["Immutable pin", "v1.0"], ["License HTTPS reference", "https://example.com/license"],
    ["Attribution", "Example project contributors"],
  ]) {
    await user.click(form.getByLabelText(new RegExp(`^${label}`)));
    await user.paste(value!);
  }
  await user.click(form.getByRole("button", { name: "Save review draft" }));
  await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
  expect(form.getByRole("button", { name: "Saving" })).toBeDisabled();
  expect(form.getByLabelText("Project/repository")).toHaveValue("example/research");
  await act(async () => reject(new Error("Review date was refused. Correct the date and retry.")));
  expect(await form.findByRole("alert")).toHaveTextContent("Review date was refused");
  expect(form.getByLabelText("Attribution")).toHaveValue("Example project contributors");
  save.mockImplementationOnce(async (kind, id, document, status) => ({ schema_version: "v1", resource: { kind, id, document, status: status!, digest: "sha256:review-draft", created_at: "2026-09-08", updated_at: "2026-09-08" } }));
  await user.clear(form.getByLabelText("Version", { exact: true }));
  await user.type(form.getByLabelText("Version", { exact: true }), "1.1");
  await user.click(form.getByRole("button", { name: "Save review draft" }));
  expect(await form.findByText(/Submitted review draft saved/)).toHaveAttribute("role", "status");
  expect(save).toHaveBeenLastCalledWith("research-sources", "research.local-source.v1", expect.objectContaining({ version: "1.1", attribution: "Example project contributors" }), "draft");
  expect(form.getByLabelText("Version", { exact: true })).toHaveValue("1.1");
  await user.click(form.getByRole("button", { name: "Cancel" }));
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
});
