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
  expect(form.getByLabelText("Source ID")).toHaveFocus();
  expect(form.getByLabelText("Attribution")).toHaveValue("Example project contributors");
  save.mockImplementationOnce(async (kind, id, document, status) => ({ schema_version: "v1", resource: { kind, id, document, status: status!, digest: "sha256:review-draft", created_at: "2026-09-08", updated_at: "2026-09-08" } }));
  await user.clear(form.getByLabelText("Version", { exact: true }));
  await user.type(form.getByLabelText("Version", { exact: true }), "1.1");
  await user.click(form.getByRole("button", { name: "Save review draft" }));
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  expect(save).toHaveBeenLastCalledWith("research-sources", "research.local-source.v1", expect.objectContaining({ version: "1.1", attribution: "Example project contributors" }), "draft");
  expect(screen.getByRole("button", { name: "Add source" })).toHaveFocus();
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
});

it("reports a copied source pin only after the clipboard confirms it", async () => {
  const user = userEvent.setup();
  vi.spyOn(api, "resources").mockResolvedValue({ schema_version: "v1", kind: "research-sources", resources: [{ kind: "research-sources", id: "source.v1", status: "draft", digest: "sha256:test", created_at: "2026-09-08", updated_at: "2026-09-08", document: { name: "Example source", pin: "public-v1" } }] });
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  let resolve!: () => void;
  const pending = new Promise<void>((done) => { resolve = done; });
  const write = vi.spyOn(navigator.clipboard, "writeText").mockReturnValueOnce(pending);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter><ResearchSourcesPage/></MemoryRouter></QueryClientProvider>);
  await user.click(await screen.findByRole("button", { name: "Copy pin" }));
  expect(write).toHaveBeenCalledWith("public-v1");
  expect(screen.queryByText(/Copied immutable pin/)).not.toBeInTheDocument();
  await act(async () => resolve());
  expect(await screen.findByText("Copied immutable pin for Example source.")).toBeVisible();
  write.mockRejectedValueOnce(new Error("Permission denied"));
  await user.click(screen.getByRole("button", { name: "Copy pin" }));
  expect(await screen.findByText(/The pin could not be copied/)).toBeVisible();
  expect(screen.queryByText(/Copied immutable pin/)).not.toBeInTheDocument();
});
