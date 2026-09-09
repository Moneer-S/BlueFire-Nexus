import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { SavedExperimentReview } from "../src/components/SavedExperimentReview";
import { api } from "../src/lib/api";
import { demoScenario } from "../src/lib/demo";
import { ProductProvider, useProduct } from "../src/state/ProductContext";
import { receiverFixtureDigest, receiverFixtureId } from "./receiver-defense-fixture";

function response() {
  const document = { ...structuredClone(demoScenario), title: "Selected saved version" };
  return { schema_version: "bluefire.scenario-version.v1", scenario: { scenario_id: document.id, version: 2, digest: receiverFixtureDigest, title: document.title, created_at: "2026-09-07T00:00:00Z", document } };
}
function Witness() {
  const product = useProduct();
  return <><output aria-label="Working graph">{JSON.stringify(product.scenario)}</output><button onClick={() => product.setScenario({ ...product.scenario, title: "Unrelated manual edits" })}>Edit current graph</button></>;
}
function mount(digest = receiverFixtureDigest, fromRun = false) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter initialEntries={[fromRun ? "/builder?from_run=1" : "/builder"]}><Witness /><SavedExperimentReview id={demoScenario.id} version={2} digest={digest} receiverJob={receiverFixtureId} renderEditor={(review) => <><output aria-label="Reviewed graph">{JSON.stringify(review.scenario)}</output><output aria-label="Read only">{String(review.readOnly)}</output>{review.details}{review.controls}</>} /></MemoryRouter></ProductProvider></QueryClientProvider>);
}
it("previews the exact saved version without replacing the current graph and retains the control-test return link", async () => {
  const request = vi.spyOn(api, "immutableScenarioVersion").mockResolvedValue(response());
  mount();
  const original = screen.getByLabelText("Working graph").textContent;
  expect(await screen.findByLabelText("Reviewed graph")).toHaveTextContent("Selected saved version");
  expect(request).toHaveBeenCalledWith(demoScenario.id, 2);
  expect(screen.getByLabelText("Working graph").textContent).toBe(original);
  expect(screen.getByLabelText("Read only")).toHaveTextContent("true");
  expect(screen.getByRole("link", { name: "Return to control test" })).toHaveAttribute("href", `/compare?receiver_job=${receiverFixtureId}`);
});
it("preserves manual edits made while the saved version loads and opens only after explicit replacement", async () => {
  let resolve!: (value: ReturnType<typeof response>) => void;
  vi.spyOn(api, "immutableScenarioVersion").mockReturnValue(new Promise((finish) => { resolve = finish; }));
  const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
  const user = userEvent.setup(); mount();
  await user.click(screen.getByRole("button", { name: "Edit current graph" }));
  await act(async () => resolve(response()));
  await user.click(await screen.findByRole("button", { name: "Open this version for editing" }));
  expect(confirm).toHaveBeenCalledOnce();
  expect(screen.getByLabelText("Working graph")).toHaveTextContent("Unrelated manual edits");
  confirm.mockReturnValue(true);
  await user.click(screen.getByRole("button", { name: "Open this version for editing" }));
  expect(screen.getByLabelText("Working graph")).toHaveTextContent("Selected saved version");
});
it.each(["digest", "version"] as const)("refuses a different saved %s without exposing an open action", async (field) => {
  const wrong = response();
  if (field === "version") wrong.scenario.version = 3; else wrong.scenario.digest = `sha256:${"9".repeat(64)}`;
  vi.spyOn(api, "immutableScenarioVersion").mockResolvedValue(wrong);
  mount(); const original = screen.getByLabelText("Working graph").textContent;
  expect(await screen.findByText(/The saved version does not match this link/)).toBeVisible();
  expect(screen.queryByRole("button", { name: "Open this version for editing" })).not.toBeInTheDocument();
  expect(screen.getByLabelText("Working graph").textContent).toBe(original);
});
it("does not fetch an incomplete saved-version link", () => {
  const request = vi.spyOn(api, "immutableScenarioVersion"); mount("");
  expect(screen.getByText("This saved-version link is incomplete.")).toBeVisible();
  expect(request).not.toHaveBeenCalled();
});

it("returns a saved experiment review to its exact Assistant run settings", async () => {
  vi.spyOn(api, "immutableScenarioVersion").mockResolvedValue(response());
  mount(receiverFixtureDigest, true);
  const link = await screen.findByRole("link", { name: "Return to run settings" });
  expect(link).toHaveAttribute("href", `/runs?${new URLSearchParams({ saved_scenario: demoScenario.id, version: "2", digest: receiverFixtureDigest })}`);
  expect(screen.queryByRole("link", { name: "Return to control test" })).not.toBeInTheDocument();
});
