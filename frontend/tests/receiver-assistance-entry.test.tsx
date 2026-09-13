import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { ReceiverTestSetup } from "../src/components/ReceiverTestSetup";
import { ReceiverDefensePage } from "../src/pages/ReceiverDefense";
import { ExperimentAssistant } from "../src/components/ExperimentAssistant";
import { api } from "../src/lib/api";
import { demoCatalog } from "../src/lib/demo";
import { readAssistanceReceipt } from "../src/lib/assistance";
import { AssistanceProvider, useAssistanceSelection } from "../src/state/AssistanceContext";
import { ProductProvider, useProduct } from "../src/state/ProductContext";
import { receiverAssistantFixture, receiverAssistantProvider } from "./receiver-assistance-fixture";

function Witness() {
  const selection = useAssistanceSelection(), { scenario, runConfig } = useProduct();
  return <><output aria-label="Published receiver selection">{JSON.stringify(selection)}</output><output aria-label="Current graph and run settings">{JSON.stringify({ scenario, runConfig })}</output></>;
}
function mount(element: React.ReactNode, entry = "/compare?receiver=1") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[entry]}><ProductProvider><AssistanceProvider><Witness />{element}<ExperimentAssistant providers={[receiverAssistantProvider]} /></AssistanceProvider></ProductProvider></MemoryRouter></QueryClientProvider>);
}

it("publishes the native setup's exact immutable version and private settings without replacing the working draft", async () => {
  const { native } = receiverAssistantFixture();
  const saved = { scenario_id: native.context.selection.scenario_id, version: 1, digest: native.context.selection.digest, title: native.context.scenario_title, document: native.context.scenario, created_at: "2026-09-07T00:00:00Z" };
  const catalog = structuredClone(demoCatalog);
  const profile = catalog.runner_profiles.find((item) => item.mode === "execute")!;
  vi.spyOn(api, "catalog").mockResolvedValue(catalog);
  vi.spyOn(api, "scenarioVersions").mockResolvedValue({ schema_version: "bluefire.scenario-version-list.v1", scenarios: [saved] });
  vi.spyOn(api, "receiverContext").mockImplementation(async (body) => ({ ...native.context, ...body }));
  const getContext = vi.spyOn(api, "assistanceReceiverContext").mockImplementation(async (selected) => ({ ...receiverAssistantFixture().context, selected,
    receiver_context: { ...native.context, ...(selected.kind === "receiver_scenario" ? { selection: selected.selection, run_intent: selected.run_intent } : {}) } }));
  const start = vi.fn(), post = vi.spyOn(api, "submitAssistance"), prepare = vi.spyOn(api, "prepareReceiver");
  const view = mount(<ReceiverTestSetup disabled={false} onStart={start} />);
  const before = screen.getByLabelText("Current graph and run settings").textContent;
  const user = userEvent.setup();
  await user.selectOptions(await screen.findByLabelText("Saved experiment", { exact: false }), `${saved.scenario_id}:1:${saved.digest}`);
  await user.click(screen.getByRole("radio", { name: /Execute/ }));
  await user.selectOptions(screen.getByLabelText("Environment profile"), profile.id);
  await waitFor(() => expect(screen.getByLabelText("Published receiver selection").textContent).toContain('"receiver_scenario"'));
  const published = JSON.parse(screen.getByLabelText("Published receiver selection").textContent!);
  expect(published.selected).toMatchObject({ selection: native.context.selection, run_intent: { runner_profile_id: profile.id, mode: "execute", autonomy: "off", ai_provider_id: null } });
  await user.click(await screen.findByRole("button", { name: "Coordinate with Assistant" }));
  await waitFor(() => expect(getContext).toHaveBeenCalledWith(published.selected));
  expect(start).not.toHaveBeenCalled(); expect(post).not.toHaveBeenCalled(); expect(prepare).not.toHaveBeenCalled();
  expect(screen.getByLabelText("Current graph and run settings").textContent).toBe(before);
  view.unmount();
  mount(<ReceiverTestSetup disabled={false} onStart={start} />);
  await waitFor(() => expect(screen.getByLabelText("Published receiver selection").textContent).toContain(profile.id));
  expect(JSON.parse(screen.getByLabelText("Published receiver selection").textContent!).selected).toEqual(published.selected);
});

it("publishes existing evidence from the native owner and opens its exact saved Assistant using GET only", async () => {
  const fixture = receiverAssistantFixture();
  fixture.native.job.request!.assistance_turn = { parent_job_id: fixture.envelope().job.job_id, step_id: "receiver" };
  vi.spyOn(api, "receiverTest").mockResolvedValue(fixture.native);
  const get = vi.spyOn(api, "assistanceTurn").mockResolvedValue(fixture.envelope());
  const post = vi.spyOn(api, "submitAssistance"), prepare = vi.spyOn(api, "prepareReceiver");
  mount(<ReceiverDefensePage />, `/compare?receiver_job=${fixture.native.job.job_id}`);
  await screen.findByRole("button", { name: "Open saved Assistant work" });
  expect(JSON.parse(screen.getByLabelText("Published receiver selection").textContent!).selected).toEqual({ kind: "receiver_test", receiver_job_id: fixture.native.job.job_id, receiver_context_digest: fixture.native.context.context_digest });
  await userEvent.setup().click(screen.getByRole("button", { name: "Open saved Assistant work" }));
  await screen.findByRole("heading", { name: "Your review is needed" });
  expect(get).toHaveBeenCalledWith(fixture.envelope().job.job_id);
  expect(readAssistanceReceipt()).toEqual(fixture.request);
  expect(post).not.toHaveBeenCalled(); expect(prepare).not.toHaveBeenCalled();
});
