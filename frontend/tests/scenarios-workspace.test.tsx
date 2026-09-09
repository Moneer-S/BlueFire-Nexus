import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoScenario } from "../src/lib/demo";
import { ScenariosPage } from "../src/pages/Scenarios";
import { ProductProvider, useProduct } from "../src/state/ProductContext";
import type { Scenario, ScenarioVersion } from "../src/types";

const clients: QueryClient[] = [];
afterEach(() => { clients.splice(0).forEach((client) => client.clear()); });
const saved = { ...structuredClone(demoScenario), id: "experiment.saved.v1", title: "Saved collection procedure" };
const packaged = { ...structuredClone(demoScenario), id: "experiment.packaged.v1", title: "Packaged collection procedure" };
function version(document = saved): ScenarioVersion { return { scenario_id: document.id, title: document.title, version: 3, digest: "sha256:test", created_at: "2026-09-01T12:00:00Z", document }; }
function Context() {
  const { scenario, setScenario, dirty } = useProduct(); const location = useLocation(); const navigate = useNavigate();
  return <><output aria-label="Current document">{JSON.stringify(scenario)}</output><output aria-label="Dirty">{String(dirty)}</output><output aria-label="Location">{location.pathname}{location.search}</output><button onClick={() => setScenario({ ...scenario, title: "Later edit" })}>Edit elsewhere</button><button onClick={() => navigate(-1)}>Back</button></>;
}
function setup(options: { draft?: Scenario; clean?: boolean; url?: string; unavailable?: boolean; versions?: ReturnType<typeof api.scenarioVersions>; history?: ScenarioVersion[]; exact?: ScenarioVersion } = {}) {
  const draft = options.draft ?? { ...structuredClone(demoScenario), title: "My working procedure" };
  localStorage.setItem("bluefire.local.scenario.v1", JSON.stringify(draft));
  if (options.clean) localStorage.setItem("bluefire.local.scenario-saved.v1", JSON.stringify(draft));
  vi.spyOn(api, "scenarios").mockImplementation(() => options.unavailable ? Promise.reject(new Error("Packaged request unavailable")) : Promise.resolve({ scenarios: [packaged] }));
  vi.spyOn(api, "scenarioVersions").mockImplementation(() => options.versions ?? (options.unavailable ? Promise.reject(new Error("Version request unavailable")) : Promise.resolve({ schema_version: "bluefire.scenario-version-list.v1", scenarios: [version()] })));
  vi.spyOn(api, "scenarioVersionHistory").mockImplementation(async (id) => ({ schema_version: "v1", scenarios: (options.history ?? (await (options.versions ?? Promise.resolve({ scenarios: [version()] }))).scenarios).filter(item => item.scenario_id === id) }));
  vi.spyOn(api, "immutableScenarioVersion").mockImplementation(async (id, number) => {
    const item = options.exact ?? (await (options.versions ?? Promise.resolve({ scenarios: [version()] }))).scenarios.find(item => item.scenario_id === id && item.version === number);
    if (!item) throw new Error("Version not found");
    return { schema_version: "v1", scenario: item };
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity }, mutations: { retry: false } } }); clients.push(client);
  const view = render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter initialEntries={[options.url ?? "/scenarios"]}><Context/><Routes><Route path="/scenarios" element={<ScenariosPage/>}/><Route path="/builder" element={<h1>Experiment editor</h1>}/></Routes></MemoryRouter></ProductProvider></QueryClientProvider>);
  return { ...view, client, draft };
}
function documentNow() { return JSON.parse(screen.getByLabelText("Current document").textContent!) as Scenario; }
async function savedRow() { return screen.findByRole("article", { name: "Saved collection procedure - Saved v3" }); }

it("focuses the exact saved handoff without replacing a same-ID dirty draft, including outside URL search", async () => {
  const draft = { ...saved, title: "Unsaved change" };
  setup({ draft, url: `/scenarios?selected=${saved.id}&q=unrelated` });
  const row = await savedRow();
  await waitFor(() => expect(row).toHaveFocus());
  expect(row).toHaveAttribute("aria-current", "true");
  expect(within(row).getByText(/outside this search/)).toBeVisible();
  expect(documentNow()).toEqual(draft);
  expect(screen.getByLabelText("Dirty")).toHaveTextContent("true");
  expect(screen.getByRole("searchbox")).toHaveValue("unrelated");
});

it("labels only an exact document match Saved v3 and retains a distinct changed working copy", async () => {
  const { client } = setup({ draft: saved, clean: true });
  expect(await savedRow()).toBeVisible();
  fireEvent.click(screen.getByRole("button", { name: "Edit elsewhere" }));
  expect(screen.getByRole("article", { name: "Later edit - Working draft" })).toBeVisible();
  expect(await savedRow()).toBeVisible();
  await act(async () => client.setQueryData(["scenario-versions"], { scenarios: [] }));
  await waitFor(() => expect(screen.queryByRole("article", { name: "Saved collection procedure - Saved v3" })).not.toBeInTheDocument());
});

it("persists search through editor navigation and Back without marking the draft saved", async () => {
  const user = userEvent.setup(); setup(); await savedRow();
  await user.type(screen.getByRole("searchbox"), "My working");
  await user.click(screen.getByRole("button", { name: "Continue editing" }));
  expect(screen.getByRole("heading", { name: "Experiment editor" })).toBeVisible();
  expect(screen.getByLabelText("Dirty")).toHaveTextContent("true");
  await user.click(screen.getByRole("button", { name: "Back" }));
  expect(screen.getByRole("searchbox")).toHaveValue("My working");
});

it.each(["Open", "Duplicate"])("protects the dirty document before %s, allows inspection/cancel, then applies only confirmation", async (action) => {
  const user = userEvent.setup(); const { draft } = setup();
  await user.click(within(await savedRow()).getByRole("button", { name: action }));
  const dialog = screen.getByRole("dialog", { name: "Replace your working draft?" });
  await user.click(within(dialog).getByText("Review draft and replacement"));
  expect(within(dialog).getByRole("heading", { name: "Current draft" })).toBeVisible();
  expect(documentNow()).toEqual(draft);
  await user.click(within(dialog).getByRole("button", { name: "Keep working draft" }));
  expect(documentNow()).toEqual(draft);
  expect(within(await savedRow()).getByRole("button", { name: action })).toHaveFocus();
  await user.click(within(await savedRow()).getByRole("button", { name: action }));
  await user.click(screen.getByRole("button", { name: `Replace draft and ${action.toLowerCase()}` }));
  if (action === "Open") { expect(documentNow()).toEqual(saved); expect(screen.getByLabelText("Dirty")).toHaveTextContent("false"); }
  else { expect(documentNow().title).toBe(`${saved.title} copy`); expect(documentNow().id).not.toBe(saved.id); expect(screen.getByLabelText("Dirty")).toHaveTextContent("true"); }
});

it("guards creation with the proposed name and only replaces on explicit confirmation", async () => {
  const user = userEvent.setup(); const { draft } = setup(); await savedRow();
  await user.click(screen.getByRole("button", { name: "New experiment" }));
  await user.clear(screen.getByRole("textbox", { name: "Experiment name" }));
  await user.type(screen.getByRole("textbox", { name: "Experiment name" }), "New procedure");
  await user.click(screen.getByRole("button", { name: "Create draft" }));
  expect(documentNow()).toEqual(draft);
  expect(screen.getByRole("dialog")).toHaveTextContent("New procedure");
  await user.click(screen.getByRole("button", { name: "Replace draft and create" }));
  expect(documentNow().title).toBe("New procedure"); expect(documentNow().steps).toEqual([]);
});

it("does not discard a newer edit made while a replacement dialog is open", async () => {
  setup(); fireEvent.click(within(await savedRow()).getByRole("button", { name: "Open" }));
  fireEvent.click(screen.getByRole("button", { name: "Edit elsewhere", hidden: true }));
  fireEvent.click(screen.getByRole("button", { name: "Replace draft and open" }));
  expect(documentNow().title).toBe("Later edit"); expect(screen.getByRole("dialog")).toBeVisible();
  expect(within(screen.getByRole("dialog")).getByRole("status")).toHaveTextContent("Review it again");
});

it("guards an imported document and rejects malformed files without losing draft data", async () => {
  const user = userEvent.setup(); const { draft } = setup(); await savedRow();
  await user.upload(screen.getByLabelText("Import experiment JSON file"), new File([JSON.stringify(saved)], "procedure.json", { type: "application/json" }));
  expect(await screen.findByRole("dialog", { name: "Replace your working draft?" })).toBeVisible();
  expect(documentNow()).toEqual(draft);
  await user.click(screen.getByRole("button", { name: "Keep working draft" }));
  await user.upload(screen.getByLabelText("Import experiment JSON file"), new File(["not json"], "bad.json", { type: "application/json" }));
  await waitFor(() => expect(screen.getByText(/Unexpected token|not valid JSON/)).toBeVisible());
  expect(documentNow()).toEqual(draft); expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
});

it("keeps the draft editable when both queries fail and retries independently", async () => {
  setup({ unavailable: true });
  expect(await screen.findByRole("button", { name: "Retry saved versions" })).toBeVisible();
  expect(screen.getAllByRole("alert")).toHaveLength(2);
  expect(screen.getByRole("button", { name: "Continue editing" })).toBeEnabled();
  vi.mocked(api.scenarioVersions).mockResolvedValue({ schema_version: "bluefire.scenario-version-list.v1", scenarios: [version()] });
  fireEvent.click(screen.getByRole("button", { name: "Retry saved versions" }));
  expect(await savedRow()).toBeVisible();
  expect(screen.getByRole("alert")).toHaveTextContent("Packaged experiments unavailable");
});

it("selects a same-ID working draft independently from its saved version", async () => {
  const user = userEvent.setup(); setup({ draft: { ...saved, title: "My draft edits" }, url: `/scenarios?selected=${saved.id}` });
  await savedRow();
  await user.click(screen.getByRole("button", { name: "My draft edits" }));
  expect(screen.getByRole("article", { name: "My draft edits - Working draft" })).toHaveFocus();
  expect(await savedRow()).not.toHaveAttribute("aria-current");
  expect(screen.getByLabelText("Location")).toHaveTextContent("view=draft");
});

it("checks the latest dirty draft after an asynchronous file read", async () => {
  const user = userEvent.setup(); setup({ clean: true }); await savedRow();
  const readers: FileReader[] = [];
  vi.spyOn(FileReader.prototype, "readAsText").mockImplementation(function (this: FileReader) { readers.push(this); });
  await user.upload(screen.getByLabelText("Import experiment JSON file"), new File(["deferred"], "procedure.json", { type: "application/json" }));
  fireEvent.click(screen.getByRole("button", { name: "Edit elsewhere" }));
  await act(async () => { Object.defineProperty(readers[0]!, "result", { value: JSON.stringify(saved) }); readers[0]!.dispatchEvent(new ProgressEvent("load")); });
  expect(screen.getByRole("dialog")).toHaveTextContent("Later edit");
  expect(documentNow().title).toBe("Later edit");
  expect(screen.getByLabelText("Dirty")).toHaveTextContent("true");
});

it("ignores an import result after navigating away", async () => {
  const user = userEvent.setup(); const { draft } = setup(); await savedRow();
  const readers: FileReader[] = [];
  vi.spyOn(FileReader.prototype, "readAsText").mockImplementation(function (this: FileReader) { readers.push(this); });
  await user.upload(screen.getByLabelText("Import experiment JSON file"), new File(["deferred"], "procedure.json", { type: "application/json" }));
  await user.click(screen.getByRole("button", { name: "Continue editing" }));
  await act(async () => { Object.defineProperty(readers[0]!, "result", { value: JSON.stringify(saved) }); readers[0]!.dispatchEvent(new ProgressEvent("load")); });
  expect(screen.getByRole("heading", { name: "Experiment editor" })).toBeVisible();
  expect(documentNow()).toEqual(draft);
});

it("exports the actual working draft from the replacement dialog without mutating it", async () => {
  const user = userEvent.setup(); const { draft } = setup();
  const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
  await user.click(within(await savedRow()).getByRole("button", { name: "Open" }));
  await user.click(screen.getByRole("button", { name: "Export working draft" }));
  const blob = vi.mocked(URL.createObjectURL).mock.lastCall![0] as Blob;
  const body = await new Promise<string>((resolve) => { const reader = new FileReader(); reader.onload = () => resolve(String(reader.result)); reader.readAsText(blob); });
  expect(JSON.parse(body)).toEqual(draft);
  expect(click.mock.instances[0]).toHaveAttribute("download", `${draft.id}.json`);
  expect(documentNow()).toEqual(draft); expect(screen.getByRole("dialog")).toBeVisible();
});

it("does not steal search focus when a delayed selected version arrives", async () => {
  let resolve!: (value: Awaited<ReturnType<typeof api.scenarioVersions>>) => void;
  const versions = new Promise<Awaited<ReturnType<typeof api.scenarioVersions>>>((done) => { resolve = done; });
  setup({ versions, url: `/scenarios?selected=${saved.id}` });
  const user = userEvent.setup();
  await user.type(screen.getByRole("searchbox"), "collection");
  await act(async () => resolve({ schema_version: "bluefire.scenario-version-list.v1", scenarios: [version()] }));
  expect(await savedRow()).toBeVisible();
  expect(screen.getByRole("searchbox")).toHaveFocus();
  expect(screen.getByRole("searchbox")).toHaveValue("collection");
});

it("yields delayed handoff focus to a keyboard-focused action", async () => {
  let resolve!: (value: Awaited<ReturnType<typeof api.scenarioVersions>>) => void;
  const versions = new Promise<Awaited<ReturnType<typeof api.scenarioVersions>>>((done) => { resolve = done; });
  setup({ versions, url: `/scenarios?selected=${saved.id}` });
  const user = userEvent.setup();
  screen.getByRole("searchbox").focus();
  await user.tab();
  const focusedAction = document.activeElement;
  expect(focusedAction?.tagName).toBe("BUTTON");
  await act(async () => resolve({ schema_version: "bluefire.scenario-version-list.v1", scenarios: [version()] }));
  expect(await savedRow()).toBeVisible();
  expect(focusedAction).toHaveFocus();
  await user.click(within(await savedRow()).getByRole("button", { name: saved.title }));
  expect(await savedRow()).toHaveFocus();
});

it("shows packaged identity for an unchanged packaged working copy without claiming a saved version", async () => {
  setup({ draft: packaged, clean: true }); await savedRow();
  expect(screen.getByRole("article", { name: "Packaged collection procedure - Packaged" })).toHaveTextContent("Current working copy");
  expect(screen.queryByRole("article", { name: /Packaged collection procedure - Saved/ })).not.toBeInTheDocument();
});

it("keeps cached saved versions visible when refreshing fails", async () => {
  const { client } = setup(); await savedRow();
  vi.mocked(api.scenarioVersions).mockRejectedValue(new Error("Temporary failure"));
  await act(async () => { await client.refetchQueries({ queryKey: ["scenario-versions"] }); });
  expect(await screen.findByRole("alert")).toHaveTextContent("Showing previously loaded records");
  expect(await savedRow()).toBeVisible();
});

it("keeps a duplicated result selected and visible outside the retained search", async () => {
  const user = userEvent.setup(); setup({ clean: true, url: "/scenarios?q=Saved+v3" });
  await user.click(within(await savedRow()).getByRole("button", { name: "Duplicate" }));
  const copy = await screen.findByRole("article", { name: `${saved.title} copy - Working draft` });
  expect(copy).toHaveAttribute("aria-current", "true");
  expect(copy).toHaveTextContent("outside this search");
  expect(screen.getByRole("searchbox")).toHaveValue("Saved v3");
});

it("does not replace a newer replacement dialog with a delayed file result", async () => {
  const user = userEvent.setup(); const { draft } = setup(); await savedRow();
  const readers: FileReader[] = [];
  vi.spyOn(FileReader.prototype, "readAsText").mockImplementation(function (this: FileReader) { readers.push(this); });
  await user.upload(screen.getByLabelText("Import experiment JSON file"), new File(["deferred"], "procedure.json", { type: "application/json" }));
  await user.click(within(await savedRow()).getByRole("button", { name: "Duplicate" }));
  await act(async () => { Object.defineProperty(readers[0]!, "result", { value: JSON.stringify(packaged) }); readers[0]!.dispatchEvent(new ProgressEvent("load")); });
  expect(screen.getByRole("dialog")).toHaveTextContent(`${saved.title} copy`);
  expect(screen.getByRole("button", { name: "Replace draft and duplicate" })).toBeVisible();
  expect(documentNow()).toEqual(draft);
});

it("groups saved revisions under one identity and opens the exact linked historical version", async () => {
  const older = { ...saved, title: "Earlier collection design" };
  const versions = Promise.resolve({ schema_version: "bluefire.scenario-version-list.v1", scenarios: [version()] });
  const { draft } = setup({ versions, history: [version(), { ...version(older), version: 2 }], exact: { ...version(older), version: 2 }, url: `/scenarios?selected=${saved.id}&version=2` });
  const oldRow = await screen.findByRole("article", { name: "Earlier collection design - Saved v2" });
  await waitFor(() => expect(oldRow).toHaveFocus());
  expect(oldRow).toBeVisible();
  expect(oldRow).toHaveAttribute("aria-current", "true");
  expect(screen.getByText("3 experiments")).toBeVisible();
  expect(screen.getByText("Current saved · v3")).toBeVisible();
  expect(within(oldRow).getByRole("link", { name: "Link to v2" })).toHaveAttribute("href", `/scenarios?selected=${saved.id}&version=2`);
  expect(documentNow()).toEqual(draft);
  const user = userEvent.setup();
  await user.click(within(oldRow).getByRole("button", { name: "Open" }));
  expect(screen.getByRole("dialog")).toHaveTextContent("Earlier collection design");
  expect(documentNow()).toEqual(draft);
});

it("does not label a filtered older revision latest or count it separately", async () => {
  const older = { ...saved, title: "Older only search" };
  setup({ history: [version(), { ...version(older), version: 2 }] });
  await savedRow(); await userEvent.click(screen.getByText("Version history"));
  await screen.findByRole("article", { name: "Older only search - Saved v2" });
  await userEvent.type(screen.getByRole("searchbox"), "Older only");
  expect(await savedRow()).toBeVisible();
  expect(screen.getByText("1 experiment")).toBeVisible();
  expect(screen.getByText("Current saved · v3")).toBeVisible();
});

it("retains an honest empty draft through browser restoration", async () => {
  const empty = { ...saved, purpose: "", start: "", steps: [], edges: [], limitations: [] };
  setup({ draft: empty }); await savedRow();
  expect(documentNow()).toEqual(empty);
  expect(screen.getByRole("button", { name: "Add first step" })).toBeVisible();
  expect(screen.queryByText(/Validate observable outcomes for/)).not.toBeInTheDocument();
});

it("restores added steps while the operator has not yet written a purpose", async () => {
  const drafting = { ...saved, purpose: "" };
  setup({ draft: drafting }); await savedRow();
  expect(documentNow()).toEqual(drafting);
});


const historical = () => {
  const first = { ...version({ ...saved, title: "Original procedure" }), version: 1 };
  const second = { ...version({ ...saved, title: "Revised procedure" }), version: 2 };
  return { first, second, history: [second, first], heads: Promise.resolve({ schema_version: "v1", scenarios: [second] }) };
};
it("loads complete history only on expansion while the active inventory contains just v2", async () => {
  const data = historical(); setup({ versions: data.heads, history: data.history }); const user = userEvent.setup();
  await screen.findByRole("article", { name: "Revised procedure - Saved v2" });
  expect(api.scenarioVersionHistory).not.toHaveBeenCalled();
  expect(screen.queryByText("Version history · 0 other versions")).not.toBeInTheDocument();
  await user.click(screen.getByText("Version history"));
  expect(await screen.findByRole("article", { name: "Original procedure - Saved v1" })).toBeVisible();
  expect(api.scenarioVersionHistory).toHaveBeenCalledExactlyOnceWith(saved.id);
  expect(screen.getByText("Current saved · v2")).toBeVisible();
  expect(screen.getByText("Version history · 1 other version")).toBeVisible();
});
it("reloads an exact v1 link independently of heads and protects the dirty draft before opening", async () => {
  const data = historical(); const url = `/scenarios?selected=${saved.id}&version=1`;
  const first = setup({ versions: data.heads, history: data.history, exact: data.first, url });
  const original = first.draft;
  let row = await screen.findByRole("article", { name: "Original procedure - Saved v1" });
  await waitFor(() => expect(row).toHaveAttribute("aria-current", "true"));
  expect(documentNow()).toEqual(original);
  first.unmount(); vi.restoreAllMocks();
  setup({ draft: original, versions: data.heads, history: data.history, exact: data.first, url });
  row = await screen.findByRole("article", { name: "Original procedure - Saved v1" });
  await waitFor(() => expect(row).toHaveAttribute("aria-current", "true"));
  expect(api.immutableScenarioVersion).toHaveBeenCalledExactlyOnceWith(saved.id, 1);
  const user = userEvent.setup(); await user.click(within(row).getByRole("button", { name: "Open" }));
  expect(documentNow()).toEqual(original);
  await user.click(screen.getByRole("button", { name: "Keep working draft" }));
  expect(documentNow()).toEqual(original);
  await user.click(within(row).getByRole("button", { name: "Open" }));
  await user.click(screen.getByRole("button", { name: "Replace draft and open" }));
  expect(documentNow()).toEqual(data.first.document);
  expect(screen.getByLabelText("Dirty")).toHaveTextContent("false");
});
it("shows exact historical content when the active inventory is unavailable", async () => {
  const data = historical(); setup({ unavailable: true, history: data.history, exact: data.first, url: `/scenarios?selected=${saved.id}&version=1` });
  const row = await screen.findByRole("article", { name: "Original procedure - Saved v1" });
  await waitFor(() => expect(row).toHaveAttribute("aria-current", "true"));
  expect(row).toBeVisible(); expect(screen.queryByText(/Current saved/)).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Retry saved versions" })).toBeVisible();
});
it.each(["missing", "mismatched"])("never substitutes the current head for a %s exact version", async (kind) => {
  const data = historical(); const number = kind === "missing" ? 9 : 1;
  const { draft } = setup({ versions: data.heads, history: data.history, exact: kind === "mismatched" ? data.second : undefined, url: `/scenarios?selected=${saved.id}&version=${number}` });
  expect(await screen.findByRole("button", { name: "Retry linked version" })).toBeVisible();
  expect(document.querySelector('[aria-current="true"]')).toBeNull();
  expect(documentNow()).toEqual(draft);
  expect(screen.getByText(/No other version was selected; your working draft is preserved/)).toBeVisible();
});
it("retains v1 as current after its content is reactivated without calling v2 current", async () => {
  const data = historical(); setup({ versions: Promise.resolve({ schema_version: "v1", scenarios: [data.first] }), history: data.history });
  await screen.findByRole("article", { name: "Original procedure - Saved v1" });
  await userEvent.click(screen.getByText("Version history"));
  expect(await screen.findByRole("article", { name: "Revised procedure - Saved v2" })).toBeVisible();
  expect(screen.getByText("Current saved · v1")).toBeVisible();
  expect(screen.queryByText("Current saved · v2")).not.toBeInTheDocument();
});
it("keeps unavailable history distinct from an empty history and retries the same experiment", async () => {
  const data = historical(); const { draft } = setup({ versions: data.heads, history: data.history });
  vi.mocked(api.scenarioVersionHistory).mockRejectedValueOnce(new Error("Connection lost"));
  await screen.findByRole("article", { name: "Revised procedure - Saved v2" });
  await userEvent.click(screen.getByText("Version history"));
  await userEvent.click(await screen.findByRole("button", { name: "Retry version history" }));
  expect(await screen.findByRole("article", { name: "Original procedure - Saved v1" })).toBeVisible();
  expect(documentNow()).toEqual(draft);
});

it("counts a retained v1 already open as the working copy while v2 remains current saved", async () => {
  const data = historical(); setup({ draft: data.first.document, clean: true, versions: data.heads, history: data.history });
  await screen.findByRole("article", { name: "Revised procedure - Saved v2" });
  await userEvent.click(screen.getByText("Version history"));
  expect(await screen.findByText("Saved v1 is already open as the current working copy.")).toBeVisible();
  expect(screen.getByText("Version history · 1 other version")).toBeVisible();
  expect(screen.queryByText("No other retained versions.")).not.toBeInTheDocument();
  expect(screen.getAllByRole("article", { name: "Original procedure - Saved v1" })).toHaveLength(1);
  expect(screen.getByText("Current saved · v2")).toBeVisible();
});

it("refreshes expanded history with the normal Save version invalidation prefix", async () => {
  const data = historical(); const { client } = setup({ versions: data.heads, history: data.history });
  await screen.findByRole("article", { name: "Revised procedure - Saved v2" });
  await userEvent.click(screen.getByText("Version history"));
  await screen.findByRole("article", { name: "Original procedure - Saved v1" });
  const third = { ...version({ ...saved, title: "Third saved procedure" }), version: 3 };
  vi.mocked(api.scenarioVersions).mockResolvedValue({ schema_version: "v1", scenarios: [third] });
  vi.mocked(api.scenarioVersionHistory).mockResolvedValue({ schema_version: "v1", scenarios: [third, ...data.history] });
  await act(async () => { await client.invalidateQueries({ queryKey: ["scenario-versions"] }); });
  expect(await screen.findByText("Current saved · v3")).toBeVisible();
  expect(screen.getByText("Version history · 2 other versions")).toBeVisible();
  expect(screen.getByRole("article", { name: "Original procedure - Saved v1" })).toBeVisible();
  expect(screen.getByRole("article", { name: "Revised procedure - Saved v2" })).toBeVisible();
});
