import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { RunNameControl } from "../src/components/RunNameControl";
import { api, ApiError } from "../src/lib/api";
import { runLabel } from "../src/lib/runPresentation";
import type { RunPresentation, RunRecord } from "../src/types";

const first: RunRecord = {
  run_id: "run-20260908T120000Z-0123456789abcdef", scenario_title: "File collection",
  mode: "execute", status: "completed", steps: [{ step_id: "collect", status: "success" }],
  manifest: { bundle_hash: "sha256:original" }, evidence: { records: [] },
};
const second: RunRecord = { ...structuredClone(first), run_id: "run-20260908T120001Z-0123456789abcdef", scenario_title: "Other procedure" };
function saved(run: RunRecord, name: string | null): RunPresentation {
  return { schema_version: "bluefire.run-presentation.v1", run_id: run.run_id, display_name: name, default_name: run.scenario_title!, updated_at: "2026-09-08T12:01:00Z" };
}
const clients: QueryClient[] = [];
afterEach(() => { clients.splice(0).forEach(client => client.clear()); });

function Current({ runId }: { runId: string }) {
  const { data } = useQuery<RunRecord>({ queryKey: ["run", runId], enabled: false });
  return <><h1>{runLabel(data!)}</h1><RunNameControl key={runId} run={data!}/></>;
}
function setup(run = first) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  clients.push(client);
  client.setQueryData(["run", first.run_id], structuredClone(first));
  client.setQueryData(["run", second.run_id], structuredClone(second));
  client.setQueryData(["runs"], { runs: [structuredClone(first), structuredClone(second)], unavailable_run_count: 3 });
  client.setQueryData(["run", run.run_id], structuredClone(run));
  const tree = (runId: string) => <QueryClientProvider client={client}><Current runId={runId}/></QueryClientProvider>;
  const view = render(tree(run.run_id));
  return { ...view, client, show: (runId: string) => view.rerender(tree(runId)) };
}
async function enterName(name: string) {
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Rename run" }));
  await user.clear(screen.getByRole("textbox", { name: "Run name" }));
  await user.type(screen.getByRole("textbox", { name: "Run name" }), name);
  return user;
}

it("publishes a confirmed name to the exact run and history without modifying evidence or unrelated records", async () => {
  let resolve!: (value: RunPresentation) => void;
  const rename = vi.spyOn(api, "renameRun").mockImplementation(() => new Promise(done => { resolve = done; }));
  const { client } = setup();
  const user = await enterName("Operator collection check");
  await user.click(screen.getByRole("button", { name: "Save name" }));
  expect(rename).toHaveBeenCalledExactlyOnceWith(first.run_id, "Operator collection check");
  expect(screen.getByRole("textbox", { name: "Run name" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Cancel" })).toBeDisabled();
  await user.keyboard("{Escape}");
  expect(screen.getByRole("dialog", { name: "Rename run" })).toBeVisible();
  expect(client.getQueryData(["run", first.run_id])).toEqual(first);
  const presentation = saved(first, "Operator collection check");
  await act(async () => resolve(presentation));
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  expect(screen.getByRole("heading", { name: "Operator collection check" })).toBeVisible();
  expect(client.getQueryData(["run", first.run_id])).toEqual({ ...first, presentation });
  expect(client.getQueryData(["run", second.run_id])).toEqual(second);
  expect(client.getQueryData(["runs"])).toEqual({ runs: [{ ...first, presentation }, second], unavailable_run_count: 3 });
  expect(client.getQueryState(["runs"])?.isInvalidated).toBe(true);
  expect(client.getQueryState(["run", second.run_id])?.isInvalidated).toBe(false);
});

it("keeps an uncertain name and cached evidence available until an explicit retry confirms it", async () => {
  const rename = vi.spyOn(api, "renameRun").mockRejectedValueOnce(new ApiError("Refresh this run before trying again.", "run_name_unconfirmed"))
    .mockResolvedValueOnce(saved(first, "Retained name"));
  const { client } = setup();
  const user = await enterName("Retained name");
  await user.click(screen.getByRole("button", { name: "Save name" }));
  expect(await screen.findByText("Refresh this run before trying again.")).toBeVisible();
  expect(screen.getByRole("textbox", { name: "Run name" })).toHaveValue("Retained name");
  expect(client.getQueryData(["run", first.run_id])).toEqual(first);
  expect(rename).toHaveBeenCalledTimes(1);
  await user.click(screen.getByRole("button", { name: "Save name" }));
  expect(await screen.findByRole("heading", { name: "Retained name" })).toBeVisible();
  expect(rename).toHaveBeenCalledTimes(2);
});

it("resets through a null presentation request and restores the frozen experiment name", async () => {
  const renamed = { ...first, presentation: saved(first, "Custom name") };
  const rename = vi.spyOn(api, "renameRun").mockResolvedValue(saved(first, null));
  setup(renamed);
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Rename run" }));
  expect(screen.getByRole("textbox", { name: "Run name" })).toHaveValue("Custom name");
  await user.click(screen.getByRole("button", { name: "Use experiment name" }));
  expect(rename).toHaveBeenCalledExactlyOnceWith(first.run_id, null);
  expect(await screen.findByRole("heading", { name: "File collection" })).toBeVisible();
});

it("allows cancellation and refuses a blank submission without changing either cache", async () => {
  const rename = vi.spyOn(api, "renameRun");
  const { client } = setup();
  const user = await enterName("   ");
  expect(screen.getByRole("button", { name: "Save name" })).toBeDisabled();
  await user.click(screen.getByRole("button", { name: "Cancel" }));
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Rename run" })).toHaveFocus();
  expect(rename).not.toHaveBeenCalled();
  expect(client.getQueryData(["run", first.run_id])).toEqual(first);
});

it("settles a late result for its original run without closing another run's rename dialog", async () => {
  let resolve!: (value: RunPresentation) => void;
  vi.spyOn(api, "renameRun").mockImplementation(() => new Promise(done => { resolve = done; }));
  const { client, show } = setup();
  const user = await enterName("First run name");
  await user.click(screen.getByRole("button", { name: "Save name" }));
  show(second.run_id);
  await enterName("Second run draft name");
  await act(async () => resolve(saved(first, "First run name")));
  expect(screen.getByRole("dialog", { name: "Rename run" })).toBeVisible();
  expect(screen.getByRole("textbox", { name: "Run name" })).toHaveValue("Second run draft name");
  expect(screen.getByRole("heading", { name: "Other procedure", hidden: true })).toBeVisible();
  expect(client.getQueryData<RunRecord>(["run", first.run_id])?.presentation?.display_name).toBe("First run name");
  expect(client.getQueryData(["run", second.run_id])).toEqual(second);
});
