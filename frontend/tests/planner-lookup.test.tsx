import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog } from "../src/lib/demo";
import { AIPlannerPage } from "../src/pages/AIPlanner";
import { ProductProvider } from "../src/state/ProductContext";
import type { RunJob } from "../src/types";

vi.mock("../src/components/ProviderSetup", () => ({ ProviderSetup: () => null }));

function job(jobId: string): RunJob {
  return { schema_version: "bluefire.job.v1", job_id: jobId, kind: "scenario.run", state: "completed", request: {}, progress: { phase: "completed" }, result_ref: `result-${jobId}` };
}

function renderPlanner() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity, gcTime: Infinity } } });
  client.setQueryData(["catalog"], demoCatalog);
  vi.spyOn(api, "proposalReviews").mockImplementation(async (jobId) => ({ schema_version: "bluefire.ai-proposal-review-list.v1", job_id: jobId, proposals: [] }));
  const rendered = render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter><AIPlannerPage /></MemoryRouter></ProductProvider></QueryClientProvider>);
  return { ...rendered, client };
}

async function settleLookup() {
  await act(async () => { await vi.advanceTimersByTimeAsync(200); });
  await act(async () => { await vi.advanceTimersByTimeAsync(0); });
}

afterEach(() => vi.useRealTimers());

describe("Planner job lookup", () => {
  it("reads once after typing settles and cancels an unmounted pending lookup", async () => {
    vi.useFakeTimers();
    const lookup = vi.spyOn(api, "job").mockImplementation(async (id) => job(id));
    const view = renderPlanner();
    const input = screen.getByRole("textbox", { name: "Job ID" });
    const id = "job-0123456789abcdef0123456789abcdef";
    for (let end = 1; end <= id.length; end += 1) fireEvent.change(input, { target: { value: id.slice(0, end) } });
    expect(lookup).not.toHaveBeenCalled();
    await settleLookup();
    expect(lookup).toHaveBeenCalledExactlyOnceWith(id);
    expect(screen.getByText(`result-${id}`)).toBeVisible();

    fireEvent.change(input, { target: { value: "" } });
    fireEvent.change(input, { target: { value: "job-next" } });
    expect(screen.queryByText(`result-${id}`)).not.toBeInTheDocument();
    view.unmount();
    await settleLookup();
    expect(lookup).toHaveBeenCalledTimes(1);
    view.client.clear();
  });

  it("keeps a late previous response out of a newly selected job", async () => {
    vi.useFakeTimers();
    let finishFirst!: (value: RunJob) => void;
    const pending = new Promise<RunJob>((resolve) => { finishFirst = resolve; });
    const lookup = vi.spyOn(api, "job").mockImplementation(async (id) => id === "job-first" ? pending : job(id));
    const view = renderPlanner();
    const input = screen.getByRole("textbox", { name: "Job ID" });
    fireEvent.change(input, { target: { value: "job-first" } });
    await settleLookup();
    expect(lookup).toHaveBeenCalledExactlyOnceWith("job-first");
    fireEvent.change(input, { target: { value: "" } });
    fireEvent.change(input, { target: { value: "job-second" } });
    await settleLookup();
    expect(lookup.mock.calls.map(([id]) => id)).toEqual(["job-first", "job-second"]);
    expect(screen.getByText("result-job-second")).toBeVisible();
    await act(async () => { finishFirst(job("job-first")); await vi.advanceTimersByTimeAsync(0); });
    expect(input).toHaveValue("job-second");
    expect(screen.getByText("result-job-second")).toBeVisible();
    expect(screen.queryByText("result-job-first")).not.toBeInTheDocument();
    view.unmount();
    view.client.clear();
  });

  it("hides a cached review until editing back to the same ID settles", async () => {
    vi.useFakeTimers();
    vi.spyOn(api, "job").mockImplementation(async (id) => job(id));
    const view = renderPlanner();
    const input = screen.getByRole("textbox", { name: "Job ID" });
    fireEvent.change(input, { target: { value: "job-cached" } });
    await settleLookup();
    expect(screen.getByText("result-job-cached")).toBeVisible();
    fireEvent.change(input, { target: { value: "job-cachedx" } });
    fireEvent.change(input, { target: { value: "job-cached" } });
    expect(screen.queryByText("result-job-cached")).not.toBeInTheDocument();
    await act(async () => { await vi.advanceTimersByTimeAsync(199); });
    expect(screen.queryByText("result-job-cached")).not.toBeInTheDocument();
    await act(async () => { await vi.advanceTimersByTimeAsync(1); });
    expect(screen.getByText("result-job-cached")).toBeVisible();
    fireEvent.change(input, { target: { value: "job-cached " } });
    expect(screen.queryByText("result-job-cached")).not.toBeInTheDocument();
    await settleLookup();
    expect(screen.getByText("result-job-cached")).toBeVisible();
    view.unmount();
    view.client.clear();
  });
});
