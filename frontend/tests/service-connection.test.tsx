import { focusManager, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AppShell } from "../src/components/AppShell";
import { api, ApiError } from "../src/lib/api";
import { demoCatalog, demoScenario } from "../src/lib/demo";
import { ProductProvider } from "../src/state/ProductContext";

let clients: QueryClient[] = [];
beforeEach(() => {
  vi.useFakeTimers(); vi.setSystemTime(new Date("2030-01-01T12:00:00Z"));
  focusManager.setFocused(true); vi.stubGlobal("scrollTo", vi.fn());
});
afterEach(() => {
  clients.forEach((client) => client.clear()); clients = [];
  focusManager.setFocused(undefined); vi.useRealTimers(); vi.unstubAllGlobals();
});
const flush = async (ms = 1) => { await act(async () => { await vi.advanceTimersByTimeAsync(ms); }); };
const success = () => new Response(null, { status: 204 });
function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } } });
  clients.push(client);
  client.setQueryData(["catalog"], demoCatalog); client.setQueryData(["scenarios"], { scenarios: [demoScenario] });
  const catalog = vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  const scenarios = vi.spyOn(api, "scenarios").mockResolvedValue({ scenarios: [demoScenario] });
  const draft = { ...structuredClone(demoScenario), title: "Retained manual draft" };
  localStorage.setItem("bluefire.local.scenario.v1", JSON.stringify(draft));
  const view = render(<QueryClientProvider client={client}><ProductProvider><MemoryRouter initialEntries={["/compare"]}><Routes><Route element={<AppShell/>}><Route path="*" element={<p>Retained comparison result</p>}/></Route></Routes></MemoryRouter></ProductProvider></QueryClientProvider>);
  return { ...view, client, catalog, scenarios, draft };
}

it("does not treat a cached successful catalog as a service connection", async () => {
  let release!: (response: Response) => void;
  const fetcher = vi.fn(() => new Promise<Response>((resolve) => { release = resolve; }));
  vi.stubGlobal("fetch", fetcher);
  const view = mount();
  expect(screen.queryByText("Connected")).not.toBeInTheDocument();
  await act(async () => { release(success()); }); await flush();
  expect(screen.getByText("Connected")).toBeVisible(); expect(fetcher).toHaveBeenCalledOnce();
  expect(fetcher).toHaveBeenCalledWith("/api/v1/session", expect.objectContaining({ method: "GET", credentials: "same-origin", cache: "no-store", referrerPolicy: "no-referrer" }));
  expect(view.catalog).not.toHaveBeenCalled(); expect(view.scenarios).not.toHaveBeenCalled();
});

it("detects stopped service on a terminal page, preserves cached work and reconnects using GET only", async () => {
  const fetcher = vi.fn().mockResolvedValueOnce(success()).mockRejectedValueOnce(new TypeError("connection refused")).mockResolvedValue(success());
  vi.stubGlobal("fetch", fetcher);
  const view = mount(); await flush(); expect(screen.getByText("Connected")).toBeVisible();
  await flush(15_010);
  expect(screen.getByText("Disconnected")).toBeVisible(); expect(screen.queryByText("Connected")).not.toBeInTheDocument();
  expect(screen.getByText("Retained comparison result")).toBeVisible();
  expect(JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")!)).toEqual(view.draft);
  expect(view.client.getQueryData(["catalog"])).toEqual(demoCatalog);
  fireEvent.click(screen.getByRole("button", { name: "Check connection" })); await flush();
  expect(screen.getByText("Connected")).toBeVisible(); expect(fetcher).toHaveBeenCalledTimes(3);
  expect(fetcher.mock.calls.every(([url, options]) => url === "/api/v1/session" && options.method === "GET" && options.body === undefined)).toBe(true);
  expect(view.catalog).not.toHaveBeenCalled(); expect(view.scenarios).not.toHaveBeenCalled();
});

it.each([401, 403])("reports unavailable browser session (%s) without renewing credentials or losing the current result", async (status) => {
  const fetcher = vi.fn().mockResolvedValueOnce(success()).mockResolvedValue(new Response(null, { status }));
  vi.stubGlobal("fetch", fetcher); mount(); await flush(); await flush(15_010);
  expect(screen.getAllByText("Session unavailable").length).toBeGreaterThan(0);
  expect(screen.getByText(/Relaunch with bluefire ui/)).toBeVisible(); expect(screen.getByText("Retained comparison result")).toBeVisible();
  expect(screen.queryByText("Connected")).not.toBeInTheDocument();
  expect(fetcher.mock.calls.every(([, options]) => options.method === "GET" && !Object.keys(options.headers).some((key) => /bootstrap/i.test(key)))).toBe(true);
});

it("expires the connection indication when foreground checks pause and rechecks on return", async () => {
  const fetcher = vi.fn().mockResolvedValue(success()); vi.stubGlobal("fetch", fetcher);
  mount(); await flush(); act(() => focusManager.setFocused(false)); await flush(31_000);
  expect(fetcher).toHaveBeenCalledOnce(); expect(screen.getAllByText("Connection unchecked").length).toBeGreaterThan(0);
  expect(screen.queryByText("Connected")).not.toBeInTheDocument();
  act(() => focusManager.setFocused(true)); await flush();
  expect(fetcher).toHaveBeenCalledTimes(2); expect(screen.getByText("Connected")).toBeVisible();
});

it("bounds an unresponsive normal session GET and keeps previous success from masking failure", async () => {
  const fetcher = vi.fn().mockResolvedValueOnce(success()).mockImplementation((_url, options: RequestInit) => new Promise((_resolve, reject) => {
    options.signal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")), { once: true });
  }));
  vi.stubGlobal("fetch", fetcher); mount(); await flush(); await flush(20_020);
  expect(screen.getByText("Disconnected")).toBeVisible(); expect(screen.queryByText("Connected")).not.toBeInTheDocument(); expect(fetcher).toHaveBeenCalledTimes(2);
});

it("requires the normal204 response rather than treating any reachable HTTP page as ready", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("login or error page", { status: 200 })));
  await expect(api.serviceConnection()).rejects.toBeInstanceOf(ApiError);
});

it("cancels pending liveness request when the workspace unmounts", async () => {
  let signal: AbortSignal | undefined;
  vi.stubGlobal("fetch", vi.fn((_url, options: RequestInit) => new Promise((_resolve, reject) => {
    signal = options.signal ?? undefined;
    signal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")), { once: true });
  })));
  const view = mount(); expect(signal?.aborted).toBe(false); view.unmount(); await flush(); expect(signal?.aborted).toBe(true);
});
