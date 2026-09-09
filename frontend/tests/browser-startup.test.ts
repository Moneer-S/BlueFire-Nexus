import { afterEach, expect, it, vi } from "vitest";
import { watchBrowserSession } from "../src/lib/browser-startup";

let stop: (() => void) | undefined;
afterEach(() => { stop?.(); stop = undefined; vi.unstubAllGlobals(); });
const response = (status: number) => new Response(null, { status });
const flush = async () => { for (let index = 0; index < 8; index += 1) await Promise.resolve(); };
function sameDocumentHash(hash: string) {
  const oldURL = window.location.href;
  window.history.pushState(window.history.state, "", hash);
  const newURL = window.location.href;
  window.dispatchEvent(new PopStateEvent("popstate", { state: window.history.state }));
  window.dispatchEvent(new HashChangeEvent("hashchange", { oldURL, newURL }));
}

it("reconnects an unavailable same-document session before routing and retains work", async () => {
  window.history.replaceState({ idx: 4 }, "", "#/detection-lab?candidate=fixture");
  localStorage.setItem("bluefire.local.scenario.v1", '{"draft":"unchanged"}');
  sessionStorage.setItem("bluefire.assistance.receipt.v1", '{"submission_id":"retained"}');
  const capability = "A".repeat(64);
  const fetcher = vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => {
    expect(window.location.hash).toBe("#/detection-lab?candidate=fixture");
    return response(init?.method === "POST" ? 204 : 401);
  });
  vi.stubGlobal("fetch", fetcher);
  const connected = vi.fn(), unavailable = vi.fn();
  stop = watchBrowserSession({ connected, unavailable }).dispose;
  await flush(); expect(unavailable).toHaveBeenCalledOnce();
  const observedRoutes: string[] = [];
  const router = () => observedRoutes.push(window.location.hash);
  window.addEventListener("hashchange", router);
  try { sameDocumentHash(`#bluefire-session=${capability}`); await flush(); }
  finally { window.removeEventListener("hashchange", router); }
  expect(connected).toHaveBeenCalledOnce();
  expect(observedRoutes).toEqual(["#/detection-lab?candidate=fixture"]);
  expect(window.history.state).toEqual({ idx: 4 });
  expect(fetcher.mock.calls.map(([, init]) => init?.method)).toEqual(["GET", "POST"]);
  expect(fetcher.mock.lastCall).toEqual(["/api/v1/session", expect.objectContaining({ credentials: "same-origin", cache: "no-store", referrerPolicy: "no-referrer", headers: { Accept: "application/json", "X-BlueFire-Browser-Bootstrap": capability } })]);
  expect(localStorage.getItem("bluefire.local.scenario.v1")).toBe('{"draft":"unchanged"}');
  expect(sessionStorage.getItem("bluefire.assistance.receipt.v1")).toBe('{"submission_id":"retained"}');
});

it("scrubs malformed and failed fresh links and accepts a later fresh retry without reload", async () => {
  window.history.replaceState(null, "", "#/builder");
  const fetcher = vi.fn().mockResolvedValue(response(401)); vi.stubGlobal("fetch", fetcher);
  const connected = vi.fn(), unavailable = vi.fn(); stop = watchBrowserSession({ connected, unavailable }).dispose;
  await flush();
  sameDocumentHash(`#bluefire-session=${"B".repeat(64)}&duplicate=bad`); await flush();
  expect(fetcher).toHaveBeenCalledOnce(); expect(window.location.hash).toBe("#/builder");
  sameDocumentHash(`#bluefire-session=${"C".repeat(64)}`); await flush();
  expect(fetcher.mock.calls.map(([, init]) => init?.method)).toEqual(["GET", "POST", "GET"]);
  expect(connected).not.toHaveBeenCalled(); expect(unavailable).toHaveBeenCalledTimes(3);
  fetcher.mockResolvedValue(response(204));
  sameDocumentHash(`#bluefire-session=${"D".repeat(64)}`); await flush();
  expect(connected).toHaveBeenCalledOnce(); expect(window.location.hash).toBe("#/builder");
  expect(fetcher.mock.calls.every(([url, init]) => url === "/api/v1/session" && init.body === undefined)).toBe(true);
});

it("does not let an old failed startup response replace a newer successful connection", async () => {
  window.history.replaceState(null, "", "#/runs");
  let release!: (value: Response) => void;
  const fetcher = vi.fn().mockImplementationOnce(() => new Promise<Response>(resolve => { release = resolve; })).mockResolvedValue(response(204));
  vi.stubGlobal("fetch", fetcher);
  const connected = vi.fn(), unavailable = vi.fn(); stop = watchBrowserSession({ connected, unavailable }).dispose;
  sameDocumentHash(`#bluefire-session=${"E".repeat(64)}`); await flush();
  expect(connected).toHaveBeenCalledOnce();
  release(response(401)); await flush();
  expect(unavailable).not.toHaveBeenCalled(); expect(connected).toHaveBeenCalledOnce();
});

it("ignores ordinary routes and preserves the newest route across a replayed launch URL", async () => {
  window.history.replaceState(null, "", "#/runs");
  const fetcher = vi.fn().mockResolvedValue(response(204)); vi.stubGlobal("fetch", fetcher);
  const connected = vi.fn(); stop = watchBrowserSession({ connected, unavailable: vi.fn() }).dispose; await flush();
  sameDocumentHash("#/compare?left=run-fixture"); await flush(); expect(fetcher).toHaveBeenCalledOnce();
  fetcher.mockResolvedValueOnce(response(401));
  sameDocumentHash(`#bluefire-session=${"F".repeat(64)}`); await flush();
  expect(window.location.hash).toBe("#/compare?left=run-fixture");
  expect(fetcher.mock.calls.map(([, init]) => init?.method)).toEqual(["GET", "POST", "GET"]);
  expect(connected).toHaveBeenCalledTimes(2);
  stop(); sameDocumentHash(`#bluefire-session=${"G".repeat(64)}`); await flush();
  expect(fetcher).toHaveBeenCalledTimes(3);
});
