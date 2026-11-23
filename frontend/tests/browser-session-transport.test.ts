import { beforeEach, expect, it, vi } from "vitest";

const KEY = "bluefire.browser-session.v1";
const TOKEN = "S".repeat(64);
beforeEach(() => { vi.resetModules(); sessionStorage.clear(); window.history.replaceState({}, "", "/"); });

it("uses only an explicit header and cannot attach it to another origin, port, or non-API path", async () => {
  sessionStorage.setItem(KEY, TOKEN);
  const { browserApiFetch } = await import("../src/lib/browser-session");
  const fetcher = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
  vi.stubGlobal("fetch", fetcher);
  for (const target of [
    "http://127.0.0.1:9999/api/v1/catalog",
    "https://example.com/api/v1/catalog",
    "//example.com/api/v1/catalog",
    "/ui/app.js",
    "/api/v1/catalog#private",
    `http://name:password@${location.host}/api/v1/catalog`, // pragma: allowlist secret -- synthetic rejected-URL fixture
  ]) {
    await expect(browserApiFetch(target)).rejects.toThrow("The local API address is invalid.");
  }
  expect(fetcher).not.toHaveBeenCalled();
  await browserApiFetch("/api/v1/catalog", { credentials: "include", redirect: "follow", headers: { "X-BlueFire-Browser-Bootstrap": "forged", "X-BlueFire-Session": "forged" } });
  const [path, options] = fetcher.mock.calls[0]!;
  expect(path).toBe("/api/v1/catalog");
  expect(options).toMatchObject({ credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer" });
  expect(new Headers(options.headers).get("X-BlueFire-Session")).toBe(TOKEN);
  expect(new Headers(options.headers).has("X-BlueFire-Browser-Bootstrap")).toBe(false);
});

it("keeps the same header boundary for liveness, catalog and bundle export", async () => {
  sessionStorage.setItem(KEY, TOKEN);
  const { api } = await import("../src/lib/api");
  const fetcher = vi.fn(async (path: string) => path.endsWith("/session") ? new Response(null, { status: 204 })
    : path.endsWith("/bundle") ? new Response("bundle", { headers: { "Content-Type": "application/zip" } })
    : new Response(JSON.stringify({ behaviors: [], actions: [] }), { status: 200 }));
  vi.stubGlobal("fetch", fetcher);
  await api.serviceConnection(); await api.catalog();
  await api.runBundle("run-20300101T000000Z-0123456789abcdef", new AbortController().signal);
  expect(fetcher).toHaveBeenCalledTimes(3);
  for (const [, options] of fetcher.mock.calls as unknown as [string, RequestInit][]) {
    expect(options.credentials).toBe("omit");
    expect(options.redirect).toBe("error");
    expect(new Headers(options.headers).get("X-BlueFire-Session")).toBe(TOKEN);
  }
});

it("removes expired authority without erasing a replacement from a concurrent exchange", async () => {
  sessionStorage.setItem(KEY, TOKEN);
  const { browserApiFetch, exchangeBrowserCapability } = await import("../src/lib/browser-session");
  let release!: (response: Response) => void;
  const fetcher = vi.fn().mockImplementationOnce(() => new Promise<Response>(resolve => { release = resolve; }))
    .mockResolvedValueOnce(new Response(JSON.stringify({ session: "N".repeat(64) })))
    .mockResolvedValueOnce(new Response(null, { status: 401 }));
  vi.stubGlobal("fetch", fetcher);
  const oldRequest = browserApiFetch("/api/v1/session");
  await exchangeBrowserCapability("C".repeat(64));
  release(new Response(null, { status: 401 })); await oldRequest;
  expect(sessionStorage.getItem(KEY)).toBe("N".repeat(64));
  await browserApiFetch("/api/v1/session");
  expect(sessionStorage.getItem(KEY)).toBeNull();
});

it("honors explicit storage removal and never falls back to a cookie", async () => {
  sessionStorage.setItem(KEY, TOKEN);
  const { browserApiFetch } = await import("../src/lib/browser-session");
  const fetcher = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
  vi.stubGlobal("fetch", fetcher);
  await browserApiFetch("/api/v1/session"); sessionStorage.clear();
  document.cookie = `bluefire_session=${TOKEN}`;
  await browserApiFetch("/api/v1/session");
  expect(new Headers(fetcher.mock.calls[1]![1].headers).has("X-BlueFire-Session")).toBe(false);
});

it.each([{}, { session: "invalid" }, { session: TOKEN, extra: "untrusted" }, [TOKEN]])("rejects malformed exchange responses without retaining authority", async payload => {
  const { exchangeBrowserCapability } = await import("../src/lib/browser-session");
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify(payload))));
  await expect(exchangeBrowserCapability("C".repeat(64))).rejects.toThrow("The local session response is invalid.");
  expect(sessionStorage.getItem(KEY)).toBeNull();
});

it("retains a memory-only session when browser storage is disabled", async () => {
  const { browserApiFetch, exchangeBrowserCapability } = await import("../src/lib/browser-session");
  vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new DOMException("Storage unavailable", "SecurityError"); });
  const fetcher = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({ session: TOKEN })))
    .mockResolvedValueOnce(new Response(null, { status: 204 }));
  vi.stubGlobal("fetch", fetcher);
  await exchangeBrowserCapability("C".repeat(64)); await browserApiFetch("/api/v1/session");
  expect(new Headers(fetcher.mock.calls[1]![1].headers).get("X-BlueFire-Session")).toBe(TOKEN);
  expect(sessionStorage.getItem(KEY)).toBeNull();
});

it("does not replace a fresh memory-only session with stale stored authority when storage writes fail", async () => {
  sessionStorage.setItem(KEY, "O".repeat(64));
  const { browserApiFetch, exchangeBrowserCapability } = await import("../src/lib/browser-session");
  vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new DOMException("Storage full", "QuotaExceededError"); });
  const fetcher = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({ session: TOKEN })))
    .mockResolvedValueOnce(new Response(null, { status: 204 }));
  vi.stubGlobal("fetch", fetcher);
  await exchangeBrowserCapability("C".repeat(64)); await browserApiFetch("/api/v1/session");
  expect(new Headers(fetcher.mock.calls[1]![1].headers).get("X-BlueFire-Session")).toBe(TOKEN);
  expect(sessionStorage.getItem(KEY)).toBe("O".repeat(64));
});

it("bounds an unresponsive exchange and does not retain failed authority", async () => {
  vi.useFakeTimers();
  try {
    const { exchangeBrowserCapability } = await import("../src/lib/browser-session");
    vi.stubGlobal("fetch", vi.fn((_path, options: RequestInit) => new Promise<Response>((_resolve, reject) => {
      options.signal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")), { once: true });
    })));
    const pending = expect(exchangeBrowserCapability("C".repeat(64))).rejects.toMatchObject({ name: "AbortError" });
    await vi.advanceTimersByTimeAsync(15_001); await pending;
    expect(sessionStorage.getItem(KEY)).toBeNull();
  } finally { vi.useRealTimers(); }
});
