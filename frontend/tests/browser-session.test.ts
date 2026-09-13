import { describe, expect, it, vi } from "vitest";
import {
  ApiError,
  BROWSER_SESSION_RELAUNCH_MESSAGE,
  establishBrowserSession,
} from "../src/lib/api";

describe("browser session bootstrap", () => {
  it("exchanges the exact URL fragment after clearing it and never sends it in the URL or body", async () => {
    const capability = "A".repeat(64);
    window.location.hash = `#bluefire-session=${capability}`;
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => {
      void _input;
      void _init;
      expect(window.location.hash).toBe("");
      return new Response(null, { status: 204 });
    });
    vi.stubGlobal("fetch", fetchMock);

    await establishBrowserSession();

    expect(fetchMock).toHaveBeenCalledOnce();
    const [input, init] = fetchMock.mock.calls[0]!;
    expect(String(input)).toBe("/api/v1/session");
    expect(String(input)).not.toContain(capability);
    expect(init?.method).toBe("POST");
    expect(init?.body).toBeUndefined();
    expect(init?.credentials).toBe("same-origin");
    expect(init?.cache).toBe("no-store");
    expect(init?.referrerPolicy).toBe("no-referrer");
    expect(init?.headers).toEqual({
      Accept: "application/json",
      "X-BlueFire-Browser-Bootstrap": capability,
    });
  });

  it("reuses an existing HttpOnly session without consuming normal router fragments", async () => {
    window.location.hash = "#/runs";
    const fetchMock = vi.fn(async () => new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetchMock);

    await establishBrowserSession();

    expect(window.location.hash).toBe("#/runs");
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/session",
      expect.objectContaining({ method: "GET", credentials: "same-origin" }),
    );
  });

  it("reuses an existing cookie after a one-use launch fragment is replayed", async () => {
    const capability = "R".repeat(64);
    window.location.hash = `#bluefire-session=${capability}`;
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response(null, { status: 401 }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetchMock);

    await establishBrowserSession();

    expect(window.location.hash).toBe("");
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls.map(([, init]) => init?.method)).toEqual(["POST", "GET"]);
    expect(fetchMock.mock.calls[1]?.[1]?.headers).toEqual({ Accept: "application/json" });
  });

  it("clears malformed bootstrap fragments without sending them", async () => {
    const malformed = `#bluefire-session=${"A".repeat(64)}&duplicate=value`;
    window.location.hash = malformed;
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(establishBrowserSession()).rejects.toMatchObject({
      code: "browser_session_unavailable",
      message: BROWSER_SESSION_RELAUNCH_MESSAGE,
    });

    expect(window.location.hash).toBe("");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("returns only the human-safe relaunch message when exchange fails", async () => {
    const capability = "Z".repeat(64);
    window.location.hash = `#bluefire-session=${capability}`;
    vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 401 })));

    let failure: unknown;
    try {
      await establishBrowserSession();
    } catch (error) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(ApiError);
    expect((failure as ApiError).message).toBe(BROWSER_SESSION_RELAUNCH_MESSAGE);
    expect((failure as ApiError).message).not.toContain(capability);
    expect(window.location.hash).toBe("");
  });
});
