import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { useState } from "react";
import { HashRouter, Link, Navigate, Route, Routes } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { useBrowserSessionRoute, watchBrowserSession } from "../src/lib/browser-startup";
let stop: (() => void) | undefined;
afterEach(() => { stop?.(); stop = undefined; vi.unstubAllGlobals(); });
function RouteMemory({ remember }: { remember: (hash: string) => void }) { useBrowserSessionRoute(remember); return null; }
function Draft() {
  const [draft, setDraft] = useState("Original draft");
  return <label>Unsubmitted detector draft<input value={draft} onChange={event => setDraft(event.target.value)}/></label>;
}
it("handles browser popstate before HashRouter and keeps the mounted draft during reconnect", async () => {
  window.history.replaceState(null, "", "#/runs");
  const fetcher = vi.fn(async (_url: RequestInfo | URL, options?: RequestInit) => new Response(null, { status: options?.method === "POST" ? 204 : 401 }));
  vi.stubGlobal("fetch", fetcher);
  const connected = vi.fn(), unavailable = vi.fn();
  const watcher = watchBrowserSession({ connected, unavailable }); stop = watcher.dispose;
  render(<HashRouter><RouteMemory remember={watcher.rememberRoute}/><Routes><Route path="/runs" element={<Link to="/detection-lab">Open detector</Link>}/><Route path="/detection-lab" element={<Draft/>}/><Route path="/" element={<p>Overview</p>}/><Route path="*" element={<Navigate to="/" replace/>}/></Routes></HashRouter>);
  await waitFor(() => expect(unavailable).toHaveBeenCalledOnce());
  fireEvent.click(screen.getByRole("link", { name: "Open detector" }));
  const input = screen.getByRole("textbox", { name: "Unsubmitted detector draft" });
  fireEvent.change(input, { target: { value: "New unsaved source" } });
  await act(async () => {
    const oldURL = window.location.href;
    window.history.pushState(null, "", `#bluefire-session=${"H".repeat(64)}`);
    const newURL = window.location.href;
    window.dispatchEvent(new PopStateEvent("popstate", { state: window.history.state }));
    window.dispatchEvent(new HashChangeEvent("hashchange", { oldURL, newURL }));
  });
  await waitFor(() => expect(connected).toHaveBeenCalledOnce());
  expect(window.location.hash).toBe("#/detection-lab");
  expect(screen.queryByText("Overview")).not.toBeInTheDocument();
  expect(screen.getByRole("textbox", { name: "Unsubmitted detector draft" })).toBe(input);
  expect(input).toHaveValue("New unsaved source");
  expect(fetcher.mock.calls.map(([url, options]) => [url, options?.method])).toEqual([["/api/v1/session", "GET"], ["/api/v1/session", "POST"]]);
});
