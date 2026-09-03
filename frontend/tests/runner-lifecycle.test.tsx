import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { demoCatalog } from "../src/lib/demo";
import { RunnersPage } from "../src/pages/CatalogPages";
import type { RunnerLifecycleStatus } from "../src/types";

function json(value: unknown) {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

describe("managed runner lifecycle", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("offers a verified upgrade only after the managed host is stopped", async () => {
    const stopped: RunnerLifecycleStatus = {
      schema_version: "bluefire.runner-lifecycle-status.v1",
      state: "stopped",
      runner_id: "bluefire-rust-runner.v1",
      profile_id: "sandbox-execute.v1",
      loopback_only: true,
      enrollment: "active",
      process: "absent",
      runner: null,
      health: null,
    };
    const upgraded: RunnerLifecycleStatus = {
      ...stopped,
    };
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path.endsWith("/catalog")) return json(demoCatalog);
      if (path.endsWith("/resources/runners")) {
        return json({ schema_version: "bluefire.resource-list.v1", kind: "runners", resources: [] });
      }
      if (path.endsWith("/resources/runner-profiles")) {
        return json({ schema_version: "bluefire.resource-list.v1", kind: "runner-profiles", resources: [] });
      }
      if (path.endsWith("/runner/bootstrap") && init?.method === "POST") return json(upgraded);
      if (path.endsWith("/runner")) return json(stopped);
      throw new Error(`Unhandled test request: ${path}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
    const user = userEvent.setup();

    render(<QueryClientProvider client={client}><RunnersPage /></QueryClientProvider>);

    await user.click(await screen.findByRole("button", { name: /Upgrade & re-enroll/i }));
    expect(screen.getByRole("heading", { name: "Upgrade managed runner" })).toBeVisible();
    expect(fetchMock.mock.calls.some(([input]) => String(input).endsWith("/runner/bootstrap"))).toBe(false);

    await user.click(screen.getByRole("button", { name: /Confirm verified upgrade/i }));

    await waitFor(() => {
      expect(fetchMock.mock.calls.some(([input]) => String(input).endsWith("/runner/bootstrap"))).toBe(true);
    });
    const upgradeCall = fetchMock.mock.calls.find(([input]) => String(input).endsWith("/runner/bootstrap"));
    expect(upgradeCall?.[1]?.method).toBe("POST");
    expect(JSON.parse(String(upgradeCall?.[1]?.body))).toEqual({
      profile_id: "sandbox-execute.v1",
      allow_upgrade: true,
    });
  });

  it("uses stop to reconcile a stale process record instead of attempting bootstrap", async () => {
    const stale: RunnerLifecycleStatus = {
      schema_version: "bluefire.runner-lifecycle-status.v1",
      state: "stale",
      runner_id: "bluefire-rust-runner.v1",
      profile_id: "sandbox-execute.v1",
      loopback_only: true,
      enrollment: "active",
      process: "stale",
      runner: null,
      health: null,
    };
    const stopped: RunnerLifecycleStatus = { ...stale, state: "stopped", process: "absent" };
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path.endsWith("/catalog")) return json(demoCatalog);
      if (path.endsWith("/resources/runners")) {
        return json({ schema_version: "bluefire.resource-list.v1", kind: "runners", resources: [] });
      }
      if (path.endsWith("/resources/runner-profiles")) {
        return json({ schema_version: "bluefire.resource-list.v1", kind: "runner-profiles", resources: [] });
      }
      if (path.endsWith("/runner/stop") && init?.method === "POST") return json(stopped);
      if (path.endsWith("/runner")) return json(stale);
      throw new Error(`Unhandled test request: ${path}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
    const user = userEvent.setup();

    render(<QueryClientProvider client={client}><RunnersPage /></QueryClientProvider>);

    expect(await screen.findByRole("button", { name: /Reconcile stale host/i })).toBeVisible();
    expect(screen.queryByRole("button", { name: /Upgrade & re-enroll/i })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Reconcile stale host/i }));

    await waitFor(() => {
      expect(fetchMock.mock.calls.some(([input]) => String(input).endsWith("/runner/stop"))).toBe(true);
    });
    const stopCall = fetchMock.mock.calls.find(([input]) => String(input).endsWith("/runner/stop"));
    expect(stopCall?.[1]?.method).toBe("POST");
    expect(JSON.parse(String(stopCall?.[1]?.body))).toEqual({ profile_id: "sandbox-execute.v1" });
    expect(fetchMock.mock.calls.some(([input]) => String(input).endsWith("/runner/bootstrap"))).toBe(false);
  });
});
