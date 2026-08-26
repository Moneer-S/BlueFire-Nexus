import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { demoCatalog } from "../src/lib/demo";
import { api } from "../src/lib/api";
import { ActionPackagesPage } from "../src/pages/ActionPackages";
import type { ActionPackageInstallation, ActionPackageInventory } from "../src/types";

const packageDigest = `sha256:${"1".repeat(64)}`;
const contentDigest = `sha256:${"2".repeat(64)}`;
const catalogDigest = `sha256:${"3".repeat(64)}`;

function packageRecord(overrides: Partial<ActionPackageInstallation> = {}): ActionPackageInstallation {
  return {
    schema_version: "bluefire.action-package-installation.v1",
    package_id: "bluefire.publisher.endpoint-pack",
    version: "2.0.0",
    status: "installed",
    package_digest: packageDigest,
    content_digest: contentDigest,
    publisher_id: "bluefire.publisher",
    key_id: "release-2026",
    signer_fingerprint: `sha256:${"4".repeat(64)}`,
    manifest: {
      package_id: "bluefire.publisher.endpoint-pack",
      version: "2.0.0",
      compatibility: { minimum_bluefire_version: "0.1.0", maximum_bluefire_version_exclusive: "1.0.0" },
      license: { spdx_id: "MIT", notice: "Publisher notice" },
      provenance: { publisher_id: "bluefire.publisher", source: "Reviewed release", reference: "https://packages.example.invalid/release-2", revision: "commit-abc" },
      platforms: ["windows"],
      capabilities: ["filesystem.read"],
      safety_tiers: ["safe"],
      behavior_ids: ["publisher.endpoint.observe.v1"],
      action_ids: ["publisher.endpoint.observe.v1"],
    },
    installed_by: "operator-install",
    installed_at: "2026-08-26T12:00:00Z",
    installed_head: true,
    active: false,
    active_version: "1.0.0",
    active_generation: 6,
    catalog_generation: 7,
    catalog_digest: catalogDigest,
    trust: {
      state: "trusted",
      source: "local_operator",
      publisher_id: "bluefire.publisher",
      key_id: "release-2026",
      key_fingerprint: `sha256:${"4".repeat(64)}`,
      trusted_by: "operator-trust",
      trusted_at: "2026-08-25T12:00:00Z",
      event_sequence: 1,
      updated_at: "2026-08-25T12:00:00Z",
      provenance: { source: "Publisher security page", reference: "https://packages.example.invalid/key", revision: "2026-08" },
    },
    activation: null,
    tombstone: null,
    ...overrides,
  };
}

function inventory(item = packageRecord()): ActionPackageInventory {
  return {
    schema_version: "bluefire.action-package-inventory.v1",
    packages: [item],
    publishers: [{
      schema_version: "bluefire.action-package-publisher-trust.v1",
      publisher_id: "bluefire.publisher",
      key_id: "release-2026",
      public_key_b64u: "public-key-value",
      key_fingerprint: `sha256:${"4".repeat(64)}`,
      provenance: { source: "Publisher security page", reference: "https://packages.example.invalid/key", revision: "2026-08" },
      trust_state: "trusted",
      trust_source: "local_operator",
      trust_event_sequence: 1,
      trust_updated_at: "2026-08-25T12:00:00Z",
      trusted_by: "operator-trust",
      trusted_at: "2026-08-25T12:00:00Z",
    }],
    catalog: { schema_version: "bluefire.action-catalog-authority.v1", generation: 7, catalog_digest: catalogDigest, authority_digest: `sha256:${"5".repeat(64)}`, packages: [] },
    activation_events: [{ generation: 7, event_id: "event-7", event_type: "deactivated", cause: "operator", package_id: "bluefire.publisher.endpoint-pack", actor: "operator-a", reason: "Upgrade prepared", created_at: "2026-08-26T12:01:00Z" }],
    execution_boundary: "signed-reviewed-opcodes-only",
  };
}

function json(value: unknown) {
  return new Response(JSON.stringify(value), { status: 200, headers: { "Content-Type": "application/json" } });
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><ActionPackagesPage /></QueryClientProvider>);
}

describe("action package management", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("shows the honest execution boundary and verifies an upgrade against an explicit runner profile", async () => {
    const current = inventory();
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path.endsWith("/action-packages") && init?.method === "POST") return json({ schema_version: "bluefire.action-package-activation.v1", operation: "upgrade", package: { ...current.packages[0], active: true, status: "active" }, catalog: current.catalog });
      if (path.endsWith("/action-packages")) return json(current);
      if (path.endsWith("/catalog")) return json(demoCatalog);
      if (path.endsWith("/activate")) return json({ schema_version: "bluefire.action-package-activation.v1", operation: "upgrade", package: { ...current.packages[0], active: true, status: "active" }, catalog: current.catalog });
      throw new Error(`Unhandled request: ${path}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderPage();

    expect(await screen.findByRole("heading", { name: "Action packages" })).toBeVisible();
    expect(screen.getByText(/do not load executable code/i)).toBeVisible();
    expect(screen.getAllByText(catalogDigest).length).toBeGreaterThan(0);
    expect(screen.getByText("windows")).toBeVisible();
    expect(screen.getByText("filesystem.read")).toBeVisible();

    await user.click(screen.getByRole("button", { name: "Upgrade to 2.0.0" }));
    expect(screen.getByRole("heading", { name: "Upgrade to 2.0.0" })).toBeVisible();
    expect(screen.getByLabelText("Exact lifecycle identity")).toHaveTextContent(packageDigest);
    fireEvent.change(screen.getByLabelText("Authenticated Execute runner profile"), { target: { value: "sandbox-execute.v1" } });
    fireEvent.change(screen.getByLabelText("Operator"), { target: { value: "operator-upgrade" } });
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "Publish the reviewed endpoint package upgrade" } });
    fireEvent.click(screen.getByRole("checkbox", { name: /confirm this exact package version/i }));
    fireEvent.click(screen.getByRole("button", { name: "Verify & publish generation" }));

    await waitFor(() => expect(fetchMock.mock.calls.some(([input]) => String(input).endsWith("/activate"))).toBe(true));
    const activation = fetchMock.mock.calls.find(([input]) => String(input).endsWith("/activate"));
    expect(String(activation?.[0])).toBe("/api/v1/action-packages/bluefire.publisher.endpoint-pack/versions/2.0.0/activate");
    expect(JSON.parse(String(activation?.[1]?.body))).toEqual({
      runner_profile_id: "sandbox-execute.v1",
      activated_by: "operator-upgrade",
      reason: "Publish the reviewed endpoint package upgrade",
    });
  });

  it("binds deactivation to the exact immutable package and current catalog snapshot", async () => {
    const item = packageRecord({ status: "active", active: true, active_version: "2.0.0", active_generation: 7 });
    const current = inventory(item);
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path.endsWith("/action-packages")) return json(current);
      if (path.endsWith("/catalog")) return json(demoCatalog);
      if (path.endsWith("/deactivate") && init?.method === "POST") return json({ schema_version: "bluefire.action-package-deactivation.v1", package: { ...item, active: false }, catalog: current.catalog });
      throw new Error(`Unhandled request: ${path}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderPage();

    await user.click(await screen.findByRole("button", { name: "Deactivate 2.0.0" }));
    fireEvent.change(screen.getByLabelText("Operator"), { target: { value: "operator-deactivate" } });
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "Pause the package during publisher review" } });
    fireEvent.click(screen.getByRole("checkbox", { name: /confirm this exact package version/i }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm deactivation" }));

    await waitFor(() => expect(fetchMock.mock.calls.some(([input]) => String(input).endsWith("/deactivate"))).toBe(true));
    const request = fetchMock.mock.calls.find(([input]) => String(input).endsWith("/deactivate"));
    expect(JSON.parse(String(request?.[1]?.body))).toEqual({
      package_digest: packageDigest,
      expected_catalog_generation: 7,
      expected_catalog_digest: catalogDigest,
      deactivated_by: "operator-deactivate",
      reason: "Pause the package during publisher review",
    });
  });

  it("imports a file-backed signed envelope without exposing a raw JSON editor", async () => {
    const current = inventory();
    const envelope = { schema_version: "bluefire.action-package-envelope.v1", manifest: current.packages[0]!.manifest, payload: {}, integrity: { algorithm: "sha256", content_digest: contentDigest }, signature: { algorithm: "ed25519", key_id: "release-2026", value: "signature" } };
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path.endsWith("/action-packages") && init?.method === "POST") return json({ schema_version: "bluefire.action-package-install.v1", package: current.packages[0], catalog_changed: false, activation_required: true });
      if (path.endsWith("/action-packages")) return json({ ...current, packages: [] });
      if (path.endsWith("/catalog")) return json(demoCatalog);
      throw new Error(`Unhandled request: ${path}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderPage();

    await user.click(await screen.findByRole("button", { name: "Import signed package" }));
    expect(screen.queryByRole("textbox", { name: /raw/i })).not.toBeInTheDocument();
    const file = new File([JSON.stringify(envelope)], "endpoint-pack.json", { type: "application/json" });
    Object.defineProperty(file, "text", { value: vi.fn(async () => JSON.stringify(envelope)) });
    await user.upload(screen.getByLabelText("Signed envelope file"), file);
    expect(await screen.findByText("Envelope ready for independent verification")).toBeVisible();
    fireEvent.change(screen.getByLabelText("Installed by"), { target: { value: "operator-import" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify & install inactive" }));

    await waitFor(() => expect(fetchMock.mock.calls.filter(([input, init]) => String(input).endsWith("/action-packages") && init?.method === "POST")).toHaveLength(1));
    const request = fetchMock.mock.calls.find(([input, init]) => String(input).endsWith("/action-packages") && init?.method === "POST");
    expect(JSON.parse(String(request?.[1]?.body))).toEqual({ envelope, installed_by: "operator-import" });
  });

  it("refuses an oversized signed envelope before reading it into browser memory", async () => {
    const current = inventory();
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path.endsWith("/action-packages")) return json({ ...current, packages: [] });
      if (path.endsWith("/catalog")) return json(demoCatalog);
      throw new Error(`Unhandled request: ${path}`);
    }));
    const user = userEvent.setup();
    renderPage();

    await user.click(await screen.findByRole("button", { name: "Import signed package" }));
    const file = new File([new Uint8Array(1_048_577)], "oversized.json", { type: "application/json" });
    const read = vi.fn(async () => "{}");
    Object.defineProperty(file, "text", { value: read });
    await user.upload(screen.getByLabelText("Signed envelope file"), file);

    expect(await screen.findByText("The signed envelope exceeds the 1 MiB browser/API limit.")).toBeVisible();
    expect(read).not.toHaveBeenCalled();
  });

  it("uses exact publisher and package lifecycle API routes", async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => {
      void _input; void _init;
      return json({});
    });
    vi.stubGlobal("fetch", fetchMock);
    const identity = { package_digest: packageDigest, expected_catalog_generation: 7, expected_catalog_digest: catalogDigest };

    await api.trustActionPackagePublisher({ publisher_id: "publisher/a", key_id: "key 1", public_key: "public", provenance: { source: "review" }, trusted_by: "operator" });
    await api.transitionActionPackagePublisher("publisher/a", "key 1", "suspend", "operator", "investigate");
    await api.transitionActionPackagePublisher("publisher/a", "key 1", "revoke", "operator", "compromised");
    await api.removeActionPackage("publisher/package", "2.0.0+build.1", identity, "operator", "retire");

    expect(fetchMock.mock.calls.map(([input]) => String(input))).toEqual([
      "/api/v1/action-package-publishers",
      "/api/v1/action-package-publishers/publisher%2Fa/keys/key%201/suspend",
      "/api/v1/action-package-publishers/publisher%2Fa/keys/key%201/revoke",
      "/api/v1/action-packages/publisher%2Fpackage/versions/2.0.0%2Bbuild.1/remove",
    ]);
    expect(JSON.parse(String(fetchMock.mock.calls[3]?.[1]?.body))).toEqual({
      ...identity,
      removed_by: "operator",
      reason: "retire",
    });
  });
});
