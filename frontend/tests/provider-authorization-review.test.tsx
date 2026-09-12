import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ProviderSetup } from "../src/components/ProviderSetup";
import { api } from "../src/lib/api";
import type { AILiveAuthorizationList, ManagedResource, PublicAIProviderConfig } from "../src/types";
import { authorization, provider, snapshot } from "./provider-authorization-fixtures";

vi.mock("../src/lib/api", () => ({ api: { resources: vi.fn(), checkAIProvider: vi.fn(), saveResource: vi.fn(), activateResource: vi.fn(), deactivateResource: vi.fn(), aiAuthorizations: vi.fn(), authorizeAI: vi.fn(), revokeAIAuthorization: vi.fn() } }));
const consent = /I authorize the selected model work/;
const liveButton = () => screen.getByRole("button", { name: "Send live connection test" });
const authorizeButton = () => screen.getByRole("button", { name: "Authorize reviewed model usage" });

async function mount(config: PublicAIProviderConfig = provider, initial = snapshot(), active = false) {
  let rows: AILiveAuthorizationList = structuredClone(initial);
  let resource: ManagedResource = { kind: "model_provider", id: config.id, status: active ? "active" : "draft", document: { ...config }, digest: "test-digest", created_at: "", updated_at: "" };
  vi.mocked(api.resources).mockImplementation(async () => ({ schema_version: "bluefire.resource-list.v1", kind: "model_provider", resources: [structuredClone(resource)] }));
  vi.mocked(api.aiAuthorizations).mockImplementation(async () => structuredClone(rows));
  vi.mocked(api.saveResource).mockImplementation(async (_kind, id, document) => { resource = { ...resource, id, document, status: "draft" }; return { schema_version: "bluefire.resource.v1", resource: structuredClone(resource) }; });
  vi.mocked(api.activateResource).mockImplementation(async () => { resource.status = "active"; return { schema_version: "bluefire.resource.v1", resource: structuredClone(resource) }; });
  vi.mocked(api.authorizeAI).mockImplementation(async body => {
    const row = authorization({ provider: body.provider, purposes: body.purposes, limits: body.limits, approved_by: body.approved_by, local_endpoint_authorized: body.local_endpoint_authorized, context: { kind: rows.context.kind, binding_digest: rows.context.binding_digest! } });
    rows = { ...rows, authorizations: [row] }; return { authorization: row };
  });
  vi.mocked(api.revokeAIAuthorization).mockImplementation(async id => { const row = { ...rows.authorizations.find(item => item.authorization_id === id)!, status: "revoked" as const }; rows = { ...rows, authorizations: [row] }; return { authorization: row }; });
  const user = userEvent.setup();
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}><ProviderSetup/></QueryClientProvider>);
  await screen.findByRole("heading", { name: "Review model data and usage" });
  if (initial.context.kind !== "broker") await user.click(await screen.findByRole("button", { name: `Edit ${config.id}` }));
  return user;
}
async function review(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole("checkbox", { name: "Test the connection with synthetic data" }));
  await user.type(screen.getByLabelText("Operator identity for model usage"), "Lab owner");
  await user.click(screen.getByRole("checkbox", { name: consent }));
}

describe("in-product data and usage authorization", () => {
  beforeEach(() => { vi.resetAllMocks(); });
  it("uses one explicit final action for the exact edited connection and bounded purposes, without a model call", async () => {
    const user = await mount();
    expect(api.authorizeAI).not.toHaveBeenCalled(); expect(api.checkAIProvider).not.toHaveBeenCalled(); expect(liveButton()).toBeDisabled();
    await user.clear(screen.getByLabelText("Model ID", { exact: false })); await user.type(screen.getByLabelText("Model ID", { exact: false }), "reviewed-model");
    await review(user);
    await user.click(screen.getByRole("checkbox", { name: "Choose reviewed methods during a run" }));
    expect(screen.getByRole("checkbox", { name: consent })).not.toBeChecked();
    await user.click(screen.getByRole("checkbox", { name: consent }));
    await user.click(authorizeButton());
    await screen.findByText(/Authorization saved. No model request was sent/);
    expect(api.authorizeAI).toHaveBeenCalledWith({ provider: { ...provider, model: "reviewed-model" }, purposes: ["bluefire_connection_check", "bluefire_ai_proposal"], data_scope: "reviewed_lab_context", limits: { max_requests: 12, max_request_bytes: 4194304, max_reserved_output_tokens: 16384 }, expires_in_seconds: 900, approved_by: "Lab owner", usage_authorized: true, local_endpoint_authorized: false });
    expect(vi.mocked(api.saveResource).mock.invocationCallOrder[0]).toBeLessThan(vi.mocked(api.activateResource).mock.invocationCallOrder[0]!);
    expect(vi.mocked(api.activateResource).mock.invocationCallOrder[0]).toBeLessThan(vi.mocked(api.authorizeAI).mock.invocationCallOrder[0]!);
    expect(api.checkAIProvider).not.toHaveBeenCalled();
    await waitFor(() => expect(liveButton()).toBeEnabled());
    expect(screen.getByRole("checkbox", { name: consent })).not.toBeChecked();
  });
  it("requires a new review when limits or connection change", async () => {
    const user = await mount(provider, snapshot([authorization()]));
    await review(user); expect(authorizeButton()).toBeEnabled();
    await user.clear(screen.getByLabelText("Total request attempts", { exact: false })); await user.type(screen.getByLabelText("Total request attempts", { exact: false }), "5");
    expect(authorizeButton()).toBeDisabled(); expect(screen.getByRole("checkbox", { name: consent })).not.toBeChecked();
    await user.click(screen.getByRole("checkbox", { name: consent }));
    await user.type(screen.getByLabelText("Secret environment reference", { exact: false }), "_CHANGED");
    expect(liveButton()).toBeDisabled(); expect(screen.getByRole("checkbox", { name: consent })).not.toBeChecked();
    expect(screen.getByText(/covers a different configuration/)).toBeVisible();
    expect(api.authorizeAI).not.toHaveBeenCalled();
  });
  it("locks an enrolled broker connection and grants only that exact configuration", async () => {
    const initial = snapshot(); initial.context = { ...initial.context, kind: "broker", provider, expires_at_ms: Date.now() + 900000 };
    const user = await mount(provider, initial);
    for (const label of ["Provider ID", "API style", "Model ID", "Request endpoint", "Secret environment reference"]) expect(screen.getByLabelText(label, { exact: false })).toBeDisabled();
    expect(screen.queryByRole("button", { name: "Save secret-free draft" })).not.toBeInTheDocument();
    await review(user); await user.click(authorizeButton()); await waitFor(() => expect(api.authorizeAI).toHaveBeenCalledWith(expect.objectContaining({ provider })));
    expect(api.saveResource).not.toHaveBeenCalled(); expect(api.activateResource).not.toHaveBeenCalled(); expect(api.checkAIProvider).not.toHaveBeenCalled();
  });
  it("requires explicit loopback permission and does not infer it from the endpoint", async () => {
    const local = { ...provider, endpoint: "http://127.0.0.1:8080/v1/chat/completions", api_key: null };
    const user = await mount(local); await review(user); expect(authorizeButton()).toBeDisabled();
    await user.click(screen.getByRole("checkbox", { name: "I authorize requests to this loopback endpoint." }));
    expect(authorizeButton()).toBeDisabled(); await user.click(screen.getByRole("checkbox", { name: consent })); await user.click(authorizeButton());
    await waitFor(() => expect(api.authorizeAI).toHaveBeenCalledWith(expect.objectContaining({ provider: local, local_endpoint_authorized: true })));
  });
  it.each(["expired", "revoked", "context_unavailable"] as const)("shows %s authorization honestly without enabling the live test", async status => {
    await mount(provider, snapshot([authorization({ status, usage: { requests: 2, request_bytes: 10, reserved_output_tokens: 800 } })]));
    expect(liveButton()).toBeDisabled(); expect(screen.getByText(/Remaining counters do not renew its authority/)).toBeVisible();
    expect(api.authorizeAI).not.toHaveBeenCalled(); expect(api.checkAIProvider).not.toHaveBeenCalled();
  });
  it("keeps offline configuration checks independent of consent and refuses a missing connection purpose", async () => {
    const user = await mount(provider, snapshot([authorization({ purposes: ["bluefire_ai_proposal"] })]));
    expect(liveButton()).toBeDisabled(); await user.click(screen.getByRole("button", { name: "Check configuration" }));
    expect(api.checkAIProvider).toHaveBeenCalledWith(provider, false); expect(api.authorizeAI).not.toHaveBeenCalled();
  });
  it("revokes the exact saved authorization and refreshes live-test availability", async () => {
    const row = authorization(); const user = await mount(provider, snapshot([row])); expect(liveButton()).toBeEnabled();
    await user.click(screen.getByRole("button", { name: "Revoke model usage for my-model" }));
    await screen.findByText("Revoked");
    await waitFor(() => expect(liveButton()).toBeDisabled()); expect(api.revokeAIAuthorization).toHaveBeenCalledWith(row.authorization_id);
    expect(api.checkAIProvider).not.toHaveBeenCalled(); expect(api.authorizeAI).not.toHaveBeenCalled();
  });
  it("clears a connection-test result and consent when the service context changes", async () => {
    const initial = snapshot([authorization()]); const user = await mount(provider, initial); await review(user);
    vi.mocked(api.aiAuthorizations).mockResolvedValue({ ...initial, context: { ...initial.context, binding_digest: `sha256:${"d".repeat(64)}` } });
    vi.mocked(api.checkAIProvider).mockResolvedValue({ schema_version: "bluefire.ai-provider-check.v1", provider_id: provider.id, api_style: provider.kind, model: provider.model, credential_state: "ready", connectivity: "passed", structured_output: "passed", attempts: 1, used_fallback: false, code: "probe_passed", message: "Synthetic connection succeeded." });
    await user.click(liveButton());
    await waitFor(() => expect(api.aiAuthorizations).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(liveButton()).toBeDisabled());
    expect(screen.queryByText("Live structured-output test passed")).not.toBeInTheDocument();
    expect(screen.getByRole("checkbox", { name: consent })).not.toBeChecked();
  });
  it("leaves active configuration replacement to explicit deactivation", async () => {
    const user = await mount(provider, snapshot(), true);
    await user.type(screen.getByLabelText("Model ID", { exact: false }), "-changed"); await review(user);
    expect(authorizeButton()).toBeDisabled(); expect(screen.getByRole("button", { name: "Save secret-free draft" })).toBeDisabled();
    expect(api.activateResource).not.toHaveBeenCalled(); expect(api.authorizeAI).not.toHaveBeenCalled();
  });
  it("requires visible repair of broader data policy and rejects invalid fields before saving", async () => {
    const unsafe = { ...provider, redaction: { ...provider.redaction, enabled: false, include_evidence_content: true } };
    const user = await mount(unsafe); await review(user); expect(authorizeButton()).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Use required data protection" }));
    expect(screen.getByRole("checkbox", { name: consent })).not.toBeChecked();
    await user.type(screen.getByLabelText("Secret environment reference", { exact: false }), " not-a-variable");
    expect(screen.getByRole("button", { name: "Save secret-free draft" })).toBeDisabled(); expect(screen.getByRole("button", { name: "Check configuration" })).toBeDisabled();
    expect(api.saveResource).not.toHaveBeenCalled(); expect(api.authorizeAI).not.toHaveBeenCalled();
  });
});
