import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ProviderSetup } from "../src/components/ProviderSetup";
import { api } from "../src/lib/api";
import { downloadArtifact } from "../src/lib/download";
import { publicProvider } from "../src/lib/provider-authorization";
import type { AIProviderCheck } from "../src/types";
import { authorization, provider, snapshot } from "./provider-authorization-fixtures";

vi.mock("../src/lib/api", async importOriginal => {
  const actual = await importOriginal<typeof import("../src/lib/api")>();
  return { ...actual, api: { resources: vi.fn(), checkAIProvider: vi.fn(), saveResource: vi.fn(), activateResource: vi.fn(), deactivateResource: vi.fn(), aiAuthorizations: vi.fn(), authorizeAI: vi.fn(), revokeAIAuthorization: vi.fn() } };
});
vi.mock("../src/lib/download", () => ({ downloadArtifact: vi.fn() }));
const checked: AIProviderCheck = { schema_version: "bluefire.ai-provider-check.v1", provider_id: "provider.local.v1", api_style: "chat_completions", model: "my-model", credential_state: "ready", connectivity: "not_tested", structured_output: "not_tested", attempts: 0, used_fallback: false, code: "configuration_ready", message: "Configuration checked; no network request was made." };
function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><ProviderSetup/></QueryClientProvider>);
  return client;
}
function blobText(blob: Blob): Promise<string> { return new Promise((resolve, reject) => { const reader = new FileReader(); reader.onload = () => resolve(String(reader.result)); reader.onerror = () => reject(reader.error); reader.readAsText(blob); }); }

describe("explicit provider setup", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(api.resources).mockResolvedValue({ schema_version: "bluefire.resource-list.v1", kind: "model_provider", resources: [] });
    vi.mocked(api.checkAIProvider).mockResolvedValue(checked);
    vi.mocked(api.aiAuthorizations).mockResolvedValue(snapshot());
  });
  it("never probes on mount and separates readiness from opt-in live testing", async () => {
    vi.mocked(api.aiAuthorizations).mockResolvedValue(snapshot([authorization()]));
    const user = userEvent.setup(); mount();
    await waitFor(() => expect(screen.getByLabelText("API style")).toBeEnabled());
    expect(screen.getByLabelText("Provider ID", { exact: false })).not.toBeVisible();
    await user.selectOptions(screen.getByLabelText("API style"), "chat_completions");
    // Enter complete setup values through the same clipboard events an operator uses.
    await user.click(screen.getByLabelText("Model ID", { exact: false }));
    await user.paste("my-model");
    await user.click(screen.getByLabelText("Request endpoint", { exact: false }));
    await user.paste("https://model.example/v1/chat/completions");
    await user.click(screen.getByLabelText("Secret environment reference", { exact: false }));
    await user.paste("MODEL_API_KEY");
    expect(api.checkAIProvider).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Check configuration" }));
    await screen.findByText("Configuration checked · connection untested");
    expect(api.checkAIProvider).toHaveBeenLastCalledWith(expect.objectContaining({ kind: "chat_completions", model: "my-model", endpoint: "https://model.example/v1/chat/completions", api_key: { env: "MODEL_API_KEY" } }), false);
    expect(screen.queryByText("Live structured-output test passed")).not.toBeInTheDocument();
    vi.mocked(api.checkAIProvider).mockResolvedValue({ ...checked, code: "probe_passed", connectivity: "passed", structured_output: "passed", attempts: 1 });
    await user.click(screen.getByRole("button", { name: "Send live connection test" }));
    await screen.findByText("Live structured-output test passed");
    expect(api.checkAIProvider).toHaveBeenLastCalledWith(expect.anything(), true);
    await user.type(screen.getByLabelText("Model ID", { exact: false }), "-changed");
    expect(screen.queryByText("Live structured-output test passed")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Send live connection test" })).toBeDisabled();
  });
  it("edits saved endpoint and environment reference while preserving request/redaction settings", async () => {
    const doc = { id: "provider.local.v1", kind: "openai_responses", model: "custom-model", endpoint: "http://localhost:8080/custom/responses", api_key: { env: "MODEL_LOCAL_TOKEN", unrelated_metadata: "outside-public-contract" }, timeout_seconds: 17, max_retries: 1, max_output_tokens: 2048, redaction: { enabled: true, include_evidence_content: false, max_string_chars: 1500, redact_keys: ["api_key", "authorization", "cookie", "credential", "password", "secret", "token", "private_note"] }, unrelated_metadata: "outside-public-contract" };
    const resource = { kind: "model_provider", id: doc.id, status: "draft", document: { config: doc }, digest: "test-digest", created_at: "", updated_at: "" };
    vi.mocked(api.resources).mockResolvedValue({ schema_version: "bluefire.resource-list.v1", kind: "model_provider", resources: [resource] });
    vi.mocked(api.saveResource).mockResolvedValue({ schema_version: "bluefire.resource.v1", resource });
    const user = userEvent.setup(); mount();
    expect(await screen.findByText("Responses API · custom-model")).toBeVisible();
    expect(screen.getByText(doc.id)).not.toBeVisible();
    await user.click(await screen.findByRole("button", { name: "Edit Responses API · custom-model" }));
    await user.click(screen.getAllByText("Connection identity")[0]!);
    expect(screen.getByLabelText("Provider ID", { exact: false })).toHaveValue(doc.id);
    expect(screen.getByLabelText("Request endpoint", { exact: false })).toHaveValue(doc.endpoint);
    expect(screen.getByLabelText("Secret environment reference", { exact: false })).toHaveValue("MODEL_LOCAL_TOKEN");
    await user.click(screen.getByText("Prepare a disposable lab connection"));
    await user.click(screen.getByRole("button", { name: "Download lab connection" }));
    expect(downloadArtifact).toHaveBeenCalledTimes(1);
    const [blob, filename] = vi.mocked(downloadArtifact).mock.calls[0]!;
    expect(filename).toBe("bluefire-model-connection.json");
    expect(blob.type).toBe("application/json"); expect(blob.size).toBeLessThanOrEqual(16_384);
    expect(JSON.parse(await blobText(blob))).toEqual(publicProvider(doc));
    expect(JSON.parse(await blobText(blob)).api_key).toEqual({ env: "MODEL_LOCAL_TOKEN" });
    expect(screen.getByText(/Review after restarting: earlier service authorizations do not transfer/)).toBeVisible();
    expect(screen.getByText(/--ai-provider-definition/)).toBeVisible();
    expect(api.saveResource).not.toHaveBeenCalled(); expect(api.activateResource).not.toHaveBeenCalled(); expect(api.authorizeAI).not.toHaveBeenCalled(); expect(api.checkAIProvider).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Save secret-free draft" }));
    await waitFor(() => expect(api.saveResource).toHaveBeenCalledWith("model-providers", doc.id, publicProvider(doc), "draft"));
    expect(api.checkAIProvider).not.toHaveBeenCalled();
    expect(api.authorizeAI).not.toHaveBeenCalled();
    await user.clear(screen.getByLabelText("Model ID", { exact: false }));
    await user.click(screen.getByLabelText("Model ID", { exact: false })); await user.paste("changed-model");
    await user.click(screen.getByRole("button", { name: "Download lab connection" }));
    expect(downloadArtifact).toHaveBeenCalledTimes(2);
    expect(JSON.parse(await blobText(vi.mocked(downloadArtifact).mock.calls[1]![0]))).toEqual({ ...publicProvider(doc), model: "changed-model" });
    expect(api.saveResource).toHaveBeenCalledTimes(1); expect(api.activateResource).not.toHaveBeenCalled(); expect(api.authorizeAI).not.toHaveBeenCalled(); expect(api.checkAIProvider).not.toHaveBeenCalled();
  });
  it("distinguishes missing credentials, unavailable enrollment and missing usage without making a model request", async () => {
    const initial = snapshot(); initial.context = { ...initial.context, kind: "broker", provider, expires_at_ms: Date.now() + 900000 };
    vi.mocked(api.aiAuthorizations).mockResolvedValue(initial);
    const user = userEvent.setup(); mount();
    const check = await screen.findByRole("button", { name: "Check configuration" });
    await waitFor(() => expect(check).toBeEnabled());
    vi.mocked(api.checkAIProvider).mockResolvedValue({ ...checked, code: "credential_unavailable", credential_state: "unavailable", message: "Credential ownership is unavailable." });
    await user.click(check);
    expect(await screen.findByText(/Provide the named environment variable to the host launcher/)).toBeVisible();
    expect(screen.queryByText("Not checked · restore enrolled connection")).not.toBeInTheDocument();
    vi.mocked(api.checkAIProvider).mockResolvedValue({ ...checked, code: "broker_unavailable", credential_state: "unavailable", message: "The enrolled connection is unavailable." });
    await user.click(check);
    expect(await screen.findByText("Not checked · restore enrolled connection")).toBeVisible();
    expect(screen.getByText(/A broker failure does not establish that the named environment variable is missing/)).toBeVisible();
    expect(screen.queryByText(/Provide the named environment variable to the host launcher/)).not.toBeInTheDocument();
    vi.mocked(api.checkAIProvider).mockResolvedValue(checked);
    await user.click(check);
    expect(await screen.findByText("Configuration checked · connection untested")).toBeVisible();
    expect(screen.getByText("Review required")).toBeVisible();
    expect(screen.getByRole("button", { name: "Send live connection test" })).toBeDisabled();
    expect(api.checkAIProvider).toHaveBeenCalledTimes(3);
    expect(vi.mocked(api.checkAIProvider).mock.calls.every(([config, connect]) => JSON.stringify(config) === JSON.stringify(provider) && connect === false)).toBe(true);
    expect(api.saveResource).not.toHaveBeenCalled(); expect(api.activateResource).not.toHaveBeenCalled(); expect(api.authorizeAI).not.toHaveBeenCalled();
  });
  it("names wrapped built-in cards without displaying their IDs as primary labels", async () => {
    const configs = [
      { id: "deterministic-offline.v1", kind: "deterministic", model: "deterministic-planner.v1" },
      { id: "openai-responses.v1", kind: "openai_responses", model: "configured-model" },
    ];
    vi.mocked(api.resources).mockResolvedValue({ schema_version: "bluefire.resource-list.v1", kind: "model_provider", resources: configs.map(config => ({ kind: "model_provider", id: config.id, status: "active", document: { config }, digest: "test-digest", created_at: "", updated_at: "" })) });
    mount();
    const saved = await screen.findByRole("region", { name: "Saved model connections" });
    expect(within(saved).getByText("Offline deterministic planner")).toBeVisible();
    expect(within(saved).getByText("Responses API · configured-model")).toBeVisible();
    for (const config of configs) expect(within(saved).getByText(config.id)).not.toBeVisible();
    expect(api.saveResource).not.toHaveBeenCalled();
    expect(api.activateResource).not.toHaveBeenCalled();
    expect(api.authorizeAI).not.toHaveBeenCalled();
    expect(api.checkAIProvider).not.toHaveBeenCalled();
  });
  it("keeps deterministic mode free of a live-test button", async () => {
    mount();
    await waitFor(() => expect(screen.getByLabelText("API style")).toBeEnabled());
    await userEvent.setup().selectOptions(screen.getByLabelText("API style"), "deterministic");
    expect(screen.queryByRole("button", { name: "Send live connection test" })).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Secret environment reference", { exact: false })).not.toBeInTheDocument();
    expect(screen.queryByText("Prepare a disposable lab connection")).not.toBeInTheDocument();
    expect(screen.getByText("No model calls")).toBeVisible();
    expect(screen.getByText(/no API key or model usage authorization is needed/)).toBeVisible();
    expect(screen.queryByText(/Provide the credential through the named environment variable/)).not.toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "Selected connection summary" })).getByText("No network destination")).toBeVisible();
    expect(downloadArtifact).not.toHaveBeenCalled();
  });
  it("applies optional endpoint presets without inventing models or replacing identity and request limits", async () => {
    const user = userEvent.setup(); mount();
    await waitFor(() => expect(screen.getByLabelText("Connection preset", { exact: false })).toBeEnabled());
    await user.selectOptions(screen.getByLabelText("Connection preset", { exact: false }), "openai");
    expect(screen.getByLabelText("Request endpoint", { exact: false })).toHaveValue("https://api.openai.com/v1/responses");
    expect(screen.getByLabelText("Secret environment reference", { exact: false })).toHaveValue("OPENAI_API_KEY");
    expect(screen.getByLabelText("Model ID", { exact: false })).toHaveValue("");
    await user.type(screen.getByLabelText("Model ID", { exact: false }), "operator-selected-model");
    await user.click(screen.getByText("Request limits"));
    await user.clear(screen.getByLabelText("Output token limit", { exact: false }));
    await user.type(screen.getByLabelText("Output token limit", { exact: false }), "2048");
    await user.selectOptions(screen.getByLabelText("Connection preset", { exact: false }), "loopback");
    expect(screen.getByLabelText("Model ID", { exact: false })).toHaveValue("operator-selected-model");
    expect(screen.getByLabelText("Provider ID", { exact: false })).toHaveValue("provider.local.v1");
    expect(screen.getByLabelText("Output token limit", { exact: false })).toHaveValue(2048);
    expect(screen.getByLabelText("Request endpoint", { exact: false })).toHaveValue("http://127.0.0.1:8080/v1/chat/completions");
    expect(screen.getByText(/A loopback address does not identify a test provider/)).toBeVisible();
    expect(api.checkAIProvider).not.toHaveBeenCalled(); expect(api.saveResource).not.toHaveBeenCalled(); expect(api.activateResource).not.toHaveBeenCalled(); expect(api.authorizeAI).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "Send live connection test" })).toBeDisabled();
  });
  it("summarizes exact bound usage reservations and the earlier session expiry", async () => {
    const sessionExpiry = Date.now() + 60_000;
    const initial = snapshot([authorization({ context: { kind: "broker", binding_digest: snapshot().context.binding_digest! }, usage: { requests: 2, request_bytes: 1024, reserved_output_tokens: 800 } })]);
    initial.context = { ...initial.context, kind: "broker", provider, expires_at_ms: sessionExpiry };
    vi.mocked(api.aiAuthorizations).mockResolvedValue(initial);
    mount();
    const summary = screen.getByRole("region", { name: "Selected connection summary" });
    expect(await within(summary).findByText("my-model")).toBeVisible();
    expect(within(summary).getByText("https://model.example")).toBeVisible();
    expect(within(summary).getByText("Enrolled connection")).toBeVisible();
    expect(within(summary).getByText("Authorized for 1 purpose")).toBeVisible();
    const limits = within(summary).getByLabelText("Current authorization remaining limits");
    expect(within(limits).getByText("10")).toBeVisible();
    expect(within(limits).getByText("4,193,280")).toBeVisible();
    expect(within(limits).getByText("15,584")).toBeVisible();
    expect(limits.querySelector("time")).toHaveAttribute("datetime", new Date(sessionExpiry).toISOString());
    expect(screen.queryByLabelText("Connection preset", { exact: false })).not.toBeInTheDocument();
    expect(api.authorizeAI).not.toHaveBeenCalled(); expect(api.checkAIProvider).not.toHaveBeenCalled();
  });
  it("does not describe an expired broker session as currently authorized", async () => {
    const initial = snapshot([authorization({ context: { kind: "broker", binding_digest: snapshot().context.binding_digest! } })]);
    initial.context = { ...initial.context, kind: "broker", provider, expires_at_ms: Date.now() - 1 };
    vi.mocked(api.aiAuthorizations).mockResolvedValue(initial);
    mount();
    const summary = screen.getByRole("region", { name: "Selected connection summary" });
    expect(await within(summary).findByText("Enrolled session expired")).toBeVisible();
    expect(within(summary).getByText("No current authorization")).toBeVisible();
    expect(within(summary).queryByLabelText("Current authorization remaining limits")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Send live connection test" })).toBeDisabled();
  });
  it("retains cached authorization history without reporting active authority after refresh fails", async () => {
    const initial = snapshot([authorization({ context: { kind: "broker", binding_digest: snapshot().context.binding_digest! } })]);
    initial.context = { ...initial.context, kind: "broker", provider, expires_at_ms: Date.now() + 60_000 };
    vi.mocked(api.aiAuthorizations).mockResolvedValue(initial);
    const client = mount();
    const row = await screen.findByRole("article", { name: "Model authorization for my-model" });
    expect(within(row).getByText("Active")).toHaveClass("badge-success");
    vi.mocked(api.aiAuthorizations).mockRejectedValue(new Error("Authorization status is offline"));
    await act(async () => { await client.invalidateQueries({ queryKey: ["ai-authorizations"] }); });
    expect(await within(row).findByText("Last reported")).toHaveClass("badge-neutral");
    expect(within(row).queryByText("Active")).not.toBeInTheDocument();
    expect(within(row).getByText("Last reported status: Active. Current authority is unavailable.")).toBeVisible();
    expect(within(row).getByRole("button", { name: "Revoke model usage for my-model" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Authorize reviewed model usage" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Send live connection test" })).toBeDisabled();
    expect(screen.queryByLabelText("Current authorization remaining limits")).not.toBeInTheDocument();
    expect(api.authorizeAI).not.toHaveBeenCalled(); expect(api.revokeAIAuthorization).not.toHaveBeenCalled(); expect(api.checkAIProvider).not.toHaveBeenCalled();
  });
  it("retains cached connection records without presenting their active status as current after refresh fails", async () => {
    vi.mocked(api.resources).mockResolvedValue({ schema_version: "bluefire.resource-list.v1", kind: "model_provider", resources: [{ kind: "model_provider", id: provider.id, status: "active", document: { ...provider }, digest: "test-digest", created_at: "", updated_at: "" }] });
    const client = mount();
    const saved = await screen.findByRole("region", { name: "Saved model connections" });
    expect(within(saved).getByText("Active")).toBeVisible();
    vi.mocked(api.resources).mockRejectedValue(new Error("Saved provider inventory is offline"));
    await act(async () => { await client.invalidateQueries({ queryKey: ["resources", "model-providers"] }); });
    expect(await within(saved).findByText("Last reported")).toHaveClass("badge-neutral");
    expect(within(saved).queryByText("Active")).not.toBeInTheDocument();
    expect(within(saved).getByText("Last reported status: Active. Current saved state is unavailable.")).toBeVisible();
    expect(within(saved).getByRole("button", { name: "Edit Chat Completions API · my-model" })).toBeDisabled();
    expect(within(saved).getByRole("button", { name: "Deactivate" })).toBeDisabled();
    expect(api.saveResource).not.toHaveBeenCalled(); expect(api.activateResource).not.toHaveBeenCalled(); expect(api.deactivateResource).not.toHaveBeenCalled();
  });
});
