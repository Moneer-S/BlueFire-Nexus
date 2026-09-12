import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ProviderSetup } from "../src/components/ProviderSetup";
import { api } from "../src/lib/api";
import { publicProvider } from "../src/lib/provider-authorization";
import type { AIProviderCheck } from "../src/types";
import { authorization, snapshot } from "./provider-authorization-fixtures";

vi.mock("../src/lib/api", () => ({ api: { resources: vi.fn(), checkAIProvider: vi.fn(), saveResource: vi.fn(), activateResource: vi.fn(), deactivateResource: vi.fn(), aiAuthorizations: vi.fn(), authorizeAI: vi.fn(), revokeAIAuthorization: vi.fn() } }));
const checked: AIProviderCheck = { schema_version: "bluefire.ai-provider-check.v1", provider_id: "provider.local.v1", api_style: "chat_completions", model: "my-model", credential_state: "ready", connectivity: "not_tested", structured_output: "not_tested", attempts: 0, used_fallback: false, code: "configuration_ready", message: "Configuration checked; no network request was made." };
function mount() { render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}><ProviderSetup/></QueryClientProvider>); }

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
    await user.type(screen.getByLabelText("Model ID", { exact: false }), "my-model");
    await user.type(screen.getByLabelText("Request endpoint", { exact: false }), "https://model.example/v1/chat/completions");
    await user.type(screen.getByLabelText("Secret environment reference", { exact: false }), "MODEL_API_KEY");
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
    const doc = { id: "provider.local.v1", kind: "openai_responses", model: "custom-model", endpoint: "http://localhost:8080/custom/responses", api_key: { env: "MODEL_LOCAL_TOKEN" }, timeout_seconds: 17, max_retries: 1, max_output_tokens: 2048, redaction: { enabled: true, include_evidence_content: false, max_string_chars: 1500, redact_keys: ["api_key", "authorization", "cookie", "credential", "password", "secret", "token", "private_note"] } };
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
    await user.click(screen.getByRole("button", { name: "Save secret-free draft" }));
    await waitFor(() => expect(api.saveResource).toHaveBeenCalledWith("model-providers", doc.id, publicProvider(doc), "draft"));
    expect(api.checkAIProvider).not.toHaveBeenCalled();
    expect(api.authorizeAI).not.toHaveBeenCalled();
  });
  it("names wrapped built-in cards without displaying their IDs as primary labels", async () => {
    const configs = [
      { id: "deterministic-offline.v1", kind: "deterministic", model: "deterministic-planner.v1" },
      { id: "openai-responses.v1", kind: "openai_responses", model: "configured-model" },
    ];
    vi.mocked(api.resources).mockResolvedValue({ schema_version: "bluefire.resource-list.v1", kind: "model_provider", resources: configs.map(config => ({ kind: "model_provider", id: config.id, status: "active", document: { config }, digest: "test-digest", created_at: "", updated_at: "" })) });
    mount();
    expect(await screen.findByText("Offline deterministic planner")).toBeVisible();
    expect(screen.getByText("Responses API · configured-model")).toBeVisible();
    for (const config of configs) expect(screen.getByText(config.id)).not.toBeVisible();
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
  });
});
