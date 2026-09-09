import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ProviderSetup } from "../src/components/ProviderSetup";
import { api } from "../src/lib/api";
import type { AIProviderCheck } from "../src/types";

vi.mock("../src/lib/api", () => ({ api: { resources: vi.fn(), checkAIProvider: vi.fn(), saveResource: vi.fn(), activateResource: vi.fn(), deactivateResource: vi.fn() } }));
const checked: AIProviderCheck = { schema_version: "bluefire.ai-provider-check.v1", provider_id: "provider.local.v1", api_style: "chat_completions", model: "my-model", credential_state: "ready", connectivity: "not_tested", structured_output: "not_tested", attempts: 0, used_fallback: false, code: "configuration_ready", message: "Configuration checked; no network request was made." };
function mount() { render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}><ProviderSetup/></QueryClientProvider>); }

describe("explicit provider setup", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(api.resources).mockResolvedValue({ schema_version: "bluefire.resource-list.v1", kind: "model_provider", resources: [] });
    vi.mocked(api.checkAIProvider).mockResolvedValue(checked);
  });
  it("never probes on mount and separates readiness from opt-in live testing", async () => {
    const user = userEvent.setup(); mount();
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
  });
  it("edits saved endpoint and environment reference while preserving request/redaction settings", async () => {
    const doc = { id: "provider.local.v1", kind: "openai_responses", model: "custom-model", endpoint: "http://localhost:8080/custom/responses", api_key: { env: "MODEL_LOCAL_TOKEN" }, timeout_seconds: 17, max_retries: 1, max_output_tokens: 2048, redaction: { enabled: true, include_evidence_content: false } };
    const resource = { kind: "model_provider", id: doc.id, status: "draft", document: doc, digest: "test-digest", created_at: "", updated_at: "" };
    vi.mocked(api.resources).mockResolvedValue({ schema_version: "bluefire.resource-list.v1", kind: "model_provider", resources: [resource] });
    vi.mocked(api.saveResource).mockResolvedValue({ schema_version: "bluefire.resource.v1", resource });
    const user = userEvent.setup(); mount();
    await user.click(await screen.findByRole("button", { name: "Edit provider.local.v1" }));
    expect(screen.getByLabelText("Request endpoint", { exact: false })).toHaveValue(doc.endpoint);
    expect(screen.getByLabelText("Secret environment reference", { exact: false })).toHaveValue("MODEL_LOCAL_TOKEN");
    await user.click(screen.getByRole("button", { name: "Save secret-free draft" }));
    await waitFor(() => expect(api.saveResource).toHaveBeenCalledWith("model-providers", doc.id, doc, "draft"));
    expect(api.checkAIProvider).not.toHaveBeenCalled();
  });
  it("keeps deterministic mode free of a live-test button", async () => {
    mount();
    await userEvent.setup().selectOptions(screen.getByLabelText("API style"), "deterministic");
    expect(screen.queryByRole("button", { name: "Send live connection test" })).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Secret environment reference", { exact: false })).not.toBeInTheDocument();
  });
});
