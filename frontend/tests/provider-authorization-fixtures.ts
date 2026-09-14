import { publicProvider } from "../src/lib/provider-authorization";
import type { AILiveAuthorization, AILiveAuthorizationList } from "../src/types";

export const provider = publicProvider({ id: "provider.local.v1", kind: "chat_completions", model: "my-model", endpoint: "https://model.example/v1/chat/completions", api_key: { env: "MODEL_API_KEY" }, timeout_seconds: 30, max_retries: 0, max_output_tokens: 800 });
export const context: AILiveAuthorizationList["context"] = { kind: "direct", binding_digest: `sha256:${"a".repeat(64)}`, expires_at_ms: null, provider: null };
export function authorization(overrides: Partial<AILiveAuthorization> = {}): AILiveAuthorization {
  return {
    schema_version: "bluefire.ai-live-authorization.v1", authorization_id: `ai-authorization-${"a".repeat(32)}`, authorization_digest: `sha256:${"b".repeat(64)}`, configuration_digest: `sha256:${"c".repeat(64)}`,
    provider: structuredClone(provider), purposes: ["bluefire_connection_check"], data_scope: "reviewed_lab_context", limits: { max_requests: 12, max_request_bytes: 4194304, max_reserved_output_tokens: 16384 },
    created_at_ms: Date.now(), expires_at_ms: Date.now() + 900000, approved_by: "Lab owner", usage_authorized: true, local_endpoint_authorized: false,
    context: { kind: "direct", binding_digest: context.binding_digest! }, status: "active", usage: { requests: 0, request_bytes: 0, reserved_output_tokens: 0 }, ...overrides,
  };
}
export function snapshot(rows: AILiveAuthorization[] = []): AILiveAuthorizationList { return { schema_version: "bluefire.ai-live-authorizations.v1", context: { ...context }, authorizations: rows }; }
