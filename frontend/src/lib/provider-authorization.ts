import type { AILiveAuthorization, AILiveAuthorizationList, AIModelPurpose, PublicAIProviderConfig } from "../types";
import { sameJson } from "./replay-review";

export const modelPurposes: Record<AIModelPurpose, string> = {
  bluefire_connection_check: "Test the connection with synthetic data",
  bluefire_ai_proposal: "Choose reviewed methods during a run",
  bluefire_experiment_assistance: "Plan work in the Assistant",
  bluefire_detection_source_creation: "Create a detection from observations",
  bluefire_detection_source_revision: "Revise a detection",
  bluefire_run_evidence_inspection: "Explain run evidence and cleanup",
  bluefire_method_comparison: "Compare methods against a detection",
  bluefire_ai_graph_draft: "Create an experiment graph",
  bluefire_graph_step_edit: "Edit graph parameters",
  bluefire_receiver_defense_inspection: "Explain a receiver control test",
};
export const requiredRedactionKeys = ["api_key", "authorization", "cookie", "credential", "password", "secret", "token"];
export const integerInRange = (value: number, low: number, high: number) => Number.isInteger(value) && value >= low && value <= high;
export function isLoopbackProvider(provider: PublicAIProviderConfig): boolean {
  try { return ["localhost", "127.0.0.1", "[::1]"].includes(new URL(provider.endpoint ?? "").hostname); } catch { return false; }
}

/** Fill the same public defaults used by the service; never resolve a secret reference. */
export function publicProvider(source: Record<string, unknown>): PublicAIProviderConfig {
  const raw = source.config && typeof source.config === "object" ? source.config as Record<string, unknown> : source;
  const redaction = raw.redaction && typeof raw.redaction === "object" ? raw.redaction as Record<string, unknown> : {};
  return {
    id: String(raw.id ?? "").trim(), kind: raw.kind as PublicAIProviderConfig["kind"], model: String(raw.model ?? "").trim(),
    endpoint: raw.endpoint == null ? null : String(raw.endpoint).trim().replace(/\/+$/, ""), api_key: raw.api_key == null ? null : { env: String((raw.api_key as { env?: unknown }).env ?? "").trim() },
    timeout_seconds: Number(raw.timeout_seconds ?? 30), max_retries: Number(raw.max_retries ?? 2), max_output_tokens: Number(raw.max_output_tokens ?? 800),
    redaction: { enabled: redaction.enabled === undefined ? true : redaction.enabled === true, redact_keys: Array.isArray(redaction.redact_keys) ? redaction.redact_keys.map(String) : [...requiredRedactionKeys], max_string_chars: Number(redaction.max_string_chars ?? 4000), include_evidence_content: redaction.include_evidence_content === true },
  };
}

export function providerErrors(provider: PublicAIProviderConfig): string[] {
  const errors: string[] = [];
  if (provider.id.length > 200 || !/^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\.v[1-9][0-9]*$/.test(provider.id)) errors.push("Use a lowercase, versioned provider ID, such as provider.local.v1 (up to 200 characters).");
  if (!provider.model.trim() || provider.model.length > 200) errors.push("Enter the exact model ID (up to 200 characters).");
  if (provider.kind !== "deterministic") {
    try {
      const endpoint = new URL(provider.endpoint ?? "");
      if (!endpoint.hostname || endpoint.username || endpoint.password || endpoint.search || endpoint.hash || endpoint.port === "0" || provider.endpoint!.length > 2048 || (endpoint.protocol !== "https:" && !(endpoint.protocol === "http:" && isLoopbackProvider(provider)))) throw new Error();
    } catch { errors.push("Use a full HTTPS request endpoint, or HTTP for loopback, without credentials, query parameters or a fragment."); }
    if (provider.api_key ? !/^[A-Z][A-Z0-9_]*$/.test(provider.api_key.env) : !isLoopbackProvider(provider)) errors.push("Enter an uppercase server environment variable name, never its value. A remote endpoint requires a reference.");
  }
  if (!integerInRange(provider.timeout_seconds, 1, 300)) errors.push("Timeout must be a whole number from 1 to 300 seconds.");
  if (!integerInRange(provider.max_output_tokens, 64, 16384)) errors.push("Output token limit must be a whole number from 64 to 16,384.");
  if (!integerInRange(provider.max_retries, 0, 5)) errors.push("Transport retries must be a whole number from 0 to 5.");
  return errors;
}

export function hasRequiredDataPolicy(provider: PublicAIProviderConfig): boolean {
  return provider.redaction.enabled && !provider.redaction.include_evidence_content && requiredRedactionKeys.every(key => provider.redaction.redact_keys.includes(key));
}
export function authorizationStatus(row: AILiveAuthorization, snapshot: AILiveAuthorizationList, now: number): string {
  if (row.status !== "active") return row.status;
  if (!snapshot.context.binding_digest || row.context.binding_digest !== snapshot.context.binding_digest || row.context.kind !== snapshot.context.kind) return "context_unavailable";
  if (row.expires_at_ms <= now || (snapshot.context.expires_at_ms !== null && snapshot.context.expires_at_ms <= now)) return "expired";
  if (row.usage.requests >= row.limits.max_requests || row.usage.request_bytes >= row.limits.max_request_bytes || row.usage.reserved_output_tokens >= row.limits.max_reserved_output_tokens) return "budget_exhausted";
  return "active";
}
export function matchingAuthorization(provider: PublicAIProviderConfig, snapshot: AILiveAuthorizationList | undefined, now: number, purpose?: AIModelPurpose): AILiveAuthorization | undefined {
  return snapshot?.authorizations.find(row => sameJson(row.provider, provider) && authorizationStatus(row, snapshot, now) === "active" && (!purpose || row.purposes.includes(purpose)));
}
