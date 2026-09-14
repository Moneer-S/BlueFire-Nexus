import { describe, expect, it } from "vitest";
import { authorizationStatus, hasRequiredDataPolicy, isLoopbackProvider, matchingAuthorization, modelPurposes, providerErrors, publicProvider } from "../src/lib/provider-authorization";
import { authorization, provider, snapshot } from "./provider-authorization-fixtures";

describe("exact live model review", () => {
  it("matches only the complete current configuration and the requested purpose", () => {
    const rows = snapshot([authorization()]);
    expect(matchingAuthorization(provider, rows, Date.now(), "bluefire_connection_check")).toBeDefined();
    expect(matchingAuthorization(provider, rows, Date.now(), "bluefire_ai_proposal")).toBeUndefined();
    for (const changed of [{ ...provider, model: "different" }, { ...provider, endpoint: "https://other.example/v1/responses" }, { ...provider, api_key: { env: "OTHER_KEY" } }, { ...provider, max_retries: 1 }, { ...provider, redaction: { ...provider.redaction, include_evidence_content: true } }]) expect(matchingAuthorization(changed, rows, Date.now())).toBeUndefined();
  });
  it.each(["revoked", "expired", "context_unavailable"] as const)("does not treat %s rows as current authority", status => {
    expect(matchingAuthorization(provider, snapshot([authorization({ status })]), Date.now())).toBeUndefined();
  });
  it("expires locally and refuses a restarted or expired enrollment", () => {
    const row = authorization(); const rows = snapshot([row]);
    expect(authorizationStatus(row, rows, row.expires_at_ms)).toBe("expired");
    expect(matchingAuthorization(provider, { ...rows, context: { ...rows.context, binding_digest: "new-session" } }, Date.now())).toBeUndefined();
    expect(matchingAuthorization(provider, { ...rows, context: { ...rows.context, expires_at_ms: Date.now() - 1 } }, Date.now())).toBeUndefined();
  });
  it.each(["requests", "request_bytes", "reserved_output_tokens"] as const)("never treats exhausted %s as remaining authority", counter => {
    const row = authorization(); row.usage[counter] = counter === "requests" ? row.limits.max_requests : counter === "request_bytes" ? row.limits.max_request_bytes : row.limits.max_reserved_output_tokens;
    expect(authorizationStatus(row, snapshot([row]), Date.now())).toBe("budget_exhausted");
    expect(matchingAuthorization(provider, snapshot([row]), Date.now())).toBeUndefined();
  });
  it("keeps all ten existing purposes explicit", () => { expect(Object.keys(modelPurposes)).toHaveLength(10); expect(modelPurposes.bluefire_ai_graph_draft).toBe("Create an experiment graph"); });
  it("normalizes public configuration exactly as the service before review and matching", () => {
    expect(publicProvider({ ...provider, id: ` ${provider.id} `, model: ` ${provider.model} `, endpoint: `${provider.endpoint}/// `, api_key: { env: " MODEL_API_KEY " } })).toEqual(provider);
    expect(providerErrors({ ...provider, id: "UnversionedName" })).not.toEqual([]);
    expect(providerErrors({ ...provider, api_key: { env: "lowercase_key" } })).not.toEqual([]);
  });
  it("preserves explicit data limits and detects unsafe redaction without silently granting it", () => {
    const source = publicProvider({ ...provider, redaction: { enabled: false, include_evidence_content: true, max_string_chars: 900, redact_keys: ["token", "other"] } });
    expect(source.redaction.max_string_chars).toBe(900); expect(source.redaction.redact_keys).toEqual(["token", "other"]);
    expect(hasRequiredDataPolicy(source)).toBe(false); expect(hasRequiredDataPolicy(provider)).toBe(true);
  });
  it("rejects malformed references, remote HTTP, credentials in URLs and invalid request limits locally", () => {
    expect(providerErrors(provider)).toEqual([]);
    for (const changed of [{ ...provider, api_key: { env: "not a variable" } }, { ...provider, api_key: null }, { ...provider, endpoint: "http://model.example/v1/responses" }, { ...provider, endpoint: "https://user:pass@model.example/v1/responses" }, { ...provider, max_retries: 1.5 }, { ...provider, max_output_tokens: 0 }, { ...provider, timeout_seconds: 301 }]) expect(providerErrors(changed).length).toBeGreaterThan(0);
    for (const endpoint of ["http://localhost:8080/v1/responses", "http://127.0.0.1:8080/v1/responses", "http://[::1]:8080/v1/responses"]) { expect(isLoopbackProvider({ ...provider, endpoint })).toBe(true); expect(providerErrors({ ...provider, endpoint, api_key: null })).toEqual([]); }
  });
});
