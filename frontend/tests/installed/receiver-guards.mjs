import { isDeepStrictEqual } from "node:util";

// Saved JSON objects may be canonicalized; array order and exact values still matter.
export const sameJson = isDeepStrictEqual;

export function receiverContextRequestAllowed(body, expected) {
  const linked = expected.sourceControl !== null;
  const keys = linked
    ? ["selection", "run_intent", "workflow", "source_control"]
    : ["selection", "run_intent", "workflow"];
  const intent = body?.run_intent;
  const intentKeys = intent?.mode === "execute"
    ? ["mode", "autonomy", "ai_provider_id", "runner_profile_id", "target_scope", "collectors"]
    : ["mode", "autonomy", "ai_provider_id", "runner_profile_id", "target_scope"];
  const scopes = intent?.target_scope?.scope_refs;
  if (!body || typeof body !== "object" || Array.isArray(body)
    || !exactKeys(body, keys) || body.workflow !== expected.workflow
    || !sameJson(body.selection, expected.selection)
    || (linked && !sameJson(body.source_control, expected.sourceControl))
    || !exactKeys(intent, intentKeys)
    || !Object.hasOwn(expected.profileIdsByMode, intent.mode)
    || intent.autonomy !== "off" || intent.ai_provider_id !== null
    || !expected.profileIdsByMode[intent.mode].includes(intent.runner_profile_id)
    || !exactKeys(intent.target_scope, ["scope_refs"])
    || !Array.isArray(scopes) || scopes.length < 1 || scopes.length > expected.scopeRefs.length
    || new Set(scopes).size !== scopes.length
    || scopes.some((scope) => !expected.scopeRefs.includes(scope))
    || (intent.mode === "execute" && !sameJson(intent.collectors, expected.collectors))) return false;
  return true;
}

export function receiverContextRequestIsFinal(body, expected) {
  return receiverContextRequestAllowed(body, expected)
    && sameJson(body.run_intent, expected.finalRunIntent);
}

export function receiverContextResponseMatchesRequest(requestBody, finalRequest, responseBody) {
  if (!finalRequest || !sameJson(requestBody, finalRequest)
    || !responseBody || typeof responseBody !== "object" || Array.isArray(responseBody)
    || responseBody.schema_version !== "bluefire.receiver-defense-context.v1"
      && responseBody.schema_version !== "bluefire.receiver-defense-context.v2"
    || typeof responseBody.context_digest !== "string"
    || !/^sha256:[0-9a-f]{64}$/.test(responseBody.context_digest)
    || !sameJson(responseBody.selection, finalRequest.selection)
    || !sameJson(responseBody.run_intent, finalRequest.run_intent)
    || responseBody.workflow !== finalRequest.workflow
    || !sameJson(responseBody.source_control ?? null, finalRequest.source_control ?? null)) return false;
  return true;
}

export function receiverOwnerContextMatches(ownerBody, finalRequest, finalResponse) {
  if (!ownerBody || typeof ownerBody !== "object" || Array.isArray(ownerBody)
    || !finalResponse || ownerBody.context_digest !== finalResponse.context_digest) return false;
  const request = {
    selection: ownerBody.selection,
    run_intent: ownerBody.run_intent,
    workflow: ownerBody.workflow,
    ...(ownerBody.source_control !== undefined ? { source_control: ownerBody.source_control } : {}),
  };
  return receiverContextResponseMatchesRequest(request, finalRequest, finalResponse);
}

function exactKeys(value, names) {
  return value && typeof value === "object" && !Array.isArray(value)
    && sameJson(Object.keys(value).sort(), [...names].sort());
}

export function consumeRequestBudget(counts, limits, key) {
  if (!Object.hasOwn(limits, key) || counts[key] >= limits[key]) return false;
  counts[key] += 1;
  return true;
}

export function classifyRequest({ origin, expectedOrigin, method, url, body, bodyError, allowedRead, authorizePost }) {
  if (origin !== expectedOrigin) return { allowed: false, reason: "non_loopback" };
  if (method === "GET" || method === "HEAD") {
    return allowedRead(url)
      ? { allowed: true }
      : { allowed: false, reason: "read_not_allowlisted" };
  }
  if (method === "POST") {
    if (bodyError) return { allowed: false, reason: "invalid_json_body" };
    return authorizePost(url, body)
      ? { allowed: true }
      : { allowed: false, reason: "write_not_allowlisted_or_budget_exceeded" };
  }
  return { allowed: false, reason: "method_not_allowlisted" };
}
