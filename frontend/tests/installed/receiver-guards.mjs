import { isDeepStrictEqual } from "node:util";

// Saved JSON objects may be canonicalized; array order and exact values still matter.
export const sameJson = isDeepStrictEqual;
export const receiverApprovalAcknowledgementName = /^I approve this exact immutable job envelope once\s*Unchecked by default and never stored in browser persistence$/;

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

export function receiverOwnerAdmissionState(owner, ownerId, finalRequest, finalResponse) {
  const retained = finalRequest?.workflow === "retained_redaction";
  const expectedContextSchema = retained
    ? "bluefire.receiver-defense-context.v2"
    : "bluefire.receiver-defense-context.v1";
  const expectedEnvelopeSchema = retained
    ? "bluefire.receiver-defense.v2"
    : "bluefire.receiver-defense.v1";
  const job = owner?.job;
  const request = job?.request;
  const submitted = request?.submitted_request;
  const submissionId = submitted?.submission_id;
  const submissionBinding = request?._submission;
  const pendingJob = ["queued", "planning", "running"].includes(job?.state);
  if (!owner || typeof owner !== "object" || Array.isArray(owner)
    || !finalRequest || typeof finalRequest !== "object" || Array.isArray(finalRequest)
    || typeof ownerId !== "string" || !/^job-[0-9a-f]{32}$/.test(ownerId)
    || owner.schema_version !== expectedEnvelopeSchema
    || job?.schema_version !== "bluefire.job.v1" || job.job_id !== ownerId
    || job.kind !== "receiver.defense"
    || !["queued", "planning", "running", "completed", "failed", "cancelled", "interrupted"].includes(job.state)
    || !request || typeof request !== "object" || Array.isArray(request)
    || !job.progress || typeof job.progress !== "object" || Array.isArray(job.progress)
    || !exactKeys(submitted, [...Object.keys(finalRequest), "submission_id", "context_digest"])
    || !receiverOwnerContextMatches(submitted, finalRequest, finalResponse)
    || typeof submissionId !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(submissionId)
    || ownerId !== `job-${submissionId.replaceAll("-", "")}`
    || !exactKeys(submissionBinding, ["schema_version", "submission_id", "intent_digest"])
    || submissionBinding.schema_version !== "bluefire.job-submission.v1"
    || submissionBinding.submission_id !== submissionId
    || typeof submissionBinding.intent_digest !== "string"
    || !/^sha256:[0-9a-f]{64}$/.test(submissionBinding.intent_digest)
    || !sameJson(request.context, owner.context)
    || request.context_digest !== owner.context?.context_digest
    || !Array.isArray(owner.phases) || !owner.next_action || typeof owner.next_action !== "object"
    || !["active", "blocked", "stopping", "stopped", "completed"].includes(owner.status)
    || !receiverContextResponseMatchesRequest(finalRequest, finalRequest, owner.context)
    || owner.context.schema_version !== expectedContextSchema
    || owner.context.context_digest !== finalResponse?.context_digest
    || !exactKeys(owner.admission, ["accepted", "problem"])
    || typeof owner.admission.accepted !== "boolean"
    || !sameJson(job.progress.admission, owner.admission)) return "invalid";
  if (owner.admission.accepted === true && owner.admission.problem === null
    && job.state === "completed") return "accepted";
  if (owner.admission.accepted === true && owner.admission.problem === null
    && job.state === "running" && owner.status === "active") return "pending";
  if (owner.admission.accepted === false && owner.admission.problem === null
    && pendingJob && owner.status === "active") return "pending";
  return "invalid";
}

export function receiverRunIsNotDemo(run) {
  return run !== null && typeof run === "object" && !Array.isArray(run)
    && (run.is_demo === undefined || run.is_demo === false);
}

export function receiverCompletedPhase(owner, phaseName) {
  if (!owner || typeof owner !== "object" || Array.isArray(owner) || !Array.isArray(owner.phases)) return null;
  const phase = owner.phases.find((item) => item?.phase === phaseName);
  if (phase?.status !== "completed" || phase.execution_job?.state !== "completed"
    || !phase.preparation?.preparation_digest || !phase.result || !phase.cleanup) return null;
  return phase;
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
