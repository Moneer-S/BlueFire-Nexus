import { useMutation } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { authorizationStatus, hasRequiredDataPolicy, integerInRange, isLoopbackProvider, modelPurposes } from "../lib/provider-authorization";
import { sameJson } from "../lib/replay-review";
import type { AILiveAuthorizationList, AIModelPurpose, AIUsageLimits, PublicAIProviderConfig } from "../types";
import { Badge, Button, DataList, ErrorState, Field, sentence } from "./Primitives";

interface Props {
  provider: PublicAIProviderConfig;
  snapshot: AILiveAuthorizationList;
  now: number;
  disabled: boolean;
  prepareProvider: () => Promise<void>;
  onBusy: (busy: boolean) => void;
  refresh: () => void;
}

export function ProviderAuthorizationReview({ provider, snapshot, now, disabled, prepareProvider, onBusy, refresh }: Props) {
  const [purposes, setPurposes] = useState<AIModelPurpose[]>([]);
  const [limits, setLimits] = useState<AIUsageLimits>({ max_requests: 12, max_request_bytes: 4194304, max_reserved_output_tokens: 16384 });
  const [seconds, setSeconds] = useState(900);
  const [actor, setActor] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [localConfirmed, setLocalConfirmed] = useState(false);
  const loopback = isLoopbackProvider(provider);
  const contextCurrent = Boolean(snapshot.context.binding_digest) && (snapshot.context.expires_at_ms === null || snapshot.context.expires_at_ms > now);
  const valid = purposes.length > 0 && integerInRange(limits.max_requests, 1, 64) && integerInRange(limits.max_request_bytes, 1, 16777216) && integerInRange(limits.max_reserved_output_tokens, 64, 1048576) && integerInRange(seconds, 1, 900) && actor.trim().length > 0 && actor.trim().length <= 128 && [...actor].every(character => character.charCodeAt(0) >= 32);
  const authorize = useMutation({
    mutationFn: async () => {
      if (disabled || !valid || !confirmed || !contextCurrent || !hasRequiredDataPolicy(provider) || (loopback && !localConfirmed)) throw new Error("Review the current provider, purposes, data and limits before authorizing.");
      await prepareProvider();
      return api.authorizeAI({ provider, purposes: [...purposes], data_scope: "reviewed_lab_context", limits: { ...limits }, expires_in_seconds: seconds, approved_by: actor.trim(), usage_authorized: true, local_endpoint_authorized: loopback });
    },
    onSuccess: () => setConfirmed(false),
    onSettled: refresh,
  });
  const revoke = useMutation({ mutationFn: (id: string) => api.revokeAIAuthorization(id), onSettled: refresh });
  const busy = authorize.isPending || revoke.isPending;
  useEffect(() => { onBusy(busy); return () => onBusy(false); }, [busy, onBusy]);
  const changeLimit = (name: keyof AIUsageLimits, value: number) => { setLimits(current => ({ ...current, [name]: value })); setConfirmed(false); };
  return <section aria-label="Model data and usage authorization">
    <h3>Review model data and usage</h3>
    <p>Authorize this exact connection for selected work. Saving or activating its configuration sends no model request and grants no usage permission. Execute effects still require their own approval.</p>
    <DataList items={[
      { label: "Provider and model", value: `${provider.model} · ${provider.id}` },
      { label: "Request endpoint", value: provider.endpoint ?? "Unavailable" },
      { label: "Credential reference", value: provider.api_key?.env ?? "None · loopback only" },
      { label: "Per-attempt limits", value: `${provider.max_output_tokens.toLocaleString()} output tokens · ${provider.timeout_seconds} seconds · ${provider.max_retries} transport retries` },
    ]}/>
    <p><strong>Permitted data: reviewed lab context.</strong> Depending on the selected purpose, requests may include lab objectives and parameters, bounded observation summaries, rule text, and evidence references. Raw logs, evidence bodies and credential values are excluded. Credential fields are redacted. Keep prompts and selected material within this lab scope.</p>
    {!hasRequiredDataPolicy(provider) ? <p role="alert">This configuration does not meet the required redaction policy. Enable credential redaction and exclude evidence bodies before authorizing.</p> : null}
    {!contextCurrent ? <p role="alert">This model connection session is unavailable or expired. Restore the authorized service or lab enrollment, then refresh this review. No new authority is created automatically.</p> : null}
    <fieldset disabled={disabled || busy}><legend>Permitted model work</legend>{Object.entries(modelPurposes).map(([purpose, label]) => <label className="check-row" key={purpose}><input type="checkbox" checked={purposes.includes(purpose as AIModelPurpose)} onChange={event => { setPurposes(current => event.target.checked ? [...current, purpose as AIModelPurpose] : current.filter(item => item !== purpose)); setConfirmed(false); }}/><span>{label}</span></label>)}</fieldset>
    <div className="form-grid">
      <Field label="Total request attempts" hint="1–64, including retries"><input type="number" min={1} max={64} value={limits.max_requests} disabled={disabled || busy} onChange={event => changeLimit("max_requests", Number(event.target.value))}/></Field>
      <Field label="Total request bytes" hint="1–16,777,216 across all attempts"><input type="number" min={1} max={16777216} value={limits.max_request_bytes} disabled={disabled || busy} onChange={event => changeLimit("max_request_bytes", Number(event.target.value))}/></Field>
      <Field label="Total reserved output tokens" hint="64–1,048,576 across all attempts"><input type="number" min={64} max={1048576} value={limits.max_reserved_output_tokens} disabled={disabled || busy} onChange={event => changeLimit("max_reserved_output_tokens", Number(event.target.value))}/></Field>
      <Field label="Authorization duration in seconds" hint="1–900; an earlier lab-session expiry takes precedence"><input type="number" min={1} max={900} value={seconds} disabled={disabled || busy} onChange={event => { setSeconds(Number(event.target.value)); setConfirmed(false); }}/></Field>
    </div>
    <p>Usage is reserved conservatively before each attempt. Failed and cancelled attempts and retries consume the reservation; this is not a bill or an actual-token count. Provider charges may apply. Limits do not renew automatically.</p>
    {loopback ? <label className="check-row"><input type="checkbox" checked={localConfirmed} disabled={disabled || busy} onChange={event => { setLocalConfirmed(event.target.checked); setConfirmed(false); }}/><span>I authorize requests to this loopback endpoint.</span></label> : null}
    <Field label="Operator identity for model usage"><input value={actor} maxLength={128} autoComplete="off" disabled={disabled || busy} onChange={event => { setActor(event.target.value); setConfirmed(false); }}/></Field>
    <label className="check-row"><input type="checkbox" checked={confirmed} disabled={disabled || busy} onChange={event => setConfirmed(event.target.checked)}/><span>I authorize the selected model work, reviewed lab data and these usage limits.</span></label>
    <Button variant="primary" disabled={disabled || busy || !valid || !confirmed || !contextCurrent || !hasRequiredDataPolicy(provider) || (loopback && !localConfirmed)} onClick={() => authorize.mutate()}>{authorize.isPending ? "Saving authorization…" : "Authorize reviewed model usage"}</Button>
    {authorize.isSuccess ? <p role="status">Authorization saved. No model request was sent. Select this provider in Assistant or run setup when ready.</p> : null}
    {authorize.error || revoke.error ? <ErrorState title="Model authorization needs attention" error={authorize.error ?? revoke.error}/> : null}
    {snapshot.authorizations.length ? <details open><summary>Saved model authorizations</summary>{snapshot.authorizations.map(row => {
      const status = authorizationStatus(row, snapshot, now);
      return <article className="detail-body" key={row.authorization_id} aria-label={`Model authorization for ${row.provider.model}`}>
        <div><strong>{row.provider.model}</strong> · {row.provider.id} <Badge tone={status === "active" ? "success" : "neutral"}>{sentence(status)}</Badge></div>
        {!sameJson(row.provider, provider) ? <p>This authorization covers a different configuration from the form above.</p> : null}
        <p>Reviewed by {row.approved_by} · Expires {new Date(row.expires_at_ms).toLocaleString()}</p>
        <p>{row.purposes.map(purpose => modelPurposes[purpose] ?? purpose).join(" · ")}</p>
        <DataList items={[
          { label: "Request attempts remaining", value: Math.max(0, row.limits.max_requests - row.usage.requests) },
          { label: "Request bytes remaining", value: Math.max(0, row.limits.max_request_bytes - row.usage.request_bytes).toLocaleString() },
          { label: "Reserved output tokens remaining", value: Math.max(0, row.limits.max_reserved_output_tokens - row.usage.reserved_output_tokens).toLocaleString() },
        ]}/>
        {status !== "active" ? <p>This authorization cannot send new requests. Remaining counters do not renew its authority.</p> : null}
        {row.status === "active" && row.context.binding_digest === snapshot.context.binding_digest ? <Button size="small" disabled={busy} onClick={() => revoke.mutate(row.authorization_id)}>Revoke model usage for {row.provider.model}</Button> : null}
        <details><summary>Exact authorized connection</summary><p>{row.provider.endpoint} · {row.provider.api_key?.env ?? "No credential reference"}</p><p>Authorization digest: <code>{row.authorization_digest}</code></p></details>
      </article>;
    })}</details> : null}
  </section>;
}
