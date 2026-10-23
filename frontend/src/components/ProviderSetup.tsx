import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { hasRequiredDataPolicy, matchingAuthorization, providerErrors, publicProvider, requiredRedactionKeys } from "../lib/provider-authorization";
import { sameJson } from "../lib/replay-review";
import { providerLabel } from "../lib/provider-presentation";
import type { AIProviderCheck } from "../types";
import { ProviderAuthorizationReview } from "./ProviderAuthorizationReview";
import { ProviderLabLaunch } from "./ProviderLabLaunch";
import { Badge, Button, Callout, DataList, ErrorState, Field, Panel, PanelHeader, sentence } from "./Primitives";
import "./ProviderSetup.css";

type APIStyle = "deterministic" | "openai_responses" | "chat_completions";
const styles: Record<APIStyle, string> = {
  deterministic: "Deterministic · no model calls",
  openai_responses: "Responses API · strict structured output",
  chat_completions: "Chat Completions API · strict structured output",
};
const initial = { id: "provider.local.v1", kind: "openai_responses" as APIStyle, model: "", endpoint: "", env: "", timeout: 30, tokens: 800, retries: 0 };
const presets = {
  openai: { label: "OpenAI Responses", kind: "openai_responses" as APIStyle, endpoint: "https://api.openai.com/v1/responses", env: "OPENAI_API_KEY" },
  loopback: { label: "Loopback Chat Completions", kind: "chat_completions" as APIStyle, endpoint: "http://127.0.0.1:8080/v1/chat/completions", env: "" },
  offline: { label: "Offline deterministic planner", kind: "deterministic" as APIStyle, endpoint: "", env: "" },
};

function destinationLabel(endpoint: string | null): string {
  if (!endpoint) return "Not configured";
  try { return new URL(endpoint).origin; } catch { return "Review the endpoint"; }
}

export function ProviderSetup() {
  const client = useQueryClient();
  const resources = useQuery({ queryKey: ["resources", "model-providers"], queryFn: () => api.resources("model-providers") });
  const authorizations = useQuery({ queryKey: ["ai-authorizations"], queryFn: api.aiAuthorizations, refetchInterval: 5000 });
  const [form, setForm] = useState(initial);
  const [preset, setPreset] = useState("");
  const [extra, setExtra] = useState<Record<string, unknown>>({});
  const [notice, setNotice] = useState("");
  const [noticeFailure, setNoticeFailure] = useState(false);
  const [checked, setCheck] = useState<AIProviderCheck>();
  const [checkedBinding, setCheckedBinding] = useState("");
  const [authorizationBusy, setAuthorizationBusy] = useState(false);
  const [now, setNow] = useState(Date.now);
  useEffect(() => { const timer = window.setInterval(() => setNow(Date.now()), 1000); return () => window.clearInterval(timer); }, []);
  const broker = authorizations.data?.context.kind === "broker";
  const brokerProvider = broker ? authorizations.data?.context.provider : undefined;
  const document = brokerProvider ?? publicProvider({
    ...extra, id: form.id, kind: form.kind, model: form.model,
    endpoint: form.kind === "deterministic" ? null : form.endpoint,
    api_key: form.kind === "deterministic" || !form.env ? null : { env: form.env },
    timeout_seconds: form.timeout, max_retries: form.retries, max_output_tokens: form.tokens,
  });
  const display = brokerProvider ? { id: brokerProvider.id, kind: brokerProvider.kind, model: brokerProvider.model, endpoint: brokerProvider.endpoint ?? "", env: brokerProvider.api_key?.env ?? "", timeout: brokerProvider.timeout_seconds, tokens: brokerProvider.max_output_tokens, retries: brokerProvider.max_retries } : form;
  const reviewBinding = JSON.stringify([document, authorizations.data?.context]);
  const check = checkedBinding === reviewBinding ? checked : undefined;
  const refresh = () => {
    client.invalidateQueries({ queryKey: ["resources", "model-providers"] });
    client.invalidateQueries({ queryKey: ["catalog"] });
    client.invalidateQueries({ queryKey: ["ai-authorizations"] });
  };
  const reportFailure = (error: unknown, fallback: string) => { setNoticeFailure(true); setNotice(error instanceof Error ? error.message : fallback); };
  const save = useMutation({ mutationFn: () => api.saveResource("model-providers", form.id, { ...document }, "draft"), onSuccess: () => { setNoticeFailure(false); setNotice(`${providerLabel(document)} saved. Activation and model usage authorization remain separate.`); refresh(); }, onError: error => reportFailure(error, "Provider save failed.") });
  const probe = useMutation({ mutationFn: (connect: boolean) => api.checkAIProvider(document, connect), onSuccess: result => { setCheck(result); setCheckedBinding(reviewBinding); }, onError: error => reportFailure(error, "Provider check failed."), onSettled: refresh });
  const lifecycle = useMutation({ mutationFn: ({ id, active }: { id: string; active: boolean }) => active ? api.deactivateResource("model-providers", id) : api.activateResource("model-providers", id), onSuccess: ({ resource }) => { setNoticeFailure(false); setNotice(`${providerLabel(resource.document)} is ${resource.status}.`); refresh(); }, onError: error => reportFailure(error, "Provider activation failed.") });
  const update = (values: Partial<typeof form>) => { setForm(current => ({ ...current, ...values })); setPreset(""); setCheck(undefined); setNotice(""); setNoticeFailure(false); };
  const busy = save.isPending || probe.isPending || lifecycle.isPending || authorizationBusy;
  const errors = providerErrors(document);
  const valid = errors.length === 0;
  const stored = resources.data?.resources.find(resource => resource.id === document.id);
  const active = stored?.status === "active";
  const activeChanged = active && !sameJson(publicProvider(stored.document), document);
  const locked = busy || Boolean(broker) || !authorizations.data || authorizations.isError;
  const liveGrant = matchingAuthorization(document, authorizations.isError ? undefined : authorizations.data, now, "bluefire_connection_check");
  const currentUsage = matchingAuthorization(document, authorizations.isError ? undefined : authorizations.data, now);
  const offline = display.kind === "deterministic";
  const savedMatches = stored && sameJson(publicProvider(stored.document), document);
  const configurationLabel = broker ? authorizations.isError ? "Enrollment status unavailable" : !brokerProvider ? "Enrollment unavailable" : (authorizations.data?.context.expires_at_ms ?? Infinity) <= now ? "Enrolled session expired" : "Enrolled connection" : resources.isError ? "Status unavailable" : resources.isPending ? "Checking saved state" : !stored ? "Not saved" : !savedMatches ? "Unsaved changes" : `${sentence(stored.status)} configuration`;
  const usageExpiry = currentUsage ? Math.min(currentUsage.expires_at_ms, authorizations.data?.context.expires_at_ms ?? Infinity) : undefined;
  const liveReady = Boolean(liveGrant && liveGrant.limits.max_reserved_output_tokens - liveGrant.usage.reserved_output_tokens >= Math.min(256, document.max_output_tokens));
  const prepareProvider = async () => {
    if (broker) return;
    if (activeChanged) throw new Error("Deactivate this provider before changing its saved configuration.");
    if (!active) {
      if (!stored || !sameJson(publicProvider(stored.document), document)) await api.saveResource("model-providers", document.id, { ...document }, "draft");
      const result = await api.activateResource("model-providers", document.id);
      if (!sameJson(publicProvider(result.resource.document), document)) throw new Error("The activated provider differs from this review. Reload its configuration and review it again.");
    }
  };
  return <Panel className="provider-workspace"><PanelHeader eyebrow="Provider setup" title="Model connection"/>
    <div className="detail-body provider-workspace-body">
      <section className="provider-summary" aria-label="Selected connection summary">
        <header><div><p className="provider-summary-label">Selected connection</p><h3>{offline ? "Offline deterministic planner" : document.model || "Choose a model"}</h3></div><Badge tone={offline ? "neutral" : "info"}>{offline ? "No model calls" : styles[display.kind].split(" · ")[0]}</Badge></header>
        <dl className="provider-summary-facts">
          <div><dt>Data destination</dt><dd>{offline ? "No network destination" : destinationLabel(document.endpoint)}</dd></div>
          <div><dt>Saved configuration</dt><dd>{configurationLabel}</dd></div>
          <div><dt>Model usage</dt><dd>{offline ? "Not needed for offline planning" : authorizations.isError ? "Authorization status unavailable" : !authorizations.data ? "Checking authorization" : currentUsage ? `Authorized for ${currentUsage.purposes.length} ${currentUsage.purposes.length === 1 ? "purpose" : "purposes"}` : "No current authorization"}</dd></div>
        </dl>
        {!offline && currentUsage ? <div className="provider-usage-summary" aria-label="Current authorization remaining limits"><dl>
          <div><dt>Request attempts left</dt><dd>{Math.max(0, currentUsage.limits.max_requests - currentUsage.usage.requests).toLocaleString()}</dd></div>
          <div><dt>Request bytes left</dt><dd>{Math.max(0, currentUsage.limits.max_request_bytes - currentUsage.usage.request_bytes).toLocaleString()}</dd></div>
          <div><dt>Reserved output tokens left</dt><dd>{Math.max(0, currentUsage.limits.max_reserved_output_tokens - currentUsage.usage.reserved_output_tokens).toLocaleString()}</dd></div>
        </dl><p>Expires <time dateTime={new Date(usageExpiry!).toISOString()}>{new Date(usageExpiry!).toLocaleString()}</time>. Remaining reservations do not guarantee a request fits its limits.</p></div> : null}
        {!offline ? <details className="provider-exact-connection"><summary>Exact destination and data policy</summary><DataList items={[{ label: "Full request endpoint", value: document.endpoint || "Not configured" }, { label: "Credential reference", value: document.api_key?.env || "None configured" }, { label: "Data policy", value: hasRequiredDataPolicy(document) ? "Reviewed lab context; raw evidence bodies excluded; credential fields redacted" : "Needs review before authorization" }]}/></details> : null}
      </section>
      <p className="provider-mode-guidance">{offline ? "Deterministic planning stays local and makes no model calls. It does not demonstrate live inference; no API key or model usage authorization is needed." : broker ? "Review the enrolled model, destination and usage below. This connection is supplied by the lab session." : "Provide the credential through the named environment variable in the process that starts BlueFire, then restart the service. Enter only its name here, never the key value. A loopback endpoint may not require a credential; requests still need explicit authorization."}</p>
      {broker ? <p role="status">This lab uses an enrolled model connection. Its exact configuration is locked for this session; Settings cannot replace it. If it is wrong or expired, restore the authorized lab enrollment and refresh this page.</p> : null}
      {broker && !brokerProvider ? <p role="alert">The enrolled connection is unavailable. Restore the authorized lab enrollment before continuing.</p> : null}
      {authorizations.isPending ? <p role="status">Checking model authorization context…</p> : null}
      {authorizations.isError ? <ErrorState title="Model authorization context is unavailable" error={authorizations.error} retry={() => authorizations.refetch()}/> : null}
      {notice ? noticeFailure ? <Callout tone="warning" title="Provider setup needs attention">{notice}</Callout> : <p role="status">{notice}</p> : null}
      {!broker ? <Field label="Connection preset" className="provider-preset" hint="Optional starting values for API style, endpoint and credential reference. The connection identity and request limits stay unchanged."><select value={preset} disabled={locked} onChange={event => {
        const selected = event.target.value as keyof typeof presets;
        if (!selected) { setPreset(""); return; }
        const values = presets[selected];
        update({ kind: values.kind, endpoint: values.endpoint, env: values.env, model: values.kind === "deterministic" ? "deterministic-planner.v1" : form.kind === "deterministic" ? "" : form.model });
        setPreset(selected);
      }}><option value="">Custom connection</option>{Object.entries(presets).map(([id, value]) => <option key={id} value={id}>{value.label}</option>)}</select></Field> : null}
      <div className="provider-connection-fields">
      <Field label="API style"><select value={display.kind} disabled={locked} onChange={event => update({ kind: event.target.value as APIStyle, model: event.target.value === "deterministic" ? "deterministic-planner.v1" : "", endpoint: "", env: "" })}>{Object.entries(styles).map(([kind, label]) => <option key={kind} value={kind}>{label}</option>)}</select></Field>
      <Field label={display.kind === "deterministic" ? "Model label" : "Model ID"} hint={offline ? "A label for the local deterministic planner, not a remote model." : "Use the exact model ID supported by your endpoint; no aliases or provider substitution are applied."}><input value={display.model} disabled={locked} onChange={event => update({ model: event.target.value })} maxLength={200}/></Field>
      {display.kind !== "deterministic" ? <>
        <Field label="Request endpoint" hint="Full POST URL, including its API path. HTTPS required except for loopback. No path is appended automatically."><input type="url" value={display.endpoint} disabled={locked} onChange={event => update({ endpoint: event.target.value })} placeholder={display.kind === "openai_responses" ? "https://provider.example/v1/responses" : "http://127.0.0.1:8080/v1/chat/completions"} autoComplete="off"/></Field>
        <Field label="Secret environment reference" hint="Enter only the uppercase server environment variable name, never the key value. Leave blank only for a loopback endpoint without authentication."><input value={display.env} disabled={locked} onChange={event => update({ env: event.target.value })} placeholder="MODEL_API_KEY" pattern="[A-Z][A-Z0-9_]*" autoComplete="off" spellCheck={false}/></Field>
        <p className="field-note provider-field-wide">The endpoint must support the selected strict JSON schema format. Native vendor protocols and text-only compatible endpoints are not supported by these adapters. A loopback address does not identify a test provider.</p>
        <details className="provider-field-wide provider-request-limits"><summary>Request limits</summary><div className="provider-request-limit-fields">
          <Field label="Timeout seconds"><input type="number" min={1} max={300} value={display.timeout} disabled={locked} onChange={event => update({ timeout: Number(event.target.value) })}/></Field>
          <Field label="Output token limit" hint="Includes reasoning tokens. An incomplete response is reported explicitly; the runtime does not increase this limit."><input type="number" min={64} max={16384} value={display.tokens} disabled={locked} onChange={event => update({ tokens: Number(event.target.value) })}/></Field>
          <Field label="Transport retries"><input type="number" min={0} max={5} value={display.retries} disabled={locked} onChange={event => update({ retries: Number(event.target.value) })}/></Field>
        </div></details>
      </> : null}
      <details className="provider-field-wide"><summary>Connection identity</summary><Field label="Provider ID" hint="A default identity is already supplied. This stable reference binds saved configuration and usage authorization; change it only when storing a separate connection."><input value={display.id} disabled={locked} onChange={event => update({ id: event.target.value })} maxLength={200}/></Field></details>
      </div>
      {active && !broker ? <p>Deactivate this provider below before editing its saved configuration. Activation alone never grants permission for model requests.</p> : null}
      {!valid && (display.model || display.endpoint || display.env) ? <ul aria-label="Provider configuration corrections">{errors.map(error => <li key={error}>{error}</li>)}</ul> : null}
      {!broker && !hasRequiredDataPolicy(document) ? <p>The saved configuration permits broader data than this review allows. <Button disabled={locked} onClick={() => { setExtra(current => ({ ...current, redaction: { ...document.redaction, enabled: true, include_evidence_content: false, redact_keys: [...new Set([...requiredRedactionKeys, ...document.redaction.redact_keys])] } })); setCheck(undefined); }}>Use required data protection</Button></p> : null}
      <div className="button-row">{!broker ? <Button onClick={() => save.mutate()} disabled={locked || !valid || active}>Save secret-free draft</Button> : null}<Button onClick={() => { setNotice(""); setCheck(undefined); probe.mutate(false); }} disabled={busy || !valid || Boolean(broker && !brokerProvider)}>Check configuration</Button></div>
      {display.kind !== "deterministic" ? <>
        <ProviderLabLaunch provider={document} enrolled={Boolean(broker)} disabled={busy || !valid || !authorizations.data || authorizations.isError || Boolean(broker && !brokerProvider)}/>
        {authorizations.data ? <ProviderAuthorizationReview key={reviewBinding} provider={document} snapshot={authorizations.data} snapshotAvailable={!authorizations.isError} now={now} disabled={busy && !authorizationBusy || !valid || authorizations.isError || resources.isError || resources.isPending || Boolean(activeChanged && !broker) || Boolean(broker && !brokerProvider)} prepareProvider={prepareProvider} onBusy={setAuthorizationBusy} refresh={refresh}/> : null}
        <Button onClick={() => { if (liveReady) { setNotice(""); setCheck(undefined); probe.mutate(true); } }} disabled={busy || !valid || !liveReady}>{probe.isPending ? "Checking provider…" : "Send live connection test"}</Button><p className="field-note">Requires current authorization for the synthetic connection test. Sends one synthetic request using this configuration. It may incur API cost. No scenario or evidence is sent. No retries or fallback; at most 256 output tokens and a 10-second request timeout. Passing this test proves connection compatibility only.</p>
      </> : null}
      {check ? <Callout title={check.code === "probe_passed" ? "Live structured-output test passed" : check.code === "configuration_ready" ? "Configuration checked · connection untested" : sentence(check.code)} tone={check.code === "probe_passed" ? "success" : check.code === "configuration_ready" || check.code === "deterministic_no_network" ? "info" : "warning"}><p>{check.message}</p>
        {check.code.startsWith("broker_") ? <p>Restore the exact enrolled lab connection before checking credentials or authorizing usage. A broker failure does not establish that the named environment variable is missing.</p> : check.code === "credential_unavailable" ? <p>{broker ? "Provide the named environment variable to the host launcher, then restart the existing lab session with the same public connection definition." : "Provide the named environment variable to the process that starts this service, then restart it."} Review model usage after restarting; never enter the credential value here.</p> : null}
        {check.response_model ? <p>Endpoint-reported model: <code>{check.response_model}</code></p> : null}<DataList items={[{ label: "Credential reference", value: check.code.startsWith("broker_") ? "Not checked · restore enrolled connection" : sentence(check.credential_state) }, { label: "Model usage", value: !authorizations.data || authorizations.isError ? "Not checked" : currentUsage ? "Active for selected work" : "Review required" }, { label: "Connection", value: sentence(check.connectivity) }, { label: "Structured output", value: sentence(check.structured_output) }, { label: "Requests sent", value: check.attempts }]}/></Callout> : null}
      {resources.isError ? <ErrorState error={resources.error} retry={() => resources.refetch()}/> : null}
      {resources.data?.resources.length ? <section className="provider-saved-connections" aria-label="Saved model connections"><h3>Saved connections</h3>{resources.data.resources.map(resource => <article className="provider-saved-connection" key={resource.id}><div><strong>{providerLabel(resource.document)}</strong><p>{publicProvider(resource.document).kind === "deterministic" ? "Offline; no network requests" : destinationLabel(publicProvider(resource.document).endpoint)}</p>{resources.isError ? <p>Last reported status: {sentence(resource.status)}. Current saved state is unavailable.</p> : null}<details><summary>Connection identity</summary><code>{resource.id}</code></details></div><div className="row-badges"><Badge>{resources.isError ? "Last reported" : sentence(resource.status)}</Badge><Button size="small" aria-label={`Edit ${providerLabel(resource.document)}`} disabled={locked || resources.isError} onClick={() => {
        const source = (resource.document.config && typeof resource.document.config === "object" ? resource.document.config : resource.document) as Record<string, unknown>;
        const key = source.api_key as { env?: string } | null;
        setExtra(source); setForm({ id: resource.id, kind: source.kind as APIStyle, model: String(source.model ?? ""), endpoint: String(source.endpoint ?? ""), env: key?.env ?? "", timeout: Number(source.timeout_seconds ?? 30), tokens: Number(source.max_output_tokens ?? 800), retries: Number(source.max_retries ?? 0) }); setPreset(""); setCheck(undefined); setNoticeFailure(false); setNotice(`Editing ${providerLabel(source)}.`);
      }}>Edit</Button><Button size="small" disabled={locked || resources.isError} onClick={() => lifecycle.mutate({ id: resource.id, active: resource.status === "active" })}>{resource.status === "active" ? "Deactivate" : "Activate"}</Button></div></article>)}</section> : null}
    </div>
  </Panel>;
}
