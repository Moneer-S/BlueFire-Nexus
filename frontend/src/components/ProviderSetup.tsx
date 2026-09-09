import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "../lib/api";
import type { AIProviderCheck } from "../types";
import { Badge, Button, Callout, DataList, ErrorState, Field, Panel, PanelHeader, sentence } from "./Primitives";

type APIStyle = "deterministic" | "openai_responses" | "chat_completions";
const styles: Record<APIStyle, string> = {
  deterministic: "Deterministic · no model calls",
  openai_responses: "Responses API · strict structured output",
  chat_completions: "Chat Completions API · strict structured output",
};
const initial = { id: "provider.local.v1", kind: "openai_responses" as APIStyle, model: "", endpoint: "", env: "", timeout: 30, tokens: 800, retries: 0 };

export function ProviderSetup() {
  const client = useQueryClient();
  const resources = useQuery({ queryKey: ["resources", "model-providers"], queryFn: () => api.resources("model-providers") });
  const [form, setForm] = useState(initial);
  const [extra, setExtra] = useState<Record<string, unknown>>({});
  const [notice, setNotice] = useState("");
  const [check, setCheck] = useState<AIProviderCheck>();
  const document = () => ({
    ...extra, id: form.id, kind: form.kind, model: form.model,
    endpoint: form.kind === "deterministic" ? null : form.endpoint,
    api_key: form.kind === "deterministic" || !form.env ? null : { env: form.env },
    timeout_seconds: form.timeout, max_retries: form.retries, max_output_tokens: form.tokens,
  });
  const refresh = () => {
    client.invalidateQueries({ queryKey: ["resources", "model-providers"] });
    client.invalidateQueries({ queryKey: ["catalog"] });
  };
  const save = useMutation({ mutationFn: () => api.saveResource("model-providers", form.id, document(), "draft"), onSuccess: () => { setNotice(`${form.id} saved. Activate it below to select it for the runtime.`); refresh(); }, onError: error => setNotice(error instanceof Error ? error.message : "Provider save failed.") });
  const probe = useMutation({ mutationFn: (connect: boolean) => api.checkAIProvider(document(), connect), onSuccess: result => setCheck(result), onError: error => setNotice(error instanceof Error ? error.message : "Provider check failed.") });
  const lifecycle = useMutation({ mutationFn: ({ id, active }: { id: string; active: boolean }) => active ? api.deactivateResource("model-providers", id) : api.activateResource("model-providers", id), onSuccess: ({ resource }) => { setNotice(`${resource.id} is ${resource.status}.`); refresh(); }, onError: error => setNotice(error instanceof Error ? error.message : "Provider activation failed.") });
  const update = (values: Partial<typeof form>) => { setForm(current => ({ ...current, ...values })); setCheck(undefined); setNotice(""); };
  const busy = save.isPending || probe.isPending || lifecycle.isPending;
  const valid = Boolean(form.id.trim() && form.model.trim() && (form.kind === "deterministic" || form.endpoint.trim()));
  const active = resources.data?.resources.some(resource => resource.id === form.id && resource.status === "active");
  return <Panel><PanelHeader eyebrow="Provider setup" title="Connect a model" detail="Use a supported API endpoint and a secret environment variable available to the BlueFire service."/>
    <div className="detail-body">
      <p>Set the API key in the environment of the process that starts BlueFire, then restart the service. Enter that variable’s name below. Save the configuration, check it, and activate it before selecting the provider in Assistant or run setup.</p>
      {notice ? <Callout title="Provider setup">{notice}</Callout> : null}
      <Field label="Provider ID"><input value={form.id} disabled={busy} onChange={event => update({ id: event.target.value })} placeholder="provider.local.v1" maxLength={200}/></Field>
      <Field label="API style"><select value={form.kind} disabled={busy} onChange={event => update({ kind: event.target.value as APIStyle, model: event.target.value === "deterministic" ? "deterministic-planner.v1" : "", endpoint: "", env: "" })}>{Object.entries(styles).map(([kind, label]) => <option key={kind} value={kind}>{label}</option>)}</select></Field>
      <Field label={form.kind === "deterministic" ? "Model label" : "Model ID"} hint="Use the exact model ID supported by your endpoint; no aliases or provider substitution are applied."><input value={form.model} disabled={busy} onChange={event => update({ model: event.target.value })} maxLength={200}/></Field>
      {form.kind !== "deterministic" ? <>
        <Field label="Request endpoint" hint="Full POST URL, including its API path. HTTPS required except for loopback. No path is appended automatically."><input type="url" value={form.endpoint} disabled={busy} onChange={event => update({ endpoint: event.target.value })} placeholder={form.kind === "openai_responses" ? "https://provider.example/v1/responses" : "http://127.0.0.1:8080/v1/chat/completions"} autoComplete="off"/></Field>
        <Field label="Secret environment reference" hint="Enter only the server environment variable name, never the key value. Leave blank only for a loopback endpoint without authentication."><input value={form.env} disabled={busy} onChange={event => update({ env: event.target.value })} placeholder="MODEL_API_KEY" pattern="[A-Za-z_][A-Za-z0-9_]*" autoComplete="off" spellCheck={false}/></Field>
        <p className="field-note">The endpoint must support the selected strict JSON schema format. Native vendor protocols and text-only compatible endpoints are not supported by these adapters.</p>
        <details><summary>Request limits</summary>
          <Field label="Timeout seconds"><input type="number" min={1} max={300} value={form.timeout} disabled={busy} onChange={event => update({ timeout: Number(event.target.value) })}/></Field>
          <Field label="Output token limit" hint="Includes reasoning tokens. An incomplete response is reported explicitly; the runtime does not increase this limit."><input type="number" min={64} max={16384} value={form.tokens} disabled={busy} onChange={event => update({ tokens: Number(event.target.value) })}/></Field>
          <Field label="Transport retries"><input type="number" min={0} max={5} value={form.retries} disabled={busy} onChange={event => update({ retries: Number(event.target.value) })}/></Field>
        </details>
      </> : null}
      {active ? <Callout title="Active provider">Deactivate this provider below before editing its saved configuration.</Callout> : null}
      <div className="button-row"><Button onClick={() => save.mutate()} disabled={busy || !valid || active}>Save secret-free draft</Button><Button onClick={() => { setNotice(""); setCheck(undefined); probe.mutate(false); }} disabled={busy || !valid}>Check configuration</Button></div>
      {form.kind !== "deterministic" ? <><Button onClick={() => { setNotice(""); setCheck(undefined); probe.mutate(true); }} disabled={busy || !valid}>{probe.isPending ? "Checking provider…" : "Send live connection test"}</Button><p className="field-note">Sends one synthetic request using this configuration. It may incur API cost. No scenario or evidence is sent. No retries or fallback; at most 256 output tokens and a 10-second request timeout.</p></> : null}
      {check ? <Callout title={check.code === "probe_passed" ? "Live structured-output test passed" : check.code === "configuration_ready" ? "Configuration checked · connection untested" : sentence(check.code)} tone={check.code === "probe_passed" ? "success" : check.code === "configuration_ready" || check.code === "deterministic_no_network" ? "info" : "warning"}><p>{check.message}</p>{check.response_model ? <p>Endpoint-reported model: <code>{check.response_model}</code></p> : null}<DataList items={[{ label: "Credential reference", value: sentence(check.credential_state) }, { label: "Connection", value: sentence(check.connectivity) }, { label: "Structured output", value: sentence(check.structured_output) }, { label: "Requests sent", value: check.attempts }]}/></Callout> : null}
      {resources.isError ? <ErrorState error={resources.error} retry={() => resources.refetch()}/> : null}
      {resources.data?.resources.map(resource => <article className="secret-row" key={resource.id}><div><strong>{resource.id}</strong><small>{String(resource.document.kind ?? "Provider")} · {String(resource.document.model ?? "")}</small></div><div className="row-badges"><Badge>{sentence(resource.status)}</Badge><Button size="small" disabled={busy} onClick={() => {
        const source = (resource.document.config && typeof resource.document.config === "object" ? resource.document.config : resource.document) as Record<string, unknown>;
        const key = source.api_key as { env?: string } | null;
        setExtra(source); setForm({ id: resource.id, kind: source.kind as APIStyle, model: String(source.model ?? ""), endpoint: String(source.endpoint ?? ""), env: key?.env ?? "", timeout: Number(source.timeout_seconds ?? 30), tokens: Number(source.max_output_tokens ?? 800), retries: Number(source.max_retries ?? 0) }); setCheck(undefined); setNotice(`Editing ${resource.id}.`);
      }}>Edit {resource.id}</Button><Button size="small" disabled={busy} onClick={() => lifecycle.mutate({ id: resource.id, active: resource.status === "active" })}>{resource.status === "active" ? "Deactivate" : "Activate"}</Button></div></article>)}
    </div>
  </Panel>;
}
