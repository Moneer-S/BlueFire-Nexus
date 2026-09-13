import { useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api, DEMO_MODE } from "../lib/api";
import { checkedReceiverContext } from "../lib/receiver-defense";
import { runIntent } from "../lib/run-assistance";
import { sameJson } from "../lib/replay-review";
import { readReceiverConfiguration, readReceiverSelection, rememberReceiverConfiguration, rememberReceiverSelection } from "../lib/receiver-setup";
import type { ReceiverContextRequest } from "../lib/receiver-defense-types";
import { useAssistancePanel, usePublishReceiverSelection } from "../state/AssistanceContext";
import { validReceiverAssistanceSelection, type ReceiverAssistanceSelection } from "../lib/receiver-assistance";
import { useProduct } from "../state/ProductContext";
import type { CatalogResponse, RunConfiguration, ScenarioVersion } from "../types";
import { RunConfigurationPanel } from "./RunConfiguration";
import { ExecuteRunnerReadiness } from "./ExecuteRunnerReadiness";
import { savedExperimentPath } from "../lib/receiver-navigation";
import { Button, Callout, ErrorState, Field, LoadingState } from "./Primitives";

type StartRequest = ReceiverContextRequest & { submission_id: string; context_digest: string };
export function ReceiverTestSetup({ disabled, onStart }: { disabled: boolean; onStart: (body: StartRequest) => void }) {
  const catalog = useQuery({ queryKey: ["catalog"], queryFn: api.catalog });
  const versions = useQuery({ queryKey: ["scenario-versions"], queryFn: api.scenarioVersions });
  const [selected, setSelected] = useState(readReceiverSelection);
  const [storageError, setStorageError] = useState<unknown>();
  const saved = versions.data?.scenarios.find((item) => `${item.scenario_id}:${item.version}:${item.digest}` === selected);
  if (DEMO_MODE) return <Callout title="An owned Linux lab is required">This test changes a real receiver policy. Open the installed product with a prepared disposable lab.</Callout>;
  if (catalog.error || versions.error) return <ErrorState error={catalog.error ?? versions.error} retry={() => { void catalog.refetch(); void versions.refetch(); }} />;
  if (!catalog.data || !versions.data) return <LoadingState label="Loading saved experiments" />;
  return <section aria-label="Set up receiver control test" className="receiver-setup">
    <h2>New control test</h2>
    <Field label="Saved experiment" hint="Choose an immutable version with a JSONL staging step connected to a peer handoff."><select value={selected} onChange={(event) => { setSelected(event.target.value); try { rememberReceiverSelection(event.target.value); setStorageError(undefined); } catch (error) { setStorageError(error); } }}><option value="">Choose a saved experiment</option>{versions.data.scenarios.map((item) => <option key={`${item.scenario_id}:${item.version}:${item.digest}`} value={`${item.scenario_id}:${item.version}:${item.digest}`}>{item.title} · version {item.version}</option>)}</select></Field>
    {storageError ? <ErrorState title="Selection is only available on this page" error={storageError} /> : null}
    {selected && !saved ? <p>The previously selected version is no longer in this list. Choose an available saved version to check its current eligibility.</p> : null}
    {!versions.data.scenarios.length ? <p>Save an experiment in <Link to="/builder">Build</Link> to select it here.</p> : null}
    <details className="receiver-test-help"><summary>How the three phases work</summary><p>Run the same saved experiment with a receiver that accepts reviewed synthetic records, a receiver that requires redaction, then the original policy restored. Each phase uses a fresh, short-lived receiver in your owned lab and requires its own run approval.</p><p>This measures the local receiver policy. It does not establish external security-system prevention or detection coverage.</p></details>
    {saved ? <ReceiverConfiguration key={selected} saved={saved} catalog={catalog.data} disabled={disabled} onStart={onStart} /> : null}
  </section>;
}

function ReceiverConfiguration({ saved, catalog, disabled, onStart }: { saved: ScenarioVersion; catalog: CatalogResponse; disabled: boolean; onStart: (body: StartRequest) => void }) {
  const { runConfig } = useProduct();
  const setupKey = `${saved.scenario_id}:${saved.version}:${saved.digest}`;
  const [config, setConfig] = useState<RunConfiguration>(() => readReceiverConfiguration(setupKey, { ...structuredClone(runConfig), autonomy: "off", provider: "", actionImplementations: {}, approved: false, approvedBy: "" }));
  const [storageError, setStorageError] = useState<unknown>();
  useEffect(() => { try { rememberReceiverConfiguration(setupKey, config); setStorageError(undefined); } catch (error) { setStorageError(error); } }, [setupKey, config]);
  const request = useMemo<ReceiverContextRequest>(() => ({ selection: { kind: "saved_scenario", scenario_id: saved.scenario_id, version: saved.version, digest: saved.digest }, run_intent: runIntent(config) }), [saved, config]);
  const assistant = useAssistancePanel();
  const assistantSelection = useMemo<ReceiverAssistanceSelection | undefined>(() => { const value = { kind: "receiver_scenario" as const, ...request }; return validReceiverAssistanceSelection(value) ? value : undefined; }, [request]);
  usePublishReceiverSelection(disabled ? undefined : assistantSelection, saved.title);
  const context = useQuery({ queryKey: ["receiver-context", request], queryFn: async () => checkedReceiverContext(await api.receiverContext(request), request), retry: false });
  const ready = context.data?.eligible && context.data.availability.supported && context.data.availability.ready;
  const scopeRefused = context.data?.reasons.some((item) => ["receiver_scope_required", "scope_required"].includes(item.code));
  return <>
    <p><Link to={savedExperimentPath(saved)}>Inspect the selected saved experiment</Link></p>
    {storageError ? <ErrorState title="Settings are only available on this page" error={storageError} /> : null}
    <details className="receiver-settings" open><summary>Environment and run settings</summary><RunConfigurationPanel scenario={saved.document} config={config} catalog={catalog} assistedSetup runtimeLockedOff onChange={(next) => setConfig({ ...next, autonomy: "off", provider: "", approved: false, approvedBy: "" })} /></details>
    {context.isPending ? <LoadingState label="Checking this experiment and environment" /> : context.error ? <ErrorState title="Experiment check unavailable" error={context.error} retry={() => { void context.refetch(); }} /> : context.data ? <>
      {!context.data.eligible ? <Callout title="This experiment cannot test the receiver control"><ul>{context.data.reasons.map((item) => <li key={item.code}>{item.message}</li>)}</ul>{context.data.reasons.some((item) => ["receiver_graph_ineligible", "cleanup_required", "handoff_cleanup_required"].includes(item.code)) ? <Link to={savedExperimentPath(saved)}>Review the experiment in Build</Link> : null}</Callout> : null}
      {!context.data.availability.ready && !scopeRefused ? <><Callout title={context.data.availability.supported ? "Prepare the lab first" : "This environment is unsupported"}><p>{context.data.availability.reason}</p>{!context.data.availability.supported ? <Link to="/getting-started">Open installation and lab guidance</Link> : null}<Button onClick={() => { void context.refetch(); }}>Check readiness again</Button></Callout>{context.data.availability.supported && config.mode === "execute" ? <ExecuteRunnerReadiness profileId={config.profileId || undefined} /> : null}</> : null}
      {context.data.limitations.length ? <details><summary>Supported scope and limitations</summary><ul>{context.data.limitations.map((item, index) => <li key={index}>{item}</li>)}</ul></details> : null}
      <p>Save the test to retain its experiment and settings. The next step prepares the receiver; experiment actions require a separate run approval.</p>
      <Button variant="primary" disabled={disabled || !ready || context.isFetching} onClick={() => {
        if (!context.data || !sameJson(context.data.selection, request.selection) || !sameJson(context.data.run_intent, request.run_intent)) return;
        onStart({ ...request, submission_id: crypto.randomUUID(), context_digest: context.data.context_digest });
      }}>Save control test</Button>
      {assistant ? <div className="receiver-assistant-entry"><Button disabled={disabled || !assistantSelection || !context.data.eligible || context.isFetching} onClick={() => assistant.setOpen(true)}>Coordinate with Assistant</Button><p>Uses these settings and interprets the recorded phases. Receiver preparation and each Execute approval remain yours.</p></div> : null}
    </> : null}
  </>;
}
