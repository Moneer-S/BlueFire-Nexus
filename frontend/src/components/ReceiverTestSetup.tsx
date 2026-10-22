import { useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { Link, useLocation, useSearchParams } from "react-router-dom";
import { ArrowRight } from "lucide-react";
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
import { receiverSetupSelectionFromSearch, savedExperimentPath, type ReceiverScenarioSetupSelection } from "../lib/receiver-navigation";
import { Button, Callout, ErrorState, Field, LoadingState } from "./Primitives";

type StartRequest = ReceiverContextRequest & { submission_id: string; context_digest: string };
const receiverStarterId = "scenario.receiver-defense.redaction-validation.v1";
const receiverStarterTitle = "Validate receiver redaction and legitimate use";
export function ReceiverTestSetup(props: { disabled: boolean; onStart: (body: StartRequest) => void }) {
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const routeSelection = receiverSetupSelectionFromSearch(searchParams);
  const routeKey = routeSelection.present ? `${location.key}:${searchParams.get("receiver_setup") ?? "invalid"}` : "session";
  const [storedSelection, setStoredSelection] = useState(readReceiverSelection);
  const [storageError, setStorageError] = useState<unknown>();
  return <ReceiverTestSetupForm key={routeKey} {...props} storedSelection={storedSelection} setStoredSelection={setStoredSelection} storageError={storageError} setStorageError={setStorageError} />;
}

function ReceiverTestSetupForm({ disabled, onStart, storedSelection, setStoredSelection, storageError, setStorageError }: { disabled: boolean; onStart: (body: StartRequest) => void; storedSelection: string; setStoredSelection: (value: string) => void; storageError?: unknown; setStorageError: (value: unknown) => void }) {
  const catalog = useQuery({ queryKey: ["catalog"], queryFn: api.catalog });
  const versions = useQuery({ queryKey: ["scenario-versions"], queryFn: api.scenarioVersions });
  const [searchParams, setSearchParams] = useSearchParams();
  const routeSelection = useMemo(() => receiverSetupSelectionFromSearch(searchParams), [searchParams]);
  const selected = routeSelection.present
    ? routeSelection.setup ? `${routeSelection.setup.selection.scenario_id}:${routeSelection.setup.selection.version}:${routeSelection.setup.selection.digest}` : ""
    : storedSelection;
  const [workflow, setWorkflow] = useState<'comparison' | 'retained_redaction'>('comparison');
  const saved = versions.data?.scenarios.find((item) => `${item.scenario_id}:${item.version}:${item.digest}` === selected);
  if (DEMO_MODE) return <Callout title="An owned Linux lab is required">This test changes a real receiver policy. Open the installed product with a prepared disposable lab.</Callout>;
  if (catalog.error || versions.error) return <ErrorState error={catalog.error ?? versions.error} retry={() => { void catalog.refetch(); void versions.refetch(); }} />;
  if (!catalog.data || !versions.data) return <LoadingState label="Loading saved experiments" />;
  return <section aria-label="Set up receiver control test" className="receiver-setup">
    <h2>New control test</h2>
    <fieldset className="receiver-workflow"><legend>Policy outcome</legend><label><input type="radio" name="receiver-workflow" value="comparison" checked={workflow === "comparison"} disabled={disabled} onChange={() => setWorkflow("comparison")} /> Compare and restore prior policy</label><label><input type="radio" name="receiver-workflow" value="retained_redaction" checked={workflow === "retained_redaction"} disabled={disabled} onChange={() => setWorkflow("retained_redaction")} /> Retain redaction and verify legitimate use</label></fieldset>
    <Field label="Saved experiment" hint="Choose an immutable version with a JSONL staging step connected to a peer handoff."><select value={selected} onChange={(event) => { const nextSelection = event.target.value; setStoredSelection(nextSelection); const nextParams = new URLSearchParams(searchParams); nextParams.delete("receiver_setup"); nextParams.delete("saved_scenario"); nextParams.delete("version"); nextParams.delete("digest"); setSearchParams(nextParams, { replace: true }); try { rememberReceiverSelection(nextSelection); setStorageError(undefined); } catch (error) { setStorageError(error); } }}><option value="">Choose a saved experiment</option>{versions.data.scenarios.map((item) => <option key={`${item.scenario_id}:${item.version}:${item.digest}`} value={`${item.scenario_id}:${item.version}:${item.digest}`}>{item.title} · version {item.version}</option>)}</select></Field>
    <Link className="button button-secondary button-small receiver-starter-link" to={`/scenarios?${new URLSearchParams({ selected: receiverStarterId, view: "packaged" })}`}><ArrowRight aria-hidden="true"/> Open “{receiverStarterTitle}”</Link>
    {storageError ? <ErrorState title="Selection is only available on this page" error={storageError} /> : null}
    {routeSelection.invalid ? <Callout tone="warning" title="Saved experiment selection unavailable">The exact saved version link is invalid. Choose an available saved version to continue.</Callout> : routeSelection.present && selected && !saved ? <Callout tone="warning" title="Saved experiment version unavailable">That exact saved version is no longer available. Choose an available version; no receiver check was started.</Callout> : selected && !saved ? <p>The previously selected version is no longer in this list. Choose an available saved version to check its current eligibility.</p> : null}
    {!versions.data.scenarios.length ? <p>Save an experiment in <Link to="/builder">Build</Link> to select it here.</p> : null}
    <details className="receiver-test-help"><summary>How the three phases work</summary><p>{workflow === "retained_redaction" ? "Establish the permissive baseline, test the original staged bytes against redaction, then verify acceptance of explicitly redacted records. Retain the redaction policy for this saved control test and its linked fresh retests after receivers shut down. Independently created tests do not inherit it." : "Run the same saved experiment with a receiver that accepts reviewed synthetic records, a receiver that requires redaction, then the original policy restored."} Each phase uses a fresh, short-lived receiver in your owned lab and requires its own run approval.</p><p>This measures the local receiver policy. It does not establish external security-system prevention or detection coverage.</p></details>
    {saved ? <ReceiverConfiguration key={`${selected}:${routeSelection.setup ? JSON.stringify(routeSelection.setup.run_intent) : "session"}`} saved={saved} catalog={catalog.data} workflow={workflow} disabled={disabled} onStart={onStart} restoredRunIntent={routeSelection.setup?.run_intent} /> : null}
  </section>;
}

function configFromIntent(intent: ReceiverScenarioSetupSelection["run_intent"], defaults: RunConfiguration): RunConfiguration {
  return {
    ...defaults,
    mode: intent.mode,
    autonomy: "off",
    provider: "",
    profileId: intent.runner_profile_id ?? "",
    scopeRefs: [...intent.target_scope.scope_refs],
    collectors: intent.collectors ? [...intent.collectors] : defaults.collectors,
    actionImplementations: intent.action_implementations ? { ...intent.action_implementations } : {},
    approved: false,
    approvedBy: "",
  };
}

function ReceiverConfiguration({ saved, catalog, workflow, disabled, onStart, restoredRunIntent }: { saved: ScenarioVersion; catalog: CatalogResponse; workflow: 'comparison' | 'retained_redaction'; disabled: boolean; onStart: (body: StartRequest) => void; restoredRunIntent?: ReceiverScenarioSetupSelection["run_intent"] }) {
  const { runConfig } = useProduct();
  const setupKey = `${saved.scenario_id}:${saved.version}:${saved.digest}`;
  const [config, setConfig] = useState<RunConfiguration>(() => restoredRunIntent
    ? configFromIntent(restoredRunIntent, runConfig)
    : readReceiverConfiguration(setupKey, { ...structuredClone(runConfig), autonomy: "off", provider: "", actionImplementations: {}, approved: false, approvedBy: "" }));
  const [storageError, setStorageError] = useState<unknown>();
  useEffect(() => { try { rememberReceiverConfiguration(setupKey, config); setStorageError(undefined); } catch (error) { setStorageError(error); } }, [setupKey, config]);
  const request = useMemo<ReceiverContextRequest>(() => ({ selection: { kind: "saved_scenario", scenario_id: saved.scenario_id, version: saved.version, digest: saved.digest }, run_intent: runIntent(config), ...(workflow === "retained_redaction" ? { workflow } : {}) }), [saved, config, workflow]);
  const assistant = useAssistancePanel();
  const assistantSelection = useMemo<ReceiverAssistanceSelection | undefined>(() => { if (workflow === "retained_redaction") return undefined; const value = { kind: "receiver_scenario" as const, ...request }; return validReceiverAssistanceSelection(value) ? value : undefined; }, [request, workflow]);
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
      {assistant && workflow === "comparison" ? <div className="receiver-assistant-entry"><Button disabled={disabled || !assistantSelection || !context.data.eligible || context.isFetching} onClick={() => assistant.setOpen(true)}>Coordinate with Assistant</Button><p>Uses these settings and interprets the recorded phases. Receiver preparation and each Execute approval remain yours.</p></div> : null}
    </> : null}
  </>;
}
