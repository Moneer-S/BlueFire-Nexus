import type { SavedGraphSelection } from "../lib/run-assistance";
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type PropsWithChildren } from "react";
import type { GraphSelection } from "../lib/assistance";

export interface AssistanceSelection {
  runId: string;
  candidateId: string;
  resourceDigest: string;
  title: string;
  manualEdits: boolean;
}
interface SelectionContext {
  selection?: AssistanceSelection | GraphWorkspaceSelection | SavedGraphWorkspaceSelection;
  publish: (owner: symbol, value?: AssistanceSelection | GraphWorkspaceSelection | SavedGraphWorkspaceSelection) => void;
  requestedJobId?: string;
  openJob: (jobId: string) => void;
  finishOpenJob: () => void;
  open: boolean;
  setOpen: (value: boolean) => void;
}
export interface SavedGraphWorkspaceSelection { kind: "saved_graph"; selected: SavedGraphSelection; title: string; manualEdits: false }
export interface GraphWorkspaceSelection { kind: "graph"; baseScenario: GraphSelection["base_scenario"]; title: string; manualEdits: boolean }
const Context = createContext<SelectionContext | null>(null);

export function AssistanceProvider({ children }: PropsWithChildren) {
  const [open, setOpen] = useState(false);
  const [requestedJobId, setRequestedJobId] = useState<string>();
  const openJob = useCallback((jobId: string) => { setRequestedJobId(jobId); setOpen(true); }, []);
  const finishOpenJob = useCallback(() => setRequestedJobId(undefined), []);
  const [current, setCurrent] = useState<{ owner: symbol; value: AssistanceSelection | GraphWorkspaceSelection | SavedGraphWorkspaceSelection }>();
  const publish = useCallback((owner: symbol, value?: AssistanceSelection | GraphWorkspaceSelection | SavedGraphWorkspaceSelection) => {
    setCurrent((previous) => value ? { owner, value } : previous?.owner === owner ? undefined : previous);
  }, []);
  const value = useMemo(() => ({ selection: current?.value, publish, open, setOpen, requestedJobId, openJob, finishOpenJob }), [current, publish, open, requestedJobId, openJob, finishOpenJob]);
  return <Context.Provider value={value}>{children}</Context.Provider>;
}

export function usePublishGraphAssistanceSelection(enabled: boolean) {
  const publish = useContext(Context)?.publish;
  useEffect(() => {
    if (!publish || !enabled) return;
    const owner = Symbol("graph-selection");
    publish(owner, { kind: "graph", baseScenario: null, title: "New experiment", manualEdits: false });
    return () => publish(owner);
  }, [enabled, publish]);
}

export function useAssistanceSelection() { return useContext(Context)?.selection; }
export function useAssistancePanel() { return useContext(Context); }

/** Native views publish their actual selection, including unsaved-edit state. */
export function usePublishAssistanceSelection(selection?: AssistanceSelection) {
  const publish = useContext(Context)?.publish;
  const { runId, candidateId, resourceDigest, title, manualEdits } = selection ?? {};
  useEffect(() => {
    if (!publish || !runId || !candidateId || !resourceDigest) return;
    const owner = Symbol("native-selection");
    publish(owner, { runId, candidateId, resourceDigest, title: title ?? candidateId, manualEdits: Boolean(manualEdits) });
    return () => publish(owner);
  }, [publish, runId, candidateId, resourceDigest, title, manualEdits]);
}

export function usePublishSavedGraphSelection(selection?: SavedGraphSelection, title?: string) {
  const publish = useContext(Context)?.publish;
  useEffect(() => {
    if (!publish || !selection) return;
    const owner = Symbol("saved-graph-run");
    publish(owner, { kind: "saved_graph", selected: selection, title: title ?? selection.application.scenario_id, manualEdits: false });
    return () => publish(owner);
  }, [publish, selection, title]);
}
