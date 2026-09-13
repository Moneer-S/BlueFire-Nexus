import { validReceiverAssistanceSelection, type ReceiverAssistanceSelection } from "../lib/receiver-assistance";
import { validSavedRunSelection, savedRunSource, type SavedRunSelection } from "../lib/run-assistance";
import { validRunDetectionSelection, type RunDetectionSelection } from "../lib/detection-creation";
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type PropsWithChildren } from "react";
import { validGraphSelection, type GraphStepSelection, type GraphSelection } from "../lib/assistance";

export interface AssistanceSelection {
  runId: string;
  candidateId: string;
  resourceDigest: string;
  title: string;
  manualEdits: boolean;
}
interface SelectionContext {
  selection?: WorkspaceSelection;
  publish: (owner: symbol, value?: WorkspaceSelection) => void;
  requestedJobId?: string;
  requestedReceiverJobId?: string;
  openJob: (jobId: string, receiverJobId?: string) => void;
  finishOpenJob: () => void;
  open: boolean;
  setOpen: (value: boolean) => void;
}
export interface SavedGraphWorkspaceSelection { kind: "saved_graph"; selected: SavedRunSelection; title: string; manualEdits: false }
export interface GraphWorkspaceSelection { kind: "graph"; editStep?: GraphStepSelection; editUnavailable?: string; baseScenario: GraphSelection["base_scenario"]; title: string; manualEdits: boolean }
export interface RunDetectionWorkspaceSelection { kind: "run_detection"; selected: RunDetectionSelection; title: string; manualEdits: false }
export interface ReceiverWorkspaceSelection { kind: "receiver"; selected: ReceiverAssistanceSelection; title: string; manualEdits: false }
export type WorkspaceSelection = ReceiverWorkspaceSelection | AssistanceSelection | GraphWorkspaceSelection | SavedGraphWorkspaceSelection | RunDetectionWorkspaceSelection;
const selectionKey = "bluefire.assistance.selection.v1";
function readSelection(): WorkspaceSelection | undefined {
  try {
    const raw = sessionStorage.getItem(selectionKey);
    if (!raw || raw.length > 100000) return;
    const value = JSON.parse(raw) as WorkspaceSelection;
    if (!value || typeof value.title !== "string" || value.title.length > 1000 || typeof value.manualEdits !== "boolean") return;
    if (!("kind" in value)) return [value.runId, value.candidateId, value.resourceDigest].every(item => typeof item === "string" && item.length > 0 && item.length <= 200) ? value : undefined;
    if (value.kind === "saved_graph") return validSavedRunSelection(value.selected) ? value : undefined;
    if (value.kind === "run_detection") return validRunDetectionSelection(value.selected) ? value : undefined;
    if (value.kind === "receiver") return validReceiverAssistanceSelection(value.selected) ? value : undefined;
    if (value.kind === "graph" && (value.editUnavailable === undefined || (typeof value.editUnavailable === "string" && value.editUnavailable.length <= 1000)) && validGraphSelection({ kind: "graph", base_scenario: value.baseScenario, ...(value.editStep ? { edit_step: value.editStep } : {}) })) return value;
  } catch { /* Context is rechecked by the service before submission. */ }
}
const Context = createContext<SelectionContext | null>(null);

export function AssistanceProvider({ children }: PropsWithChildren) {
  const [open, setOpen] = useState(() => { try { return sessionStorage.getItem("bluefire.assistance.open.v1") === "true"; } catch { return false; } });
  const [requestedJobId, setRequestedJobId] = useState<string>();
  const [requestedReceiverJobId, setRequestedReceiverJobId] = useState<string>();
  const openJob = useCallback((jobId: string, receiverJobId?: string) => { setRequestedJobId(jobId); setRequestedReceiverJobId(receiverJobId); setOpen(true); }, []);
  const finishOpenJob = useCallback(() => { setRequestedJobId(undefined); setRequestedReceiverJobId(undefined); }, []);
  const [current, setCurrent] = useState<{ owner?: symbol; value: WorkspaceSelection } | undefined>(() => {
    const saved = readSelection(); return saved ? { value: saved } : undefined;
  });
  useEffect(() => {
    try {
      sessionStorage.setItem("bluefire.assistance.open.v1", String(open));
      if (current) sessionStorage.setItem(selectionKey, JSON.stringify(current.value));
    } catch { /* Draft context is optional; request receipts remain mandatory. */ }
  }, [open, current]);
  const publish = useCallback((owner: symbol, value?: WorkspaceSelection) => {
    setCurrent((previous) => value ? { owner, value } : previous?.owner === owner ? { value: previous.value } : previous);
  }, []);
  const value = useMemo(() => ({ selection: current?.value, publish, open, setOpen, requestedJobId, requestedReceiverJobId, openJob, finishOpenJob }), [current, publish, open, requestedJobId, requestedReceiverJobId, openJob, finishOpenJob]);
  return <Context.Provider value={value}>{children}</Context.Provider>;
}

export function usePublishGraphAssistanceSelection(enabled: boolean, editStep?: GraphStepSelection, title?: string, editUnavailable?: string) {
  const publish = useContext(Context)?.publish;
  useEffect(() => {
    if (!publish || !enabled) return;
    const owner = Symbol("graph-selection");
    publish(owner, { kind: "graph", baseScenario: null, ...(editStep ? { editStep } : {}), ...(editUnavailable ? { editUnavailable } : {}), title: title ?? "New experiment", manualEdits: false });
    return () => publish(owner);
  }, [enabled, publish, editStep, title, editUnavailable]);
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

export function usePublishSavedGraphSelection(selection?: SavedRunSelection, title?: string) {
  const publish = useContext(Context)?.publish;
  useEffect(() => {
    if (!publish || !selection) return;
    const owner = Symbol("saved-graph-run");
    publish(owner, { kind: "saved_graph", selected: selection, title: title ?? savedRunSource(selection).scenario_id, manualEdits: false });
    return () => publish(owner);
  }, [publish, selection, title]);
}

export function usePublishRunDetectionSelection(selection?: RunDetectionSelection, title?: string) {
  const publish = useContext(Context)?.publish;
  useEffect(() => {
    if (!publish || !selection) return;
    const owner = Symbol("run-detection-creation");
    publish(owner, { kind: "run_detection", selected: selection, title: title ?? "Create a detection", manualEdits: false });
    return () => publish(owner);
  }, [publish, selection, title]);
}

export function usePublishReceiverSelection(selection?: ReceiverAssistanceSelection, title?: string) {
  const publish = useContext(Context)?.publish;
  useEffect(() => {
    if (!publish || !selection) return;
    const owner = Symbol("receiver-assistance");
    publish(owner, { kind: "receiver", selected: selection, title: title ?? "Receiver control test", manualEdits: false });
    return () => publish(owner);
  }, [publish, selection, title]);
}
