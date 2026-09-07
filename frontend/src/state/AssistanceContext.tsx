import { createContext, useCallback, useContext, useEffect, useMemo, useState, type PropsWithChildren } from "react";

export interface AssistanceSelection {
  runId: string;
  candidateId: string;
  resourceDigest: string;
  title: string;
  manualEdits: boolean;
}
interface SelectionContext {
  selection?: AssistanceSelection;
  publish: (owner: symbol, value?: AssistanceSelection) => void;
}
const Context = createContext<SelectionContext | null>(null);

export function AssistanceProvider({ children }: PropsWithChildren) {
  const [current, setCurrent] = useState<{ owner: symbol; value: AssistanceSelection }>();
  const publish = useCallback((owner: symbol, value?: AssistanceSelection) => {
    setCurrent((previous) => value ? { owner, value } : previous?.owner === owner ? undefined : previous);
  }, []);
  const value = useMemo(() => ({ selection: current?.value, publish }), [current, publish]);
  return <Context.Provider value={value}>{children}</Context.Provider>;
}

export function useAssistanceSelection() { return useContext(Context)?.selection; }

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
