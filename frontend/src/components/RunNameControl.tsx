import * as Dialog from "@radix-ui/react-dialog";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "../lib/api";
import { runNameValue } from "../lib/runPresentation";
import type { RunRecord } from "../types";
import { Button, ErrorState, Field } from "./Primitives";

export function RunNameControl({ run }: { run: RunRecord }) {
  const client = useQueryClient();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState(runNameValue(run));
  const rename = useMutation({
    mutationFn: (displayName: string | null) => api.renameRun(run.run_id, displayName),
    onSuccess: presentation => {
      client.setQueryData<RunRecord>(["run", run.run_id], old => old ? { ...old, presentation } : old);
      client.setQueryData<{runs: RunRecord[]; unavailable_run_count: number}>(["runs"], old => old ? { ...old, runs: old.runs.map(item => item.run_id === run.run_id ? { ...item, presentation } : item) } : old);
      void client.invalidateQueries({ queryKey: ["run", run.run_id] });
      void client.invalidateQueries({ queryKey: ["runs"] });
      setOpen(false);
    },
  });
  return <Dialog.Root open={open} onOpenChange={value => { if (rename.isPending) return; setOpen(value); if (value) { setName(runNameValue(run)); rename.reset(); } }}>
    <Dialog.Trigger asChild><Button variant="ghost" size="small">Rename run</Button></Dialog.Trigger>
    <Dialog.Portal><Dialog.Overlay className="dialog-overlay"/><Dialog.Content className="dialog-content">
      <Dialog.Title>Rename run</Dialog.Title><Dialog.Description>Change the display name. Recorded evidence, run identity and comparisons stay intact.</Dialog.Description>
      <form className="dialog-form" onSubmit={event => { event.preventDefault(); rename.mutate(name.trim()); }}>
        <Field label="Run name"><input value={name} onChange={event => setName(event.target.value)} maxLength={120} required autoFocus disabled={rename.isPending}/></Field>
        {rename.isError ? <ErrorState title="Run name change could not be confirmed" error={rename.error}/> : null}
        <div className="dialog-actions"><Button type="button" variant="ghost" disabled={rename.isPending} onClick={() => rename.mutate(null)}>Use experiment name</Button><Dialog.Close asChild><Button type="button" variant="ghost" disabled={rename.isPending}>Cancel</Button></Dialog.Close><Button type="submit" variant="primary" disabled={rename.isPending || !name.trim()}>{rename.isPending ? "Saving name" : "Save name"}</Button></div>
      </form>
    </Dialog.Content></Dialog.Portal>
  </Dialog.Root>;
}

export function CopyRunId({ runId }: { runId: string }) {
  const [notice, setNotice] = useState("");
  return <span className="copy-record-id"><code>{runId}</code><Button variant="ghost" size="small" onClick={async () => {
    try { await navigator.clipboard.writeText(runId); setNotice("Run ID copied"); }
    catch { setNotice("Copy unavailable. Select and copy the run ID above."); }
  }}>Copy run ID</Button><span role="status">{notice}</span></span>;
}
