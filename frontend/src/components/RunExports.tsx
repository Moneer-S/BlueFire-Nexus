import { useEffect, useRef, useState } from "react";
import type { RunRecord } from "../types";
import { api, DEMO_MODE } from "../lib/api";
import { runReport } from "../lib/run-report";
import { downloadArtifact as download } from "../lib/download";
import { Button, Callout } from "./Primitives";
import "./RunExports.css";

export function RunExports({ run }: { run: RunRecord }) {
  return <RunExportActions key={run.run_id} run={run}/>;
}

function RunExportActions({ run }: { run: RunRecord }) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const request = useRef<AbortController | null>(null);
  useEffect(() => () => { request.current?.abort(); }, [run.run_id]);
  const finalized = Boolean(run.finalized_at);
  const bundleAvailable = finalized && !run.is_demo && !DEMO_MODE;
  const filename = run.run_id.replace(/[^a-zA-Z0-9_-]/g, "_");
  const bundle = async () => {
    if (request.current || !bundleAvailable) return;
    const controller = new AbortController();
    request.current = controller;
    setPending(true); setError(null);
    try {
      const blob = await api.runBundle(run.run_id, controller.signal);
      if (!controller.signal.aborted) download(blob, `${filename}.zip`);
    } catch (failure) {
      if (!controller.signal.aborted) setError(failure instanceof Error ? failure.message : "Bundle download failed.");
    } finally {
      if (request.current === controller) request.current = null;
      if (!controller.signal.aborted) setPending(false);
    }
  };
  return <section aria-label="Export this run">
    <div className="run-export-actions">
      <Button variant="secondary" disabled={!finalized} onClick={() => download(new Blob([runReport(run)], { type: "text/markdown;charset=utf-8" }), `${filename}.md`)}>Download report</Button>
      <Button variant="secondary" disabled={!bundleAvailable || pending} onClick={() => void bundle()}>{pending ? "Preparing bundle…" : "Download run bundle"}</Button>
    </div>
    <p className="field-note">Report: readable Markdown. Bundle: exact saved files, all events and recovery records. Detector revisions and Detection Lab evaluations are separate.{!finalized ? " Downloads become available after finalization." : run.is_demo || DEMO_MODE ? " Demo runs have no saved bundle." : ""}</p>
    {pending ? <p role="status">Validating the complete saved bundle…</p> : null}
    {error ? <Callout title="Download unavailable" tone="danger">{error}</Callout> : null}
  </section>;
}
