import { useQuery } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { savedScenarioSetupPath } from "../lib/run-assistance";
import { api } from "../lib/api";
import type { GraphEditorDraft } from "../lib/graph-assistance";
import { parseScenarioDocument } from "../lib/scenario";
import { useProduct } from "../state/ProductContext";
import type { ScenarioVersion } from "../types";
import { Button, ErrorState, LoadingState } from "./Primitives";

function checkedVersion(saved: ScenarioVersion, id: string, version: number, digest: string): ScenarioVersion {
  if (saved.scenario_id !== id || saved.version !== version || saved.digest !== digest || saved.document.id !== id) throw new Error("The saved version does not match this link. Your working graph is unchanged.");
  parseScenarioDocument(saved.document);
  return saved;
}

export function SavedExperimentReview({ id, version, digest, receiverJob, renderEditor }: {
  id: string; version: number; digest: string; receiverJob?: string; renderEditor: (draft: GraphEditorDraft) => ReactNode;
}) {
  const product = useProduct();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const fromRun = params.get("from_run") === "1";
  const [error, setError] = useState<unknown>();
  const valid = Boolean(id) && Number.isSafeInteger(version) && version > 0 && /^sha256:[0-9a-f]{64}$/.test(digest);
  const query = useQuery({ queryKey: ["saved-experiment-review", id, version, digest], enabled: valid, retry: false,
    queryFn: async () => checkedVersion((await api.immutableScenarioVersion(id, version)).scenario, id, version, digest) });
  const returnPath = fromRun ? savedScenarioSetupPath({ scenario_id: id, version, digest }) : receiverJob && /^job-[0-9a-f]{32}$/.test(receiverJob) ? `/compare?receiver_job=${encodeURIComponent(receiverJob)}` : "/compare?receiver=1";
  if (!valid || query.error) return <div className="page"><ErrorState title="Saved experiment unavailable" error={query.error ?? new Error("This saved-version link is incomplete.")} /><Link to={returnPath}>{fromRun ? "Return to run settings" : "Return to control test"}</Link></div>;
  if (!query.data) return <LoadingState label="Opening the selected saved version" />;
  const saved = query.data;
  const open = () => {
    if (product.dirty && !window.confirm("Open this saved version and replace your current unsaved graph? Save or export the current graph first to keep your edits.")) return;
    try { product.setScenario(structuredClone(saved.document), false); navigate("/builder"); }
    catch (failure) { setError(failure); }
  };
  return renderEditor({ scenario: saved.document, setScenario: () => undefined, dirty: false, readOnly: true,
    statusLabel: `Saved · v${saved.version}`, description: "Inspect this saved version. Opening it for editing is a separate action; your current working graph stays available.",
    controls: <><Button variant="primary" onClick={open}>Open this version for editing</Button><Link className="button button-secondary button-medium" to={`/runs?${new URLSearchParams({ saved_scenario: saved.scenario_id, version: String(saved.version), digest: saved.digest })}`}>Run with Assistant</Link></>,
    details: <section aria-label="Selected saved experiment"><p>Viewing <strong>{saved.title}</strong>, version {saved.version}. <Link to={returnPath}>{fromRun ? "Return to run settings" : "Return to control test"}</Link> · <Link to="/builder">Current working graph</Link></p>{error ? <ErrorState error={error} /> : null}</section> });
}
