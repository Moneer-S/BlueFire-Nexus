import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, ArrowRight, FlaskConical, RefreshCw } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { DEMO_MODE } from "../lib/api";
import { engineExperimentApi, engineExperimentPath, type EngineExperimentHead } from "../lib/engine-experiment-api";
import { engineWorkflowLabel } from "../lib/engine-experiment";
import { Badge, Button, ErrorState, LoadingState, PageHeader, Panel, formatDate, sentence } from "./Primitives";
import "./EngineExperimentWorkspace.css";

const PAGE_SIZE = 5;

function SavedExperiment({ head }: { head: EngineExperimentHead }) {
  const workspace = useQuery({ queryKey: ["engine-experiment-library", "workspace", head.experiment_id, head.active_revision, head.active_digest], queryFn: async () => {
    const value = await engineExperimentApi.workspace(head.experiment_id);
    if (value.experiment_id !== head.experiment_id || value.revision !== head.active_revision || value.experiment_digest !== head.active_digest) throw new Error("This experiment changed. Refresh the saved list to load its current revision.");
    return value;
  }, retry: false });
  const value = workspace.data;
  return <li>
    {workspace.isPending ? <LoadingState label="Loading saved experiment" /> : workspace.isError || !value ? <ErrorState title="Saved experiment unavailable" error={workspace.error} retry={() => { void workspace.refetch(); }} /> : <>
      <div className="engine-library-record"><span className="engine-attempt-marker"><FlaskConical aria-hidden="true" /></span><div><Link to={engineExperimentPath(value.experiment_id)}>{value.objective.title}<ArrowRight aria-hidden="true" /></Link><p>{value.environment.display_name} · {sentence(value.environment.platform)}</p><span>{value.engine_setup.model.test_provider ? "Labeled test provider" : `Configured provider: ${value.engine_setup.model.provider}`}</span></div><Badge tone={value.current_target === null ? "warning" : "neutral"}>{engineWorkflowLabel(value.projection.workflow_state)}</Badge></div>
      <dl className="engine-library-metadata"><div><dt>Updated</dt><dd>{formatDate(head.updated_at)}</dd></div><div><dt>Defense</dt><dd>{sentence(value.projection.conclusion.defense.state)}</dd></div><div><dt>Worker / target cleanup</dt><dd>{sentence(value.projection.conclusion.cleanup.status)}</dd></div><div><dt>Saved revision</dt><dd>{value.revision}</dd></div></dl>
    </>}
  </li>;
}

export function EngineExperimentLibrary() {
  const [page, setPage] = useState(0);
  const client = useQueryClient();
  const offset = page * PAGE_SIZE;
  const history = useQuery({ queryKey: ["engine-experiment-library", "list", page], queryFn: () => engineExperimentApi.list({ limit: PAGE_SIZE + 1, offset }), enabled: !DEMO_MODE, retry: false });
  const heads = history.data?.experiments ?? [];
  const visible = heads.slice(0, PAGE_SIZE);
  const hasNext = heads.length > PAGE_SIZE;
  return <div className="page engine-experiment-library">
    <Link className="engine-back-link" to="/composition"><ArrowLeft aria-hidden="true" />Composition workspace</Link>
    <PageHeader title="Saved defense experiments" description="Resume a controller-owned experiment with its recorded evidence and reviewed actions." actions={<Button size="small" variant="secondary" disabled={DEMO_MODE || history.isFetching} onClick={() => { setPage(0); void client.invalidateQueries({ queryKey: ["engine-experiment-library"] }); }}><RefreshCw aria-hidden="true" />Refresh saved list</Button>} />
    <Panel>
      {DEMO_MODE ? <p>Saved defense experiments are available in the installed workspace.</p> : <>
        {history.isError ? <ErrorState title="Saved experiments unavailable" error={history.error} retry={() => { void history.refetch(); }} /> : null}
        {history.isPending ? <LoadingState label="Loading saved experiments" /> : history.isSuccess ? visible.length ? <><p className="engine-evidence-note" role="status">Showing {offset + 1} to {offset + visible.length} saved experiments.</p><ul className="engine-library-list">{visible.map(head => <SavedExperiment key={`${head.experiment_id}:${head.active_revision}:${head.active_digest}`} head={head} />)}</ul><nav className="engine-library-pagination" aria-label="Saved experiment pages"><Button size="small" variant="secondary" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</Button><span>Page {page + 1}</span><Button size="small" variant="secondary" disabled={!hasNext} onClick={() => setPage(page + 1)}>Next</Button></nav></> : page > 0 ? <div className="engine-empty-evidence"><FlaskConical aria-hidden="true" /><div><strong>No saved experiments on this page</strong><Button size="small" variant="secondary" onClick={() => setPage(page - 1)}>Previous page</Button></div></div> : <div className="engine-empty-evidence"><FlaskConical aria-hidden="true" /><div><strong>No saved defense experiment</strong><p>An authorized controller must supply the reviewed objective, environment, and scope before an experiment can appear here.</p></div></div> : null}
      </>}
    </Panel>
  </div>;
}
