import { displayTitle } from "../lib/display-title";
import { runLabel } from "../lib/runPresentation";
import { useQuery } from "@tanstack/react-query";
import { ArrowRight, RotateCcw } from "lucide-react";
import { Link } from "react-router-dom";
import { api, DEMO_MODE } from "../lib/api";
import { useProduct } from "../state/ProductContext";
import { Badge, Button, ErrorState, formatDate, LoadingState, PageHeader, sentence } from "../components/Primitives";
import "./Overview.css";

export function OverviewPage() {
  const experiments = useQuery({ queryKey: ["scenarios"], queryFn: api.scenarios });
  const runs = useQuery({ queryKey: ["runs"], queryFn: api.runs });
  const { scenario, dirty } = useProduct();
  const recent = runs.data?.runs.slice(0, 8);
  const unavailable = runs.data?.unavailable_run_count ?? 0;
  return <div className="page overview-page">
    <PageHeader title="Overview" actions={<Link className="button button-primary button-medium" to="/scenarios">Open experiments<ArrowRight aria-hidden="true"/></Link>} />
    {DEMO_MODE ? <p className="workspace-note" role="status">Demo workspace · synthetic results · Execute previews have no effects.</p> : null}
    <section className="work-section" aria-labelledby="recent-work-heading">
      <header className="work-section-heading"><h2 id="recent-work-heading">Recent runs</h2><Button variant="ghost" size="small" disabled={runs.isFetching} onClick={() => runs.refetch()}><RotateCcw aria-hidden="true"/>{runs.isFetching ? "Refreshing" : "Refresh runs"}</Button></header>
      {runs.isError ? <><ErrorState title="Run history unavailable" error={runs.error} retry={() => runs.refetch()}/>{recent ? <p className="workspace-note">Showing previously loaded runs. Their current state could not be checked.</p> : null}</> : null}
      {unavailable > 0 ? <p className="workspace-note" role="status">{unavailable} run {unavailable === 1 ? "record is" : "records are"} unavailable. Only readable records are shown.</p> : null}
      {runs.isPending ? <LoadingState label="Loading run history"/> : recent?.length ? <div className="table-scroll"><table className="recent-work-table"><thead><tr><th>Run</th><th>Mode</th><th>Created</th><th>Outcome</th></tr></thead><tbody>{recent.map(run => {
        const name = runLabel(run);
        return <tr key={run.run_id}><td><Link to={"/runs/" + encodeURIComponent(run.run_id)}>{name}</Link>{run.is_demo ? <Badge tone="violet">Demo</Badge> : null}</td><td>{sentence(run.mode)}</td><td><time dateTime={run.created_at}>{formatDate(run.created_at)}</time></td><td><Badge tone={run.status === "completed" ? "neutral" : run.status === "failed" ? "danger" : "info"}>{sentence(run.status)}</Badge></td></tr>;
      })}</tbody></table></div> : runs.isSuccess && unavailable === 0 ? <div className="work-empty"><p>No runs have been recorded.</p><Link to="/runs?prepare=1">Review new run<ArrowRight aria-hidden="true"/></Link></div> : null}
    </section>
    <section className="work-section working-copy" aria-labelledby="working-copy-heading">
      <header className="work-section-heading"><h2 id="working-copy-heading">Working draft</h2><Badge tone={dirty ? "warning" : "neutral"}>{dirty ? "Unsaved changes" : "No unsaved changes"}</Badge></header>
      <div><h3>{displayTitle(scenario.title)}</h3><p>{scenario.steps.length} steps · {scenario.edges.length} routes</p><Link className="button button-secondary button-medium" to="/builder">Continue editing<ArrowRight aria-hidden="true"/></Link><Link className="button button-ghost button-medium" to="/runs?prepare=1">Review run</Link></div>
    </section>
    <section className="work-section" aria-labelledby="experiments-heading">
      <header className="work-section-heading"><h2 id="experiments-heading">Experiments</h2><Link to="/scenarios">View all<ArrowRight aria-hidden="true"/></Link></header>
      {experiments.isError ? <><ErrorState title="Experiments unavailable" error={experiments.error} retry={() => experiments.refetch()}/>{experiments.data ? <p className="workspace-note">Showing previously loaded experiments. Your working draft is preserved.</p> : null}</> : null}
      {experiments.isPending ? <LoadingState label="Loading experiments"/> : experiments.data?.scenarios.length ? <ul className="work-object-list">{experiments.data.scenarios.slice(0, 5).map(item => <li key={item.id}><span><strong>{displayTitle(item.title)}</strong><small>{item.steps.length} steps · {item.edges.length} routes</small></span><Link to={"/scenarios?selected=" + encodeURIComponent(item.id)}>Open in library<ArrowRight aria-hidden="true"/></Link></li>)}</ul> : experiments.isSuccess ? <div className="work-empty"><p>No experiments are available.</p><Link to="/scenarios">Create an experiment</Link></div> : null}
    </section>
  </div>;
}
