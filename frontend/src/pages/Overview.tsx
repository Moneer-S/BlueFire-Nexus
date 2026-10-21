import { displayTitle } from "../lib/display-title";
import { runLabel } from "../lib/runPresentation";
import { useQuery } from "@tanstack/react-query";
import { ArrowRight, Boxes, GitBranch, Network, RotateCcw } from "lucide-react";
import { Link } from "react-router-dom";
import { api, DEMO_MODE } from "../lib/api";
import { useProduct } from "../state/ProductContext";
import { Badge, Button, ErrorState, formatDate, LoadingState, PageHeader, sentence } from "../components/Primitives";
import { SavedDefensiveWork } from "../components/SavedDefensiveWork";
import "./Overview.css";

export function OverviewPage() {
  const experiments = useQuery({ queryKey: ["scenarios"], queryFn: api.scenarios });
  const runs = useQuery({ queryKey: ["runs"], queryFn: api.runs });
  const catalog = useQuery({ queryKey: ["catalog"], queryFn: api.catalog, staleTime: 60_000 });
  const { scenario, dirty } = useProduct();
  const recent = runs.data?.runs.slice(0, 8);
  const unavailable = runs.data?.unavailable_run_count ?? 0;
  const latestRun = recent?.find(run => run.scenario_id === scenario.id);
  const behaviorTitles = new Map(catalog.data?.behaviors.map(behavior => [behavior.id, behavior.title]));
  const dataBindings = scenario.steps.reduce((total, step) => total + Object.keys(step.inputs).length, 0);
  return <div className="page overview-page">
    <PageHeader title="Overview" description="Your experiments, evidence, and defensive work." actions={<><Link className="button button-secondary button-medium" to="/scenarios">Open experiments</Link><Link className="button button-primary button-medium" to="/getting-started">Start an objective<ArrowRight aria-hidden="true"/></Link></>} />
    {DEMO_MODE ? <p className="workspace-note" role="status">Demo workspace · synthetic results · Execute previews have no effects.</p> : null}
    <section className="active-work" aria-labelledby="working-copy-heading">
      <div className="active-work-content">
        <div className="active-work-heading"><span className="active-work-symbol"><Boxes aria-hidden="true"/></span><div><h2 id="working-copy-heading">Working draft</h2><Badge tone={dirty ? "warning" : "info"}>{dirty ? "Unsaved changes" : "No unsaved changes"}</Badge></div></div>
        <h3>{displayTitle(scenario.title)}</h3>
        {scenario.purpose ? <p className="active-work-purpose">{scenario.purpose}</p> : null}
        <ul className="active-work-facts" aria-label="Plan contents"><li><Network aria-hidden="true"/>{scenario.steps.length} steps</li><li><GitBranch aria-hidden="true"/>{scenario.edges.length} outcome routes</li><li><Boxes aria-hidden="true"/>{dataBindings} data bindings</li></ul>
        <div className="active-work-actions"><Link className="button button-primary" to="/builder">Continue editing<ArrowRight aria-hidden="true"/></Link><Link className="button button-secondary" to="/runs?prepare=1">Review run</Link></div>
        {latestRun ? <Link className="active-work-latest" to={`/runs/${encodeURIComponent(latestRun.run_id)}`}>Latest recorded {latestRun.mode === "simulate" ? "simulation" : "execution"}: {sentence(latestRun.status)}<ArrowRight aria-hidden="true"/></Link> : null}
      </div>
      <div className="active-work-plan"><div><h3>Plan at a glance</h3><Link to="/builder">Open graph<ArrowRight aria-hidden="true"/></Link></div><ul>{scenario.steps.slice(0, 4).map(step => <li key={step.id}><span><Network aria-hidden="true"/></span><div><strong>{displayTitle(behaviorTitles.get(step.behavior_id) ?? step.behavior_id)}</strong><small>{step.id === scenario.start ? "Starting step" : "Planned step"}</small></div></li>)}</ul>{scenario.steps.length > 4 ? <Link className="active-work-more" to="/builder">View all {scenario.steps.length} steps<ArrowRight aria-hidden="true"/></Link> : null}</div>
    </section>
    <SavedDefensiveWork />
    <div className="overview-history">
    <section className="work-section" aria-labelledby="recent-work-heading">
      <header className="work-section-heading"><h2 id="recent-work-heading">Recent runs</h2><Button variant="ghost" size="small" disabled={runs.isFetching} onClick={() => runs.refetch()}><RotateCcw aria-hidden="true"/>{runs.isFetching ? "Refreshing" : "Refresh runs"}</Button></header>
      {runs.isError ? <><ErrorState title="Run history unavailable" error={runs.error} retry={() => runs.refetch()}/>{recent ? <p className="workspace-note">Showing previously loaded runs. Their current state could not be checked.</p> : null}</> : null}
      {unavailable > 0 ? <p className="workspace-note" role="status">{unavailable} run {unavailable === 1 ? "record is" : "records are"} unavailable. Only readable records are shown.</p> : null}
      {runs.isPending ? <LoadingState label="Loading run history"/> : recent?.length ? <div className="table-scroll"><table className="recent-work-table"><thead><tr><th>Run</th><th>Mode</th><th>Created</th><th>Outcome</th></tr></thead><tbody>{recent.map(run => {
        const name = runLabel(run);
        return <tr key={run.run_id}><td><Link to={"/runs/" + encodeURIComponent(run.run_id)}>{name}</Link>{run.is_demo ? <Badge tone="violet">Demo</Badge> : null}</td><td>{sentence(run.mode)}</td><td><time dateTime={run.created_at}>{formatDate(run.created_at)}</time></td><td><Badge tone={run.status === "completed" ? "neutral" : run.status === "failed" ? "danger" : "info"}>{sentence(run.status)}</Badge></td></tr>;
      })}</tbody></table></div> : runs.isSuccess && unavailable === 0 ? <div className="work-empty"><p>No runs have been recorded.</p><Link to="/runs?prepare=1">Review new run<ArrowRight aria-hidden="true"/></Link></div> : null}
    </section>
    <section className="work-section" aria-labelledby="experiments-heading">
      <header className="work-section-heading"><h2 id="experiments-heading">Experiments</h2><Link to="/scenarios">View all<ArrowRight aria-hidden="true"/></Link></header>
      {experiments.isError ? <><ErrorState title="Experiments unavailable" error={experiments.error} retry={() => experiments.refetch()}/>{experiments.data ? <p className="workspace-note">Showing previously loaded experiments. Your working draft is preserved.</p> : null}</> : null}
      {experiments.isPending ? <LoadingState label="Loading experiments"/> : experiments.data?.scenarios.length ? <ul className="work-object-list">{experiments.data.scenarios.slice(0, 5).map(item => <li key={item.id}><span><strong>{displayTitle(item.title)}</strong><small>{item.steps.length} steps · {item.edges.length} routes</small></span><Link to={"/scenarios?selected=" + encodeURIComponent(item.id)}>Open in library<ArrowRight aria-hidden="true"/></Link></li>)}</ul> : experiments.isSuccess ? <div className="work-empty"><p>No experiments are available.</p><Link to="/scenarios">Create an experiment</Link></div> : null}
    </section>
    </div>
  </div>;
}
