import { displayTitle } from "../lib/display-title";
import { graphNodeIcon } from "../lib/graph-node-icon";
import { runLabel } from "../lib/runPresentation";
import { objectiveLabel, shortRunId } from "../lib/run-presentation";
import { profileChoiceLabel, scopeLabel } from "../lib/run-review-labels";
import { useQuery } from "@tanstack/react-query";
import { ArrowRight, Boxes, CircleDot, GitBranch, Network, Play, RotateCcw, ScanLine, Server } from "lucide-react";
import { Link } from "react-router-dom";
import { api, DEMO_MODE } from "../lib/api";
import { useProduct } from "../state/ProductContext";
import { Badge, Button, ErrorState, formatDate, LoadingState, PageHeader, sentence } from "../components/Primitives";
import { SavedDefensiveWork } from "../components/SavedDefensiveWork";
import { ActiveWorkResume } from "../components/ActiveWorkResume";
import { useActiveDefensiveWork, useActiveWorkSummary } from "../state/activeDefensiveWork";
import "./Overview.css";

export function OverviewPage() {
  const experiments = useQuery({ queryKey: ["scenarios"], queryFn: api.scenarios });
  const runs = useQuery({ queryKey: ["runs"], queryFn: api.runs });
  const catalog = useQuery({ queryKey: ["catalog"], queryFn: api.catalog, staleTime: 60_000 });
  const { scenario, scenarioIsSeededFallback, dirty, runConfig } = useProduct();
  const activeWork = useActiveDefensiveWork();
  const activeSummary = useActiveWorkSummary(DEMO_MODE ? undefined : activeWork);
  const recent = runs.data?.runs.slice(0, 4);
  const unavailable = runs.data?.unavailable_run_count ?? 0;
  const historyIsEmpty = runs.isSuccess && runs.data?.runs.length === 0 && unavailable === 0;
  const latestRun = !scenarioIsSeededFallback ? runs.data?.runs.find(run => run.scenario_id === scenario.id) : undefined;
  const behaviorTitles = new Map(catalog.data?.behaviors.map(behavior => [behavior.id, behavior.title]));
  const behaviorsById = new Map(catalog.data?.behaviors.map(behavior => [behavior.id, behavior]));
  const dataBindings = scenario.steps.reduce((total, step) => total + Object.keys(step.inputs).length, 0);
  const entry = scenario.steps.find(step => step.id === scenario.start);
  const planSteps = [...(entry ? [entry] : []), ...scenario.steps.filter(step => step.id !== entry?.id)].slice(0, 4);
  const profiles = catalog.data?.runner_profiles ?? [];
  const selectedProfile = profiles.find(profile => profile.id === runConfig.profileId && profile.mode === runConfig.mode);

  return <div className="page overview-page">
    <PageHeader title="Overview" description="Continue your work and review recorded results." actions={<><Link className="button button-secondary button-medium" to="/scenarios">Open experiments</Link><Link className={`button button-${scenarioIsSeededFallback && (!activeWork || DEMO_MODE) ? "primary" : "secondary"} button-medium`} to="/getting-started">Start an objective<ArrowRight aria-hidden="true"/></Link></>} />
    {DEMO_MODE ? <p className="workspace-note overview-demo-note" role="status">Demo workspace · synthetic results · Execute previews have no effects.</p> : null}

    {activeWork && !DEMO_MODE ? <ActiveWorkResume reference={activeWork} /> : <section className="active-work" aria-labelledby="working-copy-heading">
      <div className="active-work-content">
        <div className="active-work-heading"><span className="active-work-symbol"><Boxes aria-hidden="true"/></span><div><h2 id="working-copy-heading">{scenarioIsSeededFallback ? "Example plan" : "Working draft"}</h2><h3>{displayTitle(scenario.title)}</h3></div></div>
        <div className="active-work-state">{scenarioIsSeededFallback ? <span>Built-in example</span> : dirty ? <span className="attention">Unsaved changes</span> : null}<span>{scenarioIsSeededFallback ? "A starting point for your own objective" : "Your current plan in Build"}</span></div>
        {scenario.purpose ? <p className="active-work-purpose">{scenario.purpose}</p> : null}
        <ul className="active-work-facts" aria-label="Plan contents"><li><Network aria-hidden="true"/>{scenario.steps.length} steps</li><li><GitBranch aria-hidden="true"/>{scenario.edges.length} outcome routes</li><li><Boxes aria-hidden="true"/>{dataBindings} data bindings</li></ul>
        <div className="active-work-actions"><Link className="button button-primary" to="/builder">{scenarioIsSeededFallback ? "Open example plan" : "Continue editing"}<ArrowRight aria-hidden="true"/></Link><Link className="button button-secondary" to="/runs?prepare=1">Review run</Link></div>
        {latestRun ? <Link className="active-work-latest" to={`/runs/${encodeURIComponent(latestRun.run_id)}`}>{runs.isError ? "Last loaded" : "Latest recorded"} {latestRun.mode === "simulate" ? "simulation" : "execution"}: {objectiveLabel(latestRun.objective_reached, latestRun.mode)}<small>Run status: {sentence(latestRun.status)}</small><ArrowRight aria-hidden="true"/></Link> : null}
      </div>
      <div className="active-work-plan"><header><h3>Plan at a glance</h3><Link to="/builder">Open graph<ArrowRight aria-hidden="true"/></Link></header><ul>{planSteps.map(step => {
        const conditionalRoutes = scenario.edges.filter(edge => edge.from_step === step.id && edge.outcome !== "success").length;
        return <li key={step.id}><span className={step.id === scenario.start ? "plan-entry" : undefined}>{(() => { const StepIcon = graphNodeIcon(behaviorsById.get(step.behavior_id)); return <StepIcon aria-hidden="true"/>; })()}</span><div><strong>{displayTitle(behaviorTitles.get(step.behavior_id) ?? step.behavior_id)}</strong><small>{step.id === scenario.start ? "Starting step" : conditionalRoutes ? `${conditionalRoutes} conditional ${conditionalRoutes === 1 ? "route" : "routes"}` : "Planned method"}</small></div></li>;
      })}</ul>{scenario.steps.length > planSteps.length ? <Link className="active-work-more" to="/builder">View all {scenario.steps.length} steps<ArrowRight aria-hidden="true"/></Link> : null}</div>
    </section>}

    <div className={`overview-dashboard${historyIsEmpty ? " is-history-empty" : ""}`}>
      <section className="work-section overview-run-context" aria-labelledby="run-context-heading">
        <header className="work-section-heading"><h2 id="run-context-heading">{activeWork && !DEMO_MODE ? "Working draft settings" : "Run context"}</h2></header>
        <dl className="overview-context-facts">
          <div><dt><Play aria-hidden="true"/>Run mode</dt><dd>{sentence(runConfig.mode)}<small>AI during the run: {sentence(runConfig.autonomy)}</small></dd></div>
          <div><dt><Server aria-hidden="true"/>Environment</dt><dd>{catalog.isPending ? "Checking profiles…" : catalog.isError ? "Catalog unavailable" : selectedProfile ? profileChoiceLabel(selectedProfile.id, profiles) : "Choose a profile"}<small>{catalog.isError ? "Your profile selection is retained." : selectedProfile ? "Configured profile · check readiness in Runs" : "Review available profiles before running."}</small></dd></div>
          <div><dt><ScanLine aria-hidden="true"/>Selected scope</dt><dd>{runConfig.scopeRefs.length ? runConfig.scopeRefs.slice(0, 2).map(scopeLabel).join(" · ") : "Not selected"}{runConfig.scopeRefs.length > 2 ? <small>+{runConfig.scopeRefs.length - 2} more in run settings</small> : null}</dd></div>
        </dl>
        <div className="overview-context-actions"><Link to="/runs?prepare=1">Review run settings<ArrowRight aria-hidden="true"/></Link>{catalog.isError ? <Button variant="ghost" size="small" onClick={() => { void catalog.refetch(); }}>Retry catalog</Button> : <Link to="/environments">Environments<ArrowRight aria-hidden="true"/></Link>}</div>
      </section>

      <section className="work-section overview-recent-work" aria-labelledby="recent-work-heading">
        <header className="work-section-heading"><h2 id="recent-work-heading">Recent outcomes</h2><div className="work-section-actions"><Link to="/runs">View all<ArrowRight aria-hidden="true"/></Link><Button variant="ghost" size="small" aria-label="Refresh runs" disabled={runs.isFetching} onClick={() => { void runs.refetch(); }}><RotateCcw aria-hidden="true"/><span className="sr-only">{runs.isFetching ? "Refreshing" : "Refresh runs"}</span></Button></div></header>
        {runs.isError ? <><ErrorState title="Run history unavailable" error={runs.error} retry={() => runs.refetch()}/>{recent ? <p className="workspace-note">Showing previously loaded runs. Their current state could not be checked.</p> : null}</> : null}
        {unavailable > 0 ? <p className="workspace-note" role="status">{unavailable} run {unavailable === 1 ? "record is" : "records are"} unavailable. Only readable records are shown.</p> : null}
        {runs.isPending ? <LoadingState label="Loading run history"/> : recent?.length ? <div className="table-scroll"><table className="recent-work-table"><thead><tr><th>Run</th><th>Created</th><th>Outcome</th></tr></thead><tbody>{recent.map(run => {
          const contexts = activeSummary.data?.runContexts?.filter(context => context.runId === run.run_id) ?? [];
          const context = contexts.length === 1 ? contexts[0] : undefined;
          return <tr key={run.run_id}>
            <td><div className="recent-work-name"><CircleDot aria-hidden="true" data-status={run.status}/><div><Link to={"/runs/" + encodeURIComponent(run.run_id)}>{runLabel(run)}</Link><small>{context ? <span className="recent-work-phase">{context.phase}</span> : null}<span className="recent-work-mode">{sentence(run.mode)}</span><span className="recent-work-id">{shortRunId(run.run_id)}</span>{run.is_demo ? <Badge tone="violet">Demo</Badge> : null}</small></div></div></td>
            <td><time dateTime={run.created_at}>{formatDate(run.created_at)}</time></td><td><div className="recent-work-outcome"><strong>{objectiveLabel(run.objective_reached, run.mode)}</strong>{context?.receiverDecision ? <span className="recent-work-decision">{context.receiverDecision}</span> : null}<small><span className="sr-only">Run status: </span>{sentence(run.status)}</small></div></td>
          </tr>;
        })}</tbody></table></div> : runs.isSuccess && unavailable === 0 ? <div className="work-empty"><CircleDot aria-hidden="true"/><p>No runs have been recorded.</p><Link to="/runs?prepare=1">Review new run<ArrowRight aria-hidden="true"/></Link></div> : null}
      </section>
    </div>

    <div className="overview-history">
      <SavedDefensiveWork />
      <section className="work-section overview-experiments" aria-labelledby="experiments-heading">
        <header className="work-section-heading"><h2 id="experiments-heading">Experiments</h2><Link to="/scenarios">View all<ArrowRight aria-hidden="true"/></Link></header>
        {experiments.isError ? <><ErrorState title="Experiments unavailable" error={experiments.error} retry={() => experiments.refetch()}/>{experiments.data ? <p className="workspace-note">Showing previously loaded experiments. Your working draft is preserved.</p> : null}</> : null}
        {experiments.isPending ? <LoadingState label="Loading experiments"/> : experiments.data?.scenarios.length ? <ul className="work-object-list">{experiments.data.scenarios.slice(0, 5).map(item => <li key={item.id}><span><strong>{displayTitle(item.title)}</strong><small>{item.steps.length} steps · {item.edges.length} routes</small></span><Link aria-label="Open in library" to={"/scenarios?selected=" + encodeURIComponent(item.id)}><ArrowRight aria-hidden="true"/></Link></li>)}</ul> : experiments.isSuccess ? <div className="work-empty"><Boxes aria-hidden="true"/><p>No experiments are available.</p><Link to="/scenarios">Create an experiment<ArrowRight aria-hidden="true"/></Link></div> : null}
        <Link className="overview-library-link" to="/getting-started">Start from your own objective<ArrowRight aria-hidden="true"/></Link>
      </section>
    </div>
  </div>;
}
