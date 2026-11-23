import { useQuery } from "@tanstack/react-query";
import { ArrowRight, CheckCircle2, CircleDashed, FolderOpen, History, Network, Play, ShieldCheck, SlidersHorizontal } from "lucide-react";
import { Link } from "react-router-dom";
import { Badge, Callout, ErrorState, LoadingState, PageHeader } from "../components/Primitives";
import { api, DEMO_MODE } from "../lib/api";
import { ObjectiveStart } from "../components/ObjectiveStart";
import "./GettingStarted.css";

export function GettingStartedPage() {
  const catalog = useQuery({ queryKey: ["catalog"], queryFn: api.catalog });
  const scenarios = useQuery({ queryKey: ["scenarios"], queryFn: api.scenarios });
  const runs = useQuery({ queryKey: ["runs"], queryFn: api.runs });
  const detections = useQuery({ queryKey: ["detection-health"], queryFn: api.detectionHealth });

  const experimentCount = scenarios.data ? new Set(scenarios.data.scenarios.map((item) => item.id)).size : undefined;
  const runCount = runs.data?.runs.length;
  const unavailableRuns = runs.data?.unavailable_run_count ?? 0;
  const hasHistory = (runCount ?? 0) > 0 || unavailableRuns > 0;
  const executeProfiles = catalog.data?.runner_profiles.filter((profile) => profile.mode === "execute");

  return <div className="page getting-started-page">
    <PageHeader title="Start an objective" description="Choose a question, review its requirements, and keep legitimate use in scope." actions={<Link className="button button-secondary button-medium" to="/builder"><Network aria-hidden="true" />Continue working draft</Link>} />
    {DEMO_MODE ? <Callout tone="warning" title="Preview workspace">This preview uses sample data. Open the installed application to save work and run an experiment.</Callout> : null}
    <ObjectiveStart />
    <div className="start-workspace-grid">
    <section className="start-work-section start-run-options" aria-labelledby="start-mode-heading">
      <header><span className="start-section-icon"><Play aria-hidden="true" /></span><div><h2 id="start-mode-heading">Choose how to run</h2><p>Preview a plan or prepare reviewed actions.</p></div></header>
      <div className="start-modes">
        <article>
          <div className="start-mode-heading"><span><Play aria-hidden="true" /></span><div><small>Plan preview</small><h3>Simulate</h3></div></div>
          <p>Inspect a planned route without changing an environment. With AI Off, no model connection is needed.</p>
          <Link className="button button-secondary button-small" to="/runs?setup=simulate">Configure Simulate<ArrowRight aria-hidden="true" /></Link>
          <small className="start-mode-note">Simulation does not verify a detector or control.</small>
        </article>
        <article>
          <div className="start-mode-heading"><span><ShieldCheck aria-hidden="true" /></span><div><small>Environment actions</small><h3>Execute</h3></div></div>
          <p>Run reviewed actions in an authorized environment, then inspect observations and cleanup.</p>
          <Link className="button button-secondary button-small" to="/runs?setup=execute#guided-execute">Prepare Execute<ArrowRight aria-hidden="true" /></Link>
          <small className="start-mode-note">Access and a fresh approval are checked before actions run.</small>
        </article>
      </div>
    </section>
    <section className="start-work-section start-saved-work" aria-labelledby="start-saved-heading">
      <header><span className="start-section-icon"><FolderOpen aria-hidden="true" /></span><div><h2 id="start-saved-heading">{hasHistory ? "Continue your work" : "Saved experiments and results"}</h2><p>Return to a plan or its recorded results.</p></div></header>
      {scenarios.isPending || runs.isPending ? <LoadingState label="Opening saved work" /> : null}
      {scenarios.isError ? <ErrorState title="Experiments could not be loaded" error={scenarios.error} retry={() => scenarios.refetch()} /> : null}
      {runs.isError ? <ErrorState title="Run history could not be loaded" error={runs.error} retry={() => runs.refetch()} /> : null}
      {unavailableRuns ? <Callout tone="warning" title="Some run history is unavailable">{unavailableRuns} {unavailableRuns === 1 ? "record could" : "records could"} not be read. This workspace is not empty.</Callout> : null}
      <div className="start-saved-links">
        <Link to="/scenarios" aria-label="Experiments"><span className="start-saved-icon"><Network aria-hidden="true" /></span><span><strong>Experiments</strong><small>{scenarios.isError ? "Saved work could not be refreshed" : experimentCount === undefined ? "Checking saved plans" : `${experimentCount} available ${experimentCount === 1 ? "plan" : "plans"}`}</small></span><ArrowRight aria-hidden="true" /></Link>
        <Link to="/runs" aria-label="Run history"><span className="start-saved-icon"><History aria-hidden="true" /></span><span><strong>Run history</strong><small>{runs.isError ? "Recorded results could not be refreshed" : runCount === undefined ? "Checking recorded results" : `${runCount} readable ${runCount === 1 ? "run" : "runs"}`}</small></span><ArrowRight aria-hidden="true" /></Link>
      </div>
      <p className="start-work-note">Opening saved work does not start a new run or change retained defenses.</p>
    </section>
    </div>
    <details className="run-review-details start-availability">
      <summary><SlidersHorizontal aria-hidden="true" /><span><strong>Workspace availability</strong><small>Inspect service, setup, and tool status.</small></span></summary>
      <div className="readiness-list">
        <div>{catalog.isSuccess && !catalog.isFetching ? <CheckCircle2 aria-hidden="true" /> : <CircleDashed aria-hidden="true" />}<span><strong>{DEMO_MODE ? "Preview catalog" : "Local service"}</strong><small>{catalog.isPending ? DEMO_MODE ? "Checking preview data." : "Checking the installed catalog." : catalog.isError ? "The catalog request could not be completed." : DEMO_MODE ? "Sample catalog loaded. No installed service is connected." : "The installed catalog responded. Each task still checks its own requirements."}</small></span><Badge tone={catalog.isSuccess && !catalog.isFetching && !DEMO_MODE ? "success" : "neutral"}>{catalog.isPending || catalog.isFetching ? "Checking" : catalog.isError ? "Unavailable" : DEMO_MODE ? "Preview" : "Connected"}</Badge></div>
        <div><CircleDashed aria-hidden="true" /><span><strong>Experiments</strong><small>{scenarios.isError ? "Saved plans could not be refreshed." : experimentCount === undefined ? "Checking saved plans." : `${experimentCount} available.`}</small></span><Badge>{scenarios.isError ? "Unavailable" : scenarios.isPending ? "Checking" : experimentCount ? "Available" : "Empty"}</Badge></div>
        <div><CircleDashed aria-hidden="true" /><span><strong>Execute environments</strong><small>{catalog.isError || !executeProfiles ? "Configuration could not be checked." : `${executeProfiles.length} ${DEMO_MODE ? "sample profiles" : "configured"}.`} Compatibility and access are checked for the selected run.</small></span><Badge>Not checked</Badge></div>
        <div><CircleDashed aria-hidden="true" /><span><strong>Detection tools</strong><small>{detections.isPending ? "Checking installed tools." : detections.isError ? "The tool health request failed; retry before evaluation." : DEMO_MODE ? "Preview tool status does not verify an installed evaluator." : detections.data?.ready ? "The installed tools passed their health check." : "Review available evaluators in Detection Lab."}</small></span><Badge tone={detections.data?.ready && !detections.isError && !DEMO_MODE ? "success" : "neutral"}>{detections.isPending ? "Checking" : detections.isError ? "Unavailable" : DEMO_MODE ? "Preview" : detections.data?.ready ? "Available" : "Check tools"}</Badge></div>
      </div>
      {catalog.isError ? <ErrorState title="Environment catalog unavailable" error={catalog.error} retry={() => catalog.refetch()} /> : null}
      {detections.isError ? <ErrorState error={detections.error} retry={() => detections.refetch()} /> : null}
      <div className="start-availability-actions"><Link to="/environments">Review environments<ArrowRight aria-hidden="true" /></Link><Link to="/detection-lab">Open Detection Lab<ArrowRight aria-hidden="true" /></Link></div>
    </details>
  </div>;
}
