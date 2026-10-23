import { useQuery } from "@tanstack/react-query";
import { ArrowRight, CheckCircle2, CircleDashed, FolderOpen, Network, Play, ShieldCheck } from "lucide-react";
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
    <PageHeader title="Start an objective" description="Access, legitimate use, and the change you want to validate." actions={<Link className="button button-secondary button-medium" to="/builder"><Network aria-hidden="true" />Continue working draft</Link>} />
    {DEMO_MODE ? <Callout tone="warning" title="Preview workspace">This preview uses sample data. Open the installed application to save work and run an experiment.</Callout> : null}
    <ObjectiveStart />
    <div className="start-workspace-grid">
    <section className="start-work-section" aria-labelledby="start-saved-heading">
      <header><FolderOpen aria-hidden="true" /><h2 id="start-saved-heading">{hasHistory ? "Continue your work" : "Saved experiments and results"}</h2></header>
      {scenarios.isPending || runs.isPending ? <LoadingState label="Opening saved work" /> : null}
      {scenarios.isError ? <ErrorState title="Experiments could not be loaded" error={scenarios.error} retry={() => scenarios.refetch()} /> : null}
      {runs.isError ? <ErrorState title="Run history could not be loaded" error={runs.error} retry={() => runs.refetch()} /> : null}
      {unavailableRuns ? <Callout tone="warning" title="Some run history is unavailable">{unavailableRuns} {unavailableRuns === 1 ? "record could" : "records could"} not be read. This workspace is not empty.</Callout> : null}
      <div className="start-saved-links">
        <Link to="/scenarios" aria-label="Experiments"><span><strong>Experiments</strong><small>{scenarios.isError ? "Saved work could not be refreshed" : experimentCount === undefined ? "Checking saved plans" : `${experimentCount} available ${experimentCount === 1 ? "plan" : "plans"}`}</small></span><ArrowRight aria-hidden="true" /></Link>
        <Link to="/runs" aria-label="Run history"><span><strong>Run history</strong><small>{runs.isError ? "Recorded results could not be refreshed" : runCount === undefined ? "Checking recorded results" : `${runCount} readable ${runCount === 1 ? "run" : "runs"}`}</small></span><ArrowRight aria-hidden="true" /></Link>
      </div>
      <p className="start-work-note">Saved plans, observations, and retained changes remain separate from new execution approvals.</p>
    </section>
    <section className="start-work-section" aria-labelledby="start-mode-heading">
      <header><Play aria-hidden="true" /><h2 id="start-mode-heading">Choose how to run</h2></header>
      <div className="start-modes">
        <article><Play aria-hidden="true" /><div><strong>Simulate</strong><small>Preview the plan without effects. AI Off needs no model connection; simulation does not verify a detector or control.</small></div><Link className="button button-secondary button-small" to="/runs?setup=simulate">Configure Simulate</Link></article>
        <article><ShieldCheck aria-hidden="true" /><div><strong>Execute</strong><small>Perform the reviewed actions in an authorized environment. Check access, observations and cleanup before releasing a fresh approval.</small></div><Link className="button button-secondary button-small" to="/runs?setup=execute#guided-execute">Prepare Execute</Link></article>
      </div>
    </section>
    </div>
    <details className="run-review-details start-availability">
      <summary>Workspace availability</summary>
      <div className="readiness-list">
        <div>{catalog.isSuccess && !catalog.isFetching ? <CheckCircle2 aria-hidden="true" /> : <CircleDashed aria-hidden="true" />}<span><strong>Local service</strong><small>{catalog.isPending ? "Checking the installed catalog." : catalog.isError ? "The catalog request could not be completed." : "The installed catalog responded. Each task still checks its own requirements."}</small></span><Badge tone={catalog.isSuccess && !catalog.isFetching ? "success" : "neutral"}>{catalog.isPending || catalog.isFetching ? "Checking" : catalog.isError ? "Unavailable" : "Connected"}</Badge></div>
        <div><CircleDashed aria-hidden="true" /><span><strong>Experiments</strong><small>{scenarios.isError ? "Saved plans could not be refreshed." : experimentCount === undefined ? "Checking saved plans." : `${experimentCount} available.`}</small></span><Badge>{scenarios.isError ? "Unavailable" : scenarios.isPending ? "Checking" : experimentCount ? "Available" : "Empty"}</Badge></div>
        <div><CircleDashed aria-hidden="true" /><span><strong>Execute environments</strong><small>{executeProfiles ? `${executeProfiles.length} configured.` : "Configuration could not be checked."} Compatibility and access are checked for the selected run.</small></span><Badge>Not checked</Badge></div>
        <div><CircleDashed aria-hidden="true" /><span><strong>Detection tools</strong><small>{detections.isPending ? "Checking installed tools." : detections.isError ? "The tool health request failed; retry before evaluation." : detections.data?.ready ? "The installed tools passed their health check." : "Review available evaluators in Detection Lab."}</small></span><Badge tone={detections.data?.ready && !detections.isError ? "success" : "neutral"}>{detections.isPending ? "Checking" : detections.isError ? "Unavailable" : detections.data?.ready ? "Available" : "Check tools"}</Badge></div>
      </div>
      {catalog.isError ? <ErrorState title="Environment catalog unavailable" error={catalog.error} retry={() => catalog.refetch()} /> : null}
      {detections.isError ? <ErrorState error={detections.error} retry={() => detections.refetch()} /> : null}
    </details>
  </div>;
}
