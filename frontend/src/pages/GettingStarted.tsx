import { useQuery } from "@tanstack/react-query";
import { ArrowRight, CheckCircle2, CircleDashed, Play, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";
import { Badge, Callout, ErrorState, LoadingState, PageHeader, Panel, PanelHeader } from "../components/Primitives";
import { api, DEMO_MODE } from "../lib/api";

export function GettingStartedPage() {
  const catalog = useQuery({ queryKey: ["catalog"], queryFn: api.catalog });
  const scenarios = useQuery({ queryKey: ["scenarios"], queryFn: api.scenarios });
  const runs = useQuery({ queryKey: ["runs"], queryFn: api.runs });
  const detections = useQuery({ queryKey: ["detection-health"], queryFn: api.detectionHealth });

  if (catalog.isPending || scenarios.isPending || runs.isPending) return <LoadingState label="Opening your workspace" />;
  if (catalog.isError) return <ErrorState error={catalog.error} retry={() => catalog.refetch()} />;
  if (scenarios.isError) return <ErrorState title="Experiments could not be loaded" error={scenarios.error} retry={() => scenarios.refetch()} />;
  if (runs.isError) return <ErrorState title="Run history could not be loaded" error={runs.error} retry={() => runs.refetch()} />;

  const experimentCount = new Set(scenarios.data.scenarios.map((item) => item.id)).size;
  const runCount = runs.data.runs.length;
  const unavailableRuns = runs.data.unavailable_run_count;
  const hasHistory = runCount > 0 || unavailableRuns > 0;
  const executeProfiles = catalog.data.runner_profiles.filter((profile) => profile.mode === "execute");

  return <div className="page getting-started-page">
    <PageHeader title="Start an experiment" actions={<Link className="button button-primary button-medium" to="/scenarios">Choose an experiment <ArrowRight aria-hidden="true" /></Link>} />
    {DEMO_MODE ? <Callout tone="warning" title="Preview workspace">This preview uses sample data. Open the installed application to save work and run an experiment.</Callout> : null}
    <Panel>
      <PanelHeader title={hasHistory ? "Continue your work" : "From a question to a result"} detail={unavailableRuns ? "Some run records could not be read. Open run history to inspect their status." : runCount ? `${runCount} saved ${runCount === 1 ? "run is" : "runs are"} available to inspect, evaluate and compare.` : "Choose an example or build a plan, then decide where and how to run it."} />
      {unavailableRuns ? <Callout tone="warning" title="Some run history is unavailable">{unavailableRuns} {unavailableRuns === 1 ? "record could" : "records could"} not be read. This workspace is not empty.</Callout> : null}
      <div className="review-path">
        <article><span>01</span><div><strong>Choose what to test</strong><small>Open an example or create your own experiment.</small></div><Link to="/scenarios">Experiments <ArrowRight aria-hidden="true" /></Link></article>
        <article><span>02</span><div><strong>Edit the plan</strong><small>Inspect steps, methods, inputs and possible outcomes.</small></div><Link to="/builder">Build <ArrowRight aria-hidden="true" /></Link></article>
        <article><span>03</span><div><strong>Review and run</strong><small>Choose the environment, requested access and observations before approval.</small></div><Link to="/runs?setup=execute">Review a run <ArrowRight aria-hidden="true" /></Link></article>
        <article><span>04</span><div><strong>Evaluate and repeat</strong><small>Inspect the observed data, improve a rule and compare a repeat.</small></div><Link to="/runs">Run history <ArrowRight aria-hidden="true" /></Link></article>
      </div>
    </Panel>
    <Panel>
      <PanelHeader title="Choose how to run" />
      <div className="review-path">
        <article><Play aria-hidden="true" /><div><strong>Simulate</strong><small>Preview the plan without effects. AI Off needs no model connection; simulation does not verify a detector or control.</small></div><Link className="button button-secondary button-small" to="/runs?setup=simulate">Configure Simulate</Link></article>
        <article><ShieldCheck aria-hidden="true" /><div><strong>Execute</strong><small>Perform the reviewed actions in an authorized environment. Check access, observations and cleanup before releasing a fresh approval.</small></div><Link className="button button-secondary button-small" to="/runs?setup=execute#guided-execute">Prepare Execute</Link></article>
      </div>
    </Panel>
    <details className="run-review-details">
      <summary>Workspace availability</summary>
      <div className="readiness-list">
        <div><CheckCircle2 aria-hidden="true" /><span><strong>Local service</strong><small>The catalog and saved-work lists responded.</small></span><Badge tone="success">Connected</Badge></div>
        <div><CircleDashed aria-hidden="true" /><span><strong>Experiments</strong><small>{experimentCount} {experimentCount === 1 ? "experiment" : "experiments"} available.</small></span><Badge>{experimentCount ? "Available" : "Empty"}</Badge></div>
        <div><CircleDashed aria-hidden="true" /><span><strong>Execute environments</strong><small>{executeProfiles.length} configured. Compatibility and access are checked for the selected run.</small></span><Badge>Not checked</Badge></div>
        <div><CircleDashed aria-hidden="true" /><span><strong>Detection tools</strong><small>{detections.isPending ? "Checking installed tools." : detections.isError ? "The tool health request failed; retry before evaluation." : detections.data?.ready ? "The installed tools passed their health check." : "Review available evaluators in Detection Lab."}</small></span><Badge tone={detections.data?.ready && !detections.isError ? "success" : "neutral"}>{detections.isPending ? "Checking" : detections.isError ? "Unavailable" : detections.data?.ready ? "Available" : "Check tools"}</Badge></div>
      </div>
      {detections.isError ? <ErrorState error={detections.error} retry={() => detections.refetch()} /> : null}
    </details>
  </div>;
}
