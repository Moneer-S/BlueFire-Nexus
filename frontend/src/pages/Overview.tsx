import { useQuery } from "@tanstack/react-query";
import { ArrowRight, Bot, CheckCircle2, FlaskConical, Network, Play, ShieldAlert } from "lucide-react";
import { Link } from "react-router-dom";
import { api, DEMO_MODE } from "../lib/api";
import { useProduct } from "../state/ProductContext";
import { Badge, Button, ErrorState, formatDate, LoadingState, PageHeader, Panel, PanelHeader, Stat, sentence } from "../components/Primitives";

export function OverviewPage() {
  const catalog = useQuery({ queryKey: ["catalog"], queryFn: api.catalog });
  const scenarios = useQuery({ queryKey: ["scenarios"], queryFn: api.scenarios });
  const runs = useQuery({ queryKey: ["runs"], queryFn: api.runs });
  const { scenario } = useProduct();
  if (catalog.isPending || scenarios.isPending || runs.isPending) return <LoadingState label="Opening BlueFire Nexus" />;
  if (catalog.isError) return <ErrorState error={catalog.error} retry={() => catalog.refetch()} />;
  const recent = runs.data?.runs.slice(0, 4) ?? [];
  const runCount = runs.data?.runs.length ?? 0;
  const executable = catalog.data.behaviors.filter((item) => item.execution_state === "action").length;
  const activeProvider = catalog.data.ai.providers?.find((item) => item.provider_id === catalog.data.ai.active_provider) ?? catalog.data.ai.providers?.[0];
  const providerHealth = activeProvider?.health?.state ?? catalog.data.ai.provider_health;

  return <div className="page overview-page">
    <PageHeader eyebrow="Mission control" title="Design the path. Observe the defense." description="Build typed behavior graphs, simulate expected telemetry, and dispatch only approved actions through bounded runners." actions={<><Link to="/builder"><Button variant="secondary">Open builder</Button></Link><Link to="/runs"><Button variant="primary"><Play aria-hidden="true"/>Configure run</Button></Link></>} />
    {DEMO_MODE ? <div className="demo-ribbon"><FlaskConical aria-hidden="true"/><span><strong>Sanitized demo workspace</strong> Every displayed result is synthetic; Execute is preview-only.</span><Badge tone="violet">No effects</Badge></div> : null}
    <div className="stat-grid">
      <Stat label="Scenarios" value={scenarios.data?.scenarios.length ?? 0} detail="Versioned local catalog" />
      <Stat label="Behavior contracts" value={catalog.data.behaviors.length} detail={`${executable} execute-ready`} tone="success" />
      <Stat label="Registered actions" value={catalog.data.actions.length} detail="Deny by default" />
      <Stat label="Run records" value={runCount} detail={runCount ? "Canonical local bundles" : "No run history yet"} tone={runCount ? "success" : "warning"} />
    </div>
    <div className="overview-grid">
      <Panel className="mission-panel">
        <PanelHeader eyebrow="Active experiment" title={scenario.title} detail={scenario.purpose} actions={<Badge tone="info">v{scenario.id.match(/\.v(\d+)$/)?.[1] ?? "draft"}</Badge>} />
        <div className="mission-path" aria-label="Scenario flow summary" tabIndex={0}>
          {scenario.steps.slice(0, 6).map((step, index) => <div key={step.id}><span>{String(index + 1).padStart(2, "0")}</span><strong>{catalog.data.behaviors.find((item) => item.id === step.behavior_id)?.title ?? step.behavior_id}</strong><small>{step.id}</small></div>)}
        </div>
        <footer><div><Network aria-hidden="true"/><span><strong>{scenario.steps.length} typed nodes</strong><small>{scenario.edges.length} explicit outcome routes</small></span></div><Link to="/builder">Edit graph <ArrowRight aria-hidden="true"/></Link></footer>
      </Panel>
      <Panel>
        <PanelHeader eyebrow="Trust boundary" title="Readiness" detail="Configuration is not proof of runner connectivity." />
        <div className="readiness-list">
          <div><CheckCircle2 className="success"/><span><strong>Local API</strong><small>Same-origin loopback adapter</small></span><Badge tone="success">Ready</Badge></div>
          <div><CheckCircle2 className="success"/><span><strong>Simulate</strong><small>Deterministic offline planning</small></span><Badge tone="success">Ready</Badge></div>
          <div><ShieldAlert className="warning"/><span><strong>Rust runners</strong><small>Verify inventory before Execute</small></span><Badge tone="warning">Check</Badge></div>
          <div><Bot className="muted"/><span><strong>AI provider</strong><small>{activeProvider ? `${activeProvider.provider_id} · ${activeProvider.model}` : "No provider metadata reported"}</small></span><Badge tone={providerHealth === "ready" || providerHealth === "healthy" ? "success" : "neutral"}>{providerHealth ? sentence(providerHealth) : "Optional"}</Badge></div>
        </div>
        <Link className="panel-link" to="/runner-profiles">Review profiles <ArrowRight /></Link>
      </Panel>
    </div>
    <Panel>
      <PanelHeader eyebrow="Feedback loop" title="Recent runs" detail="Replay after a defense change, then compare canonical evidence—not screenshots." actions={<Link to="/compare"><Button size="small">Open compare</Button></Link>} />
      {recent.length ? <div className="table-scroll"><table><thead><tr><th>Run</th><th>Mode</th><th>Objective</th><th>Created</th><th>Status</th></tr></thead><tbody>{recent.map((run) => <tr key={run.run_id}><td><code>{run.run_id}</code>{run.is_demo ? <Badge tone="violet">Demo</Badge> : null}</td><td><Badge tone={run.mode === "execute" ? "warning" : "info"}>{run.mode}</Badge></td><td>{run.objective ?? run.scenario_id ?? "Untitled experiment"}</td><td>{formatDate(run.created_at)}</td><td><Badge tone={run.status === "completed" ? "success" : "neutral"} dot>{run.status}</Badge></td></tr>)}</tbody></table></div> : <div className="inline-empty"><span>No canonical runs yet.</span><Link to="/runs">Start with Simulate</Link></div>}
    </Panel>
  </div>;
}
