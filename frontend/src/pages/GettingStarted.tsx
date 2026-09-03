import { useQuery } from "@tanstack/react-query";
import {
  ArrowRight,
  CheckCircle2,
  CircleDashed,
  FlaskConical,
  Play,
  ShieldAlert,
} from "lucide-react";
import { Link } from "react-router-dom";
import {
  Badge,
  Button,
  Callout,
  DataList,
  ErrorState,
  LoadingState,
  PageHeader,
  Panel,
  PanelHeader,
  sentence,
} from "../components/Primitives";
import { api, DEMO_MODE } from "../lib/api";

export function GettingStartedPage() {
  const catalog = useQuery({ queryKey: ["catalog"], queryFn: api.catalog });
  const scenarios = useQuery({ queryKey: ["scenarios"], queryFn: api.scenarios });
  const runs = useQuery({ queryKey: ["runs"], queryFn: api.runs });
  const detections = useQuery({
    queryKey: ["detection-health"],
    queryFn: api.detectionHealth,
  });

  if (catalog.isPending || scenarios.isPending || runs.isPending) {
    return <LoadingState label="Checking local product readiness" />;
  }
  if (catalog.isError) {
    return <ErrorState error={catalog.error} retry={() => catalog.refetch()} />;
  }

  const scenarioCount = scenarios.data?.scenarios.length ?? 0;
  const runCount = runs.data?.runs.length ?? 0;
  const executeProfiles = catalog.data.runner_profiles.filter(
    (profile) => profile.mode === "execute",
  );
  const activeProvider = catalog.data.ai.providers?.find(
    (provider) => provider.provider_id === catalog.data.ai.active_provider,
  );
  const providerState = activeProvider?.health?.state ?? catalog.data.ai.provider_health;

  return (
    <div className="page getting-started-page">
      <PageHeader
        eyebrow="First-run guide"
        title="Prove the safe path first"
        description="Confirm the local control plane, complete one deterministic Simulate run, or follow the guided local Execute path when you have an authorized disposable runner-owned sandbox."
        actions={
          <><Link to="/runs"><Button variant="primary"><Play aria-hidden="true" /> Configure Simulate</Button></Link><Link to="/runs#guided-execute"><Button variant="secondary"><ShieldAlert aria-hidden="true" /> Prepare guided Execute</Button></Link></>
        }
      />
      {DEMO_MODE ? (
        <Callout tone="warning" title="Demo mode is preview-only">
          This workspace uses sanitized synthetic fixtures. Use the Python-backed local service to
          create canonical run bundles or probe a real runner.
        </Callout>
      ) : null}
      {runCount ? (
        <Callout tone="success" title="A canonical first run exists">
          {runCount} durable run {runCount === 1 ? "record is" : "records are"} available. Open
          history to review evidence, replay, or compare.
        </Callout>
      ) : (
        <Callout title="No canonical run yet">
          Keep effect mode on Simulate and AI autonomy Off for the first run. No runner or provider
          credential is required.
        </Callout>
      )}

      <div className="two-column">
        <Panel>
          <PanelHeader
            eyebrow="Readiness"
            title="Local prerequisites"
            detail="Configured is not the same as dynamically proven."
          />
          <div className="readiness-list">
            <div>
              <CheckCircle2 className="success" aria-hidden="true" />
              <span>
                <strong>Control plane</strong>
                <small>Catalog responded through the loopback API</small>
              </span>
              <Badge tone="success">Ready</Badge>
            </div>
            <div>
              {scenarioCount ? (
                <CheckCircle2 className="success" aria-hidden="true" />
              ) : (
                <ShieldAlert className="warning" aria-hidden="true" />
              )}
              <span>
                <strong>Scenario registry</strong>
                <small>{scenarioCount} active durable graph{scenarioCount === 1 ? "" : "s"}</small>
              </span>
              <Badge tone={scenarioCount ? "success" : "danger"}>
                {scenarioCount ? "Ready" : "Empty"}
              </Badge>
            </div>
            <div>
              <CheckCircle2 className="success" aria-hidden="true" />
              <span>
                <strong>Deterministic Simulate</strong>
                <small>AI Off bypasses model-provider calls</small>
              </span>
              <Badge tone="success">Ready</Badge>
            </div>
            <div>
              <CircleDashed className="muted" aria-hidden="true" />
              <span>
                <strong>Execute runner</strong>
                <small>{executeProfiles.length} profile{executeProfiles.length === 1 ? "" : "s"}; exact inventory and sandbox probe still required</small>
              </span>
              <Badge tone="warning">Not proven</Badge>
            </div>
            <div>
              <FlaskConical className={detections.data?.ready ? "success" : "muted"} aria-hidden="true" />
              <span>
                <strong>Detection adapters</strong>
                <small>Optional for the first Simulate run</small>
              </span>
              <Badge tone={detections.data?.ready ? "success" : "neutral"}>
                {detections.isError ? "Check health" : detections.data?.ready ? "Ready" : "Optional"}
              </Badge>
            </div>
          </div>
        </Panel>

        <Panel>
          <PanelHeader eyebrow="Safe defaults" title="What the first run will prove" />
          <DataList
            items={[
              { label: "Effect mode", value: "Simulate · no external effects" },
              { label: "AI autonomy", value: "Off · no provider call" },
              { label: "Provider", value: activeProvider ? `${activeProvider.provider_id} · ${sentence(providerState ?? "optional")}` : "Not required" },
              { label: "Scope", value: "Modeled sandbox.workspace" },
              { label: "Result", value: "Canonical local run bundle" },
              { label: "Evidence", value: "Synthetic or counterfactual; never relabeled as observed" },
            ]}
          />
          <Callout title="Execute remains a separate decision">
            A completed Simulate run does not prove the Rust runner, host controls, or independent
            collectors. The guided Execute path performs a fresh identity/inventory/sandbox probe,
            selects a seeded sandbox scenario, preflights the exact intent, and still requires a
            fresh one-time job approval.
          </Callout>
        </Panel>
      </div>

      <Panel>
        <PanelHeader
          eyebrow="Walkthrough"
          title="Scenario to durable review"
          detail="Complete these in order; each link keeps the next decision explicit."
        />
        <div className="review-path">
          <article>
            <span>01</span>
            <div><strong>Choose a scenario</strong><small>Read purpose, limitations, and provenance.</small></div>
            <Link to="/scenarios">Open scenarios <ArrowRight aria-hidden="true" /></Link>
          </article>
          <article>
            <span>02</span>
            <div><strong>Validate the graph</strong><small>Inspect typed nodes, routes, artifacts, and cleanup.</small></div>
            <Link to="/builder">Open builder <ArrowRight aria-hidden="true" /></Link>
          </article>
          <article>
            <span>03</span>
            <div><strong>Run deterministic preflight</strong><small>Keep Simulate and AI Off; resolve every finding.</small></div>
            <Link to="/runs">Configure run <ArrowRight aria-hidden="true" /></Link>
          </article>
          <article>
            <span>04</span>
            <div><strong>Review the durable result</strong><small>Separate modeled evidence, limitations, and cleanup.</small></div>
            <Link to={runCount ? "/runs" : "/help"}>{runCount ? "Open history" : "Read concepts"} <ArrowRight aria-hidden="true" /></Link>
          </article>
        </div>
      </Panel>
    </div>
  );
}
