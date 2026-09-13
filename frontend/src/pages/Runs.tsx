import { useParams, useSearchParams } from "react-router-dom";
import { AssistedRunReview, SavedGraphRunSetup, SavedScenarioRunSetup } from "./AssistedRun";
import { RunWorkspace } from "../components/RunWorkspace";

export { RunReview, EvidenceDetail, DetectionDetail } from "../components/RunWorkspace";

export function RunsPage() {
  const [params] = useSearchParams();
  const { runId } = useParams<{ runId?: string }>();
  const assistanceJob = params.get("assistance_job"), graphJob = params.get("graph_job");
  if (!runId && !params.has("job") && assistanceJob !== null) return <AssistedRunReview key={assistanceJob} jobId={assistanceJob} />;
  if (!runId && !params.has("job") && graphJob !== null) return <SavedGraphRunSetup key={graphJob} jobId={graphJob} />;
  if (!runId && !params.has("job") && (params.has("saved") || params.has("saved_scenario"))) return <SavedScenarioRunSetup key={params.toString()} id={params.get("saved_scenario")} version={params.get("version")} digest={params.get("digest")} />;
  return <RunWorkspace />;
}
