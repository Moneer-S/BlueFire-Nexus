import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Beaker, CheckCircle2, Code2, FileCheck2, FlaskConical, Plus, Search, ShieldQuestion } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { api } from "../lib/api";
import type {
  DetectionCandidate,
  DetectionCloneRequest,
  DetectionComparisonResponse,
  DetectionResource,
  DetectionSetDelta,
  DetectionTuneRequest,
  ManagedResource,
  PublicBaselineReference,
  RunRecord,
} from "../types";
import { Badge, Button, Callout, DataList, EmptyState, ErrorState, Field, LoadingState, PageHeader, Panel, PanelHeader, sentence } from "../components/Primitives";

const lifecycle = ["hypothesis", "parsed", "fixture_exercised", "observed_exercised", "benign_evaluated", "rejected"];
const baselineRelationships = new Set(["imported", "adapted", "inspired", "comparative"]);
const baselineReviews = new Set(["reviewed", "conditional", "prohibited"]);
const baselineUseClassifications = new Set(["reference_only", "metadata_import", "clean_reimplementation", "external_adapter", "compatible_code_adaptation", "incompatible_or_restricted"]);
const baselineUpdateStatuses = new Set(["current", "review_due", "superseded", "blocked"]);

type CandidateView = DetectionCandidate & { resolvedId: string; resourceId?: string; runId?: string; demo?: boolean };

interface ResearchSourceDocument extends Record<string, unknown> {
  name?: string;
  authority?: string;
  pin?: string;
  version?: string;
  exact_ref?: string;
  retrieved_at?: string;
  license?: string;
  file_level_license_review?: string;
  trademark_considerations?: string;
  license_review?: string;
  relationship?: string;
  use_classification?: string;
  uses?: unknown;
  attribution?: string;
  security_review?: string;
  last_verified_at?: string;
  update_status?: string;
}

type ResearchSourceResource = ManagedResource<ResearchSourceDocument>;
type RevisionKind = "clone" | "tune";
type LifecycleAction = "parse" | "exercise-fixtures" | "exercise-observed" | "evaluate-benign" | "reject";

function publicBaselineFromSource(resource: ResearchSourceResource): PublicBaselineReference | undefined {
  const source = resource.document;
  const uses = Array.isArray(source.uses) ? source.uses.filter((item): item is string => typeof item === "string") : [];
  if (
    resource.status !== "pinned"
    || !uses.includes("comparison")
    || typeof resource.digest !== "string"
    || !/^sha256:[0-9a-f]{64}$/.test(resource.digest)
    || typeof source.pin !== "string"
    || typeof source.version !== "string"
    || typeof source.exact_ref !== "string"
    || typeof source.retrieved_at !== "string"
    || typeof source.license !== "string"
    || typeof source.file_level_license_review !== "string"
    || typeof source.trademark_considerations !== "string"
    || typeof source.license_review !== "string"
    || !baselineReviews.has(source.license_review)
    || typeof source.relationship !== "string"
    || !baselineRelationships.has(source.relationship)
    || typeof source.use_classification !== "string"
    || !baselineUseClassifications.has(source.use_classification)
    || typeof source.attribution !== "string"
    || typeof source.security_review !== "string"
    || typeof source.last_verified_at !== "string"
    || typeof source.update_status !== "string"
    || !baselineUpdateStatuses.has(source.update_status)
  ) return undefined;
  return {
    schema_version: "bluefire.public-baseline.v2",
    research_source_id: resource.id,
    source_digest: resource.digest,
    pin: source.pin,
    version: source.version,
    exact_ref: source.exact_ref,
    retrieved_at: source.retrieved_at,
    license: source.license,
    file_level_license_review: source.file_level_license_review,
    trademark_considerations: source.trademark_considerations,
    license_review: source.license_review as PublicBaselineReference["license_review"],
    relationship: source.relationship as PublicBaselineReference["relationship"],
    use_classification: source.use_classification as PublicBaselineReference["use_classification"],
    use: "comparison",
    attribution: source.attribution,
    security_review: source.security_review,
    last_verified_at: source.last_verified_at,
    update_status: source.update_status,
  };
}

function listText(values?: string[]) {
  return values?.length ? values.map(sentence).join(", ") : "None";
}

function driftText(value: Record<string, string[]>) {
  const entries = Object.entries(value);
  return entries.length ? entries.map(([field, mappings]) => `${field}: ${mappings.join(", ") || "none"}`).join(" · ") : "None";
}

function shortDigest(value: string) {
  return value.length > 24 ? `${value.slice(0, 15)}…${value.slice(-8)}` : value;
}

export function DetectionLabPage() {
  const runsQuery = useQuery({ queryKey: ["runs"], queryFn: api.runs });
  const catalogQuery = useQuery({ queryKey: ["catalog"], queryFn: api.catalog });
  const healthQuery = useQuery({ queryKey: ["detection-health"], queryFn: api.detectionHealth });
  const candidatesQuery = useQuery({ queryKey: ["detections"], queryFn: api.detections });
  const researchSourcesQuery = useQuery({
    queryKey: ["resources", "research-sources"],
    queryFn: () => api.resources<ResearchSourceDocument>("research-sources"),
  });
  const client = useQueryClient();
  const [search, setSearch] = useState("");
  const [selectedId, setSelectedId] = useState<string>();
  const [notice, setNotice] = useState<string>();
  const [title, setTitle] = useState("Sandbox staging observation");
  const [behaviorId, setBehaviorId] = useState("sandbox.collection.stage.v1");
  const [language, setLanguage] = useState("internal");

  const refreshDetections = () => {
    void client.invalidateQueries({ queryKey: ["detections"] });
    void client.invalidateQueries({ queryKey: ["detection-health"] });
  };
  const createMutation = useMutation({
    mutationFn: () => api.upsertDetection({
      behavior_id: behaviorId,
      title,
      target_language: language,
      logsource: { category: "file_event", product: "generic" },
      selection: { artifact_type: "file_observation", "path|contains": "staged/" },
      provenance: { source: "operator-authored", license: "Review required" },
      known_misses: ["Requires declared observation fields."],
      predicted_fields: ["artifact_type", "path"],
    }),
    onSuccess: ({ candidate }) => {
      setSelectedId(candidate.id);
      setNotice(`${candidate.id} saved as a strict hypothesis. It has not been parsed or exercised.`);
      refreshDetections();
    },
    onError: (error) => setNotice(error instanceof Error ? error.message : "The hypothesis could not be saved."),
  });
  const actionMutation = useMutation({
    mutationFn: ({ id, action, body }: { id: string; action: LifecycleAction; body: Record<string, unknown> }) => api.detectionAction(id, action, body),
    onSuccess: ({ candidate }) => {
      setNotice(`${candidate.id} advanced honestly to ${sentence(candidate.status)}.`);
      refreshDetections();
    },
    onError: (error) => setNotice(error instanceof Error ? error.message : "The lifecycle action was refused."),
  });
  const revisionMutation = useMutation({
    mutationFn: ({ id, kind, body }: { id: string; kind: RevisionKind; body: DetectionCloneRequest | DetectionTuneRequest }) => kind === "clone"
      ? api.cloneDetection(id, body as DetectionCloneRequest)
      : api.tuneDetection(id, body as DetectionTuneRequest),
    onSuccess: ({ candidate }) => {
      setSelectedId(candidate.id);
      setNotice(`${candidate.id} saved as a new immutable detection revision. Its parent candidate was not changed.`);
      comparisonMutation.reset();
      refreshDetections();
    },
    onError: (error) => setNotice(error instanceof Error ? error.message : "The immutable revision was refused."),
  });
  const comparisonMutation = useMutation({
    mutationFn: ({ baselineId, candidateId }: { baselineId: string; candidateId: string }) => api.compareDetections(baselineId, candidateId),
    onError: (error) => setNotice(error instanceof Error ? error.message : "The revision comparison was refused."),
  });

  if (runsQuery.isPending || catalogQuery.isPending || candidatesQuery.isPending || healthQuery.isPending) return <LoadingState label="Opening Detection Lab" />;
  if (runsQuery.isError) return <ErrorState error={runsQuery.error} retry={() => { void runsQuery.refetch(); }} />;
  if (catalogQuery.isError) return <ErrorState error={catalogQuery.error} retry={() => { void catalogQuery.refetch(); }} />;
  if (candidatesQuery.isError) return <ErrorState title="Detection registry unavailable" error={candidatesQuery.error} retry={() => { void candidatesQuery.refetch(); }} />;
  if (healthQuery.isError) return <ErrorState title="Detection health unavailable" error={healthQuery.error} retry={() => { void healthQuery.refetch(); }} />;

  const persisted: CandidateView[] = candidatesQuery.data.candidates.map((resource) => ({
    ...(resource.document as DetectionCandidate),
    state: String(resource.document.state ?? resource.status),
    candidate_id: String(resource.document.candidate_id ?? resource.id),
    resolvedId: resource.id,
    resourceId: resource.id,
  }));
  const linked: CandidateView[] = runsQuery.data.runs.flatMap((run) => (run.detections?.candidates ?? []).map((candidate, index) => ({
    ...candidate,
    resolvedId: candidate.candidate_id ?? candidate.id ?? `${run.run_id}-${index}`,
    runId: run.run_id,
    demo: run.is_demo,
  })));
  const candidates = [...new Map([...persisted, ...linked].map((item) => [item.resolvedId, item])).values()];
  const filtered = candidates.filter((item) => `${item.resolvedId} ${item.title ?? ""} ${item.behavior_id ?? ""} ${item.target_language ?? item.language ?? ""}`.toLowerCase().includes(search.toLowerCase()));
  const selected = filtered.find((item) => item.resolvedId === selectedId) ?? filtered[0];
  const counts = Object.fromEntries(lifecycle.map((state) => [state, candidates.filter((item) => item.state === state).length]));
  const finalizedRuns = runsQuery.data.runs.filter((run) => Boolean(run.finalized_at) || run.status === "completed");
  const rootId = selected?.revision_root_id ?? selected?.candidate_id ?? selected?.resolvedId;
  const lineage = persisted
    .filter((item) => (item.revision_root_id ?? item.candidate_id ?? item.resolvedId) === rootId)
    .sort((left, right) => (left.revision ?? 1) - (right.revision ?? 1));
  const sources = researchSourcesQuery.data?.resources ?? [];

  return <div className="page detection-page">
    <PageHeader eyebrow="Detection research" title="Detection Lab" description="Persist strict behavior-linked hypotheses, preserve immutable revision lineage, and advance only through parser, fixture, observed-evidence, benign, or rejection stages the control plane actually completed." />
    {notice ? <Callout title="Detection control plane">{notice}</Callout> : null}
    <div className="two-column">
      <Panel>
        <PanelHeader eyebrow="New hypothesis" title="Behavior-linked candidate" />
        <div className="detail-body">
          <Field label="Title"><input value={title} onChange={(event) => setTitle(event.target.value)} maxLength={200} /></Field>
          <Field label="Registered behavior"><select value={behaviorId} onChange={(event) => setBehaviorId(event.target.value)}>{catalogQuery.data.behaviors.map((behavior) => <option key={behavior.id} value={behavior.id}>{behavior.title}</option>)}</select></Field>
          <Field label="Target language"><select value={language} onChange={(event) => setLanguage(event.target.value)}><option value="internal">Internal structured matcher</option><option value="sigma">Sigma</option><option value="yara">YARA</option><option value="yara-l">YARA-L</option><option value="spl">SPL structural check</option></select></Field>
          <Button variant="primary" onClick={() => createMutation.mutate()} disabled={createMutation.isPending || !title || !behaviorId}><Plus />Save strict hypothesis</Button>
        </div>
      </Panel>
      <Panel>
        <PanelHeader eyebrow="Backend readiness" title="Honest parser health" actions={<Badge tone={healthQuery.data.ready ? "success" : "warning"} dot>{healthQuery.data.ready ? "Persistence ready" : "Degraded"}</Badge>} />
        <div className="detail-body">{Object.entries(healthQuery.data.languages).map(([id, backend]) => <article className="secret-row" key={id}><span><Code2 /></span><div><strong>{sentence(id)}</strong><small>{backend.backend} · {backend.version ?? "Version unavailable"}</small></div><div className="row-badges"><Badge tone={backend.ready ? "success" : "warning"}>{backend.ready ? "Ready" : "Unavailable"}</Badge><Badge tone={backend.authoritative ? "info" : "neutral"}>{backend.authoritative ? "Authoritative" : "Structural only"}</Badge></div></article>)}</div>
      </Panel>
    </div>
    <Callout title="Lifecycle semantics">Rendered text is not validation. SPL structural success remains a hypothesis. Observed exercise accepts only verified, immutable, independently observed evidence records. Clone and tune create new content-addressed candidates; they never rewrite their parent.</Callout>
    <div className="lifecycle-strip" aria-label="Detection lifecycle counts">{lifecycle.map((state, index) => <div key={state} className={state === "rejected" ? "rejected" : ""}><span>{index + 1}</span><strong>{sentence(state)}</strong><em>{counts[state]}</em></div>)}</div>
    <div className="detection-layout">
      <Panel className="candidate-list">
        <div className="history-search"><Search /><input aria-label="Search detection candidates" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search candidate, behavior, language" /></div>
        <div>{filtered.map((item) => <button key={item.resolvedId} className={selected?.resolvedId === item.resolvedId ? "selected" : ""} onClick={() => { setSelectedId(item.resolvedId); comparisonMutation.reset(); }}><span className="candidate-icon"><ShieldQuestion /></span><span><strong>{item.title ?? item.resolvedId}</strong><code>{item.behavior_id ?? item.resolvedId}</code><small>{item.revision ? `Revision ${item.revision} · ${sentence(item.revision_kind ?? "origin")}` : item.summary ?? `${sentence(item.target_language ?? item.language ?? "unknown")} candidate`}</small></span><span><Badge tone={item.state === "rejected" ? "danger" : item.state === "hypothesis" ? "neutral" : "success"}>{sentence(item.state)}</Badge>{item.demo ? <Badge tone="violet">Demo</Badge> : null}</span></button>)}</div>
        {!filtered.length ? <EmptyState title="No candidates" description="Create a hypothesis or complete a run that generates detection research records." /> : null}
      </Panel>
      {selected ? <CandidateWorkspace
        candidate={selected}
        resource={candidatesQuery.data.candidates.find((item) => item.id === selected.resourceId)}
        backend={healthQuery.data.languages[selected.target_language ?? selected.language ?? "internal"]}
        finalizedRuns={finalizedRuns}
        lineage={lineage}
        researchSources={sources}
        researchSourcesUnavailable={researchSourcesQuery.isError}
        lifecyclePending={actionMutation.isPending}
        revisionPending={revisionMutation.isPending}
        comparisonPending={comparisonMutation.isPending}
        comparison={comparisonMutation.data}
        onAction={(action, body) => selected.resourceId && actionMutation.mutate({ id: selected.resourceId, action, body })}
        onRevision={(kind, body) => selected.resourceId && revisionMutation.mutate({ id: selected.resourceId, kind, body })}
        onCompare={(candidateId) => selected.resourceId && comparisonMutation.mutate({ baselineId: selected.resourceId, candidateId })}
      /> : <Panel><EmptyState icon={<FlaskConical />} title="Select a candidate" description="Inspect lifecycle evidence, fixtures, fields, immutable revisions, and reviewed public baselines." /></Panel>}
    </div>
  </div>;
}

function CandidateWorkspace({
  candidate,
  resource,
  backend,
  finalizedRuns,
  lineage,
  researchSources,
  researchSourcesUnavailable,
  lifecyclePending,
  revisionPending,
  comparisonPending,
  comparison,
  onAction,
  onRevision,
  onCompare,
}: {
  candidate: CandidateView;
  resource?: DetectionResource;
  backend?: { ready: boolean; authoritative: boolean; backend: string; version?: string | null };
  finalizedRuns: RunRecord[];
  lineage: CandidateView[];
  researchSources: ResearchSourceResource[];
  researchSourcesUnavailable: boolean;
  lifecyclePending: boolean;
  revisionPending: boolean;
  comparisonPending: boolean;
  comparison?: DetectionComparisonResponse;
  onAction: (action: LifecycleAction, body: Record<string, unknown>) => void;
  onRevision: (kind: RevisionKind, body: DetectionCloneRequest | DetectionTuneRequest) => void;
  onCompare: (candidateId: string) => void;
}) {
  const [tab, setTab] = useState<"candidate" | "revisions" | "fixtures" | "observed" | "history">("candidate");
  const [source, setSource] = useState("");
  const [fixtures, setFixtures] = useState('[{"fixture_id":"malicious-1","artifact_type":"file_observation","path":"staged/a.txt"}]');
  const [benign, setBenign] = useState('[{"fixture_id":"benign-1","artifact_type":"file_observation","path":"documents/a.txt"}]');
  const [notes, setNotes] = useState("Declared benign fixture did not match.");
  const [runId, setRunId] = useState("");
  const [evidenceIds, setEvidenceIds] = useState("");
  const [reason, setReason] = useState("");
  const [localError, setLocalError] = useState<string>();
  const [revisionKind, setRevisionKind] = useState<RevisionKind>("clone");
  const [revisionReason, setRevisionReason] = useState("");
  const [revisionTitle, setRevisionTitle] = useState(candidate.title ?? "");
  const [selectionJson, setSelectionJson] = useState(JSON.stringify(candidate.selection ?? {}, null, 2));
  const [logsourceJson, setLogsourceJson] = useState(JSON.stringify(candidate.logsource ?? {}, null, 2));
  const [selectedBaselineIds, setSelectedBaselineIds] = useState<string[]>(candidate.public_baselines?.map((item) => item.research_source_id) ?? []);
  const [compareId, setCompareId] = useState("");

  const language = candidate.target_language ?? candidate.language ?? "internal";
  const storedSource = candidate.rule_source ?? source;
  const code = useMemo(() => storedSource || (language === "internal" ? JSON.stringify({ logsource: candidate.logsource ?? {}, selection: candidate.selection ?? {} }, null, 2) : ""), [candidate.logsource, candidate.selection, language, storedSource]);
  const selectionSeed = JSON.stringify(candidate.selection ?? {}, null, 2);
  const logsourceSeed = JSON.stringify(candidate.logsource ?? {}, null, 2);
  const baselineSeed = candidate.public_baselines?.map((item) => item.research_source_id).join("|") ?? "";
  const comparisonChoices = lineage.filter((item) => item.resourceId && item.resolvedId !== candidate.resolvedId);
  const lineageSeed = comparisonChoices.map((item) => item.resolvedId).join("|");
  const defaultCompareId = comparisonChoices[0]?.resourceId ?? "";

  useEffect(() => {
    const yara = language === "yara" || language === "yara-l";
    setFixtures(yara ? '[{"fixture_id":"malicious-1","data":"bounded fixture text"}]' : '[{"fixture_id":"malicious-1","artifact_type":"file_observation","path":"staged/a.txt"}]');
    setBenign(yara ? '[{"fixture_id":"benign-1","data":"ordinary fixture text"}]' : '[{"fixture_id":"benign-1","artifact_type":"file_observation","path":"documents/a.txt"}]');
    setSource(candidate.rule_source ?? "");
    setRevisionKind("clone");
    setRevisionReason("");
    setRevisionTitle(candidate.title ?? "");
    setSelectionJson(selectionSeed);
    setLogsourceJson(logsourceSeed);
    setSelectedBaselineIds(baselineSeed ? baselineSeed.split("|") : []);
    setLocalError(undefined);
  }, [baselineSeed, candidate.resolvedId, candidate.rule_source, candidate.title, language, logsourceSeed, selectionSeed]);

  useEffect(() => {
    setCompareId(defaultCompareId);
  }, [candidate.resolvedId, defaultCompareId, lineageSeed]);

  const authoritativeParsed = Boolean(backend?.authoritative && candidate.parser_backend?.name && candidate.state !== "hypothesis");
  const persisted = Boolean(resource);
  const canParse = persisted && candidate.state === "hypothesis";
  const canFixture = persisted && candidate.state === "parsed";
  const canObserved = persisted && ["internal", "sigma"].includes(language) && ["parsed", "fixture_exercised"].includes(candidate.state);
  const canBenign = persisted && ["fixture_exercised", "observed_exercised"].includes(candidate.state);
  const canReject = persisted && candidate.state !== "rejected";
  const availableBaselines = useMemo(() => researchSources.map(publicBaselineFromSource).filter((item): item is PublicBaselineReference => Boolean(item)), [researchSources]);
  const selectableBaselines = useMemo(() => {
    const indexed = new Map(availableBaselines.map((item) => [item.research_source_id, item]));
    for (const item of candidate.public_baselines ?? []) if (!indexed.has(item.research_source_id)) indexed.set(item.research_source_id, item);
    return [...indexed.values()];
  }, [availableBaselines, candidate.public_baselines]);
  const sourcesById = useMemo(() => new Map(researchSources.map((item) => [item.id, item])), [researchSources]);

  const submitFixtures = (action: "exercise-fixtures" | "evaluate-benign") => {
    try {
      const value = JSON.parse(action === "exercise-fixtures" ? fixtures : benign) as unknown;
      if (!Array.isArray(value)) throw new Error("Fixtures must be a JSON array.");
      setLocalError(undefined);
      onAction(action, action === "exercise-fixtures" ? { fixtures: value } : { fixtures: value, notes: notes.split("\n").map((item) => item.trim()).filter(Boolean) });
    } catch (error) {
      setLocalError(error instanceof Error ? error.message : "Fixture JSON is invalid.");
    }
  };
  const submitRevision = () => {
    try {
      if (!revisionReason.trim()) throw new Error("Explain why this immutable revision is needed.");
      const selectedBaselines = selectableBaselines.filter((item) => selectedBaselineIds.includes(item.research_source_id));
      const common: DetectionCloneRequest = {
        reason: revisionReason.trim(),
        ...(revisionTitle.trim() ? { title: revisionTitle.trim() } : {}),
        ...(candidate.provenance ? { provenance: candidate.provenance } : {}),
        ...(candidate.known_misses ? { known_misses: candidate.known_misses } : {}),
        public_baselines: selectedBaselines,
        ...(candidate.predicted_fields ? { predicted_fields: candidate.predicted_fields } : {}),
      };
      if (revisionKind === "clone") {
        setLocalError(undefined);
        onRevision("clone", common);
        return;
      }
      const parsedSelection = JSON.parse(selectionJson) as unknown;
      const parsedLogsource = JSON.parse(logsourceJson) as unknown;
      if (!parsedSelection || Array.isArray(parsedSelection) || typeof parsedSelection !== "object") throw new Error("Tune selection must be a JSON object.");
      if (!parsedLogsource || Array.isArray(parsedLogsource) || typeof parsedLogsource !== "object") throw new Error("Tune log source must be a JSON object.");
      if (JSON.stringify(parsedSelection) === JSON.stringify(candidate.selection ?? {}) && JSON.stringify(parsedLogsource) === JSON.stringify(candidate.logsource ?? {})) throw new Error("A tune must change the selection or log source; use clone when rule behavior is unchanged.");
      setLocalError(undefined);
      onRevision("tune", { ...common, selection: parsedSelection as Record<string, unknown>, logsource: parsedLogsource as Record<string, unknown> });
    } catch (error) {
      setLocalError(error instanceof Error ? error.message : "Revision inputs are invalid.");
    }
  };
  const exportDraft = () => {
    const payload = { schema_version: "bluefire.detection-draft.v1", candidate_id: candidate.resolvedId, state: candidate.state, language, rendered_source: code, parser_backend: candidate.parser_backend ?? null, authoritative_validation: authoritativeParsed };
    const url = URL.createObjectURL(new Blob([`${JSON.stringify(payload, null, 2)}\n`], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `${candidate.resolvedId}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return <Panel className="candidate-workspace">
    <PanelHeader eyebrow="Candidate workspace" title={candidate.title ?? candidate.resolvedId} detail={candidate.behavior_id ?? "Behavior not linked"} actions={<Badge tone={candidate.state === "rejected" ? "danger" : candidate.state === "hypothesis" ? "neutral" : "success"}>{sentence(candidate.state)}</Badge>} />
    <div className="workspace-tabs" role="tablist" aria-label="Detection candidate details">{(["candidate", "revisions", "fixtures", "observed", "history"] as const).map((item) => <button role="tab" aria-selected={tab === item} onClick={() => setTab(item)} key={item}>{sentence(item)}</button>)}</div>
    <div className="candidate-body">
      {!persisted ? <Callout title="Run-linked record">This candidate is part of an immutable run. Persist a new strict hypothesis to use lifecycle or revision actions.</Callout> : null}
      {localError ? <Callout tone="danger" title="Input refused locally">{localError}</Callout> : null}
      {tab === "candidate" ? <>
        <div className="editor-header"><span><Code2 />Candidate source</span><Badge tone={authoritativeParsed ? "success" : "warning"}>{authoritativeParsed ? "Authoritatively parsed" : "Not authoritative validation"}</Badge></div>
        {language === "internal" ? <pre className="rule-editor">{code}</pre> : <Field label={`${sentence(language)} source`} hint="Bounded source is sent only to the explicit parser/compiler action."><textarea rows={10} value={source} onChange={(event) => setSource(event.target.value)} disabled={!canParse} /></Field>}
        <div className="candidate-actions"><Button size="small" onClick={() => onAction("parse", language === "internal" ? {} : { source })} disabled={!canParse || lifecyclePending || (language !== "internal" && !source)}>Parse / compile honestly</Button><Button size="small" variant="ghost" onClick={exportDraft}>Export draft</Button><Button size="small" variant="danger" onClick={() => onAction("reject", { reason, notes: [] })} disabled={!canReject || lifecyclePending || !reason.trim()}>Reject</Button></div>
        <Field label="Rejection reason" hint="Required only for explicit terminal rejection."><input value={reason} onChange={(event) => setReason(event.target.value)} maxLength={1000} disabled={!canReject} /></Field>
        <DataList items={[
          { label: "Candidate ID", value: <code>{candidate.resolvedId}</code> },
          { label: "Immutable revision", value: candidate.revision ? `${candidate.revision} · ${sentence(candidate.revision_kind ?? "origin")}` : "Legacy candidate" },
          { label: "Revision root", value: <code>{candidate.revision_root_id ?? candidate.resolvedId}</code> },
          { label: "Parent candidate", value: candidate.parent_candidate_id ? <code>{candidate.parent_candidate_id}</code> : "Origin has no parent" },
          { label: "Definition digest", value: candidate.definition_digest ? <code>{candidate.definition_digest}</code> : "Not reported" },
          { label: "Behavior", value: candidate.behavior_id ?? "Unassigned" },
          { label: "Language", value: sentence(language) },
          { label: "Parser", value: candidate.parser_backend?.name ?? backend?.backend ?? "Not run" },
          { label: "Parser version", value: candidate.parser_backend?.version ?? backend?.version ?? "Not reported" },
        ]} />
        <PublicBaselineList baselines={candidate.public_baselines ?? []} sourcesById={sourcesById} empty="No reviewed public comparison baseline is pinned to this revision." />
      </> : tab === "revisions" ? <RevisionWorkspace
        candidate={candidate}
        persisted={persisted}
        lineage={lineage}
        comparisonChoices={comparisonChoices}
        comparison={comparison}
        comparisonPending={comparisonPending}
        compareId={compareId}
        setCompareId={setCompareId}
        revisionKind={revisionKind}
        setRevisionKind={setRevisionKind}
        revisionReason={revisionReason}
        setRevisionReason={setRevisionReason}
        revisionTitle={revisionTitle}
        setRevisionTitle={setRevisionTitle}
        selectionJson={selectionJson}
        setSelectionJson={setSelectionJson}
        logsourceJson={logsourceJson}
        setLogsourceJson={setLogsourceJson}
        selectableBaselines={selectableBaselines}
        selectedBaselineIds={selectedBaselineIds}
        setSelectedBaselineIds={setSelectedBaselineIds}
        sourcesById={sourcesById}
        sourcesUnavailable={researchSourcesUnavailable}
        revisionPending={revisionPending}
        onSubmit={submitRevision}
        onCompare={onCompare}
      /> : tab === "fixtures" ? <>
        <Field label="Malicious fixtures JSON" hint={language === "yara" || language === "yara-l" ? "YARA fixtures require exactly fixture_id and bounded text data." : "Structured fixtures use fields referenced by the candidate selection."}><textarea rows={8} value={fixtures} onChange={(event) => setFixtures(event.target.value)} disabled={!canFixture} /></Field>
        <Button size="small" onClick={() => submitFixtures("exercise-fixtures")} disabled={!canFixture || lifecyclePending}><Beaker />Exercise malicious fixtures</Button>
        <Field label="Benign fixtures JSON"><textarea rows={8} value={benign} onChange={(event) => setBenign(event.target.value)} disabled={!canBenign} /></Field>
        <Field label="Benign evaluation notes"><textarea rows={3} value={notes} onChange={(event) => setNotes(event.target.value)} disabled={!canBenign} /></Field>
        <Button size="small" onClick={() => submitFixtures("evaluate-benign")} disabled={!canBenign || lifecyclePending || !notes.trim()}><CheckCircle2 />Evaluate benign fixtures</Button>
        <div className="fixture-grid"><article><Beaker /><strong>Malicious fixtures</strong><Badge tone={candidate.malicious_fixtures?.length ? "success" : "neutral"}>{candidate.malicious_fixtures?.length ?? 0} retained</Badge></article><article><CheckCircle2 /><strong>Benign fixtures</strong><Badge tone={candidate.benign_fixtures?.length ? "success" : "neutral"}>{candidate.benign_fixtures?.length ?? 0} retained</Badge></article></div>
      </> : tab === "observed" ? <>
        <Callout title="Immutable observed evidence only">The control plane verifies the finalized run bundle and independently observed provenance. Evidence content cannot be pasted here.{!["internal", "sigma"].includes(language) ? " This language has no normalized observed-JSON evaluator." : ""}</Callout>
        <Field label="Finalized run"><select value={runId} onChange={(event) => setRunId(event.target.value)} disabled={!canObserved}><option value="">Select run</option>{finalizedRuns.map((run) => <option key={run.run_id} value={run.run_id}>{run.run_id}</option>)}</select></Field>
        <Field label="Evidence IDs" hint="Comma-separated immutable evidence identifiers. Leave empty to use all eligible observed records."><input value={evidenceIds} onChange={(event) => setEvidenceIds(event.target.value)} disabled={!canObserved} /></Field>
        <Button size="small" onClick={() => onAction("exercise-observed", { run_id: runId, ...(evidenceIds.trim() ? { evidence_ids: evidenceIds.split(",").map((item) => item.trim()).filter(Boolean) } : {}) })} disabled={!canObserved || lifecyclePending || !runId}><FileCheck2 />Exercise observed evidence</Button>
        <DataList items={[{ label: "Observed evidence IDs", value: candidate.observed_evidence_ids?.join(", ") || "None" }, { label: "Predicted fields", value: candidate.predicted_fields?.join(", ") || "None" }, { label: "Observed fields", value: candidate.observed_fields?.join(", ") || "None" }, { label: "Field drift", value: candidate.field_drift ? driftText(candidate.field_drift) : "Not measured" }]} />
        {candidate.field_drift ? <details><summary>Show raw field drift</summary><pre>{JSON.stringify(candidate.field_drift, null, 2)}</pre></details> : null}
      </> : <div className="structured-list">{candidate.lifecycle_history?.length ? candidate.lifecycle_history.map((item, index) => <article key={item.sequence ?? index}><strong>{item.sequence ?? index + 1}. {sentence(item.action ?? "transition")}</strong><span>{sentence(item.from_state ?? item.prior_state ?? "new")} → {sentence(item.to_state ?? item.current_state ?? candidate.state)} · {sentence(item.outcome ?? "recorded")}</span><small>{item.recorded_at ?? item.timestamp ?? "Timestamp not reported"}{item.run_id ? ` · ${item.run_id}` : ""}</small></article>) : <EmptyState title="No lifecycle history" description="Run-linked legacy candidates may not include explicit durable lifecycle rows." />}</div>}
    </div>
  </Panel>;
}

function RevisionWorkspace({
  candidate,
  persisted,
  lineage,
  comparisonChoices,
  comparison,
  comparisonPending,
  compareId,
  setCompareId,
  revisionKind,
  setRevisionKind,
  revisionReason,
  setRevisionReason,
  revisionTitle,
  setRevisionTitle,
  selectionJson,
  setSelectionJson,
  logsourceJson,
  setLogsourceJson,
  selectableBaselines,
  selectedBaselineIds,
  setSelectedBaselineIds,
  sourcesById,
  sourcesUnavailable,
  revisionPending,
  onSubmit,
  onCompare,
}: {
  candidate: CandidateView;
  persisted: boolean;
  lineage: CandidateView[];
  comparisonChoices: CandidateView[];
  comparison?: DetectionComparisonResponse;
  comparisonPending: boolean;
  compareId: string;
  setCompareId: (value: string) => void;
  revisionKind: RevisionKind;
  setRevisionKind: (value: RevisionKind) => void;
  revisionReason: string;
  setRevisionReason: (value: string) => void;
  revisionTitle: string;
  setRevisionTitle: (value: string) => void;
  selectionJson: string;
  setSelectionJson: (value: string) => void;
  logsourceJson: string;
  setLogsourceJson: (value: string) => void;
  selectableBaselines: PublicBaselineReference[];
  selectedBaselineIds: string[];
  setSelectedBaselineIds: (value: string[]) => void;
  sourcesById: Map<string, ResearchSourceResource>;
  sourcesUnavailable: boolean;
  revisionPending: boolean;
  onSubmit: () => void;
  onCompare: (candidateId: string) => void;
}) {
  return <div className="review-stack">
    <Callout title="Immutable revision rule">Clone preserves rule behavior for a new research branch. Tune must change selection or log source. Both receive a new candidate ID, parent link, revision number, and content-derived definition digest.</Callout>
    <div>
      <h3>Lineage</h3>
      <div className="structured-list">{lineage.length ? lineage.map((item) => <article key={item.resolvedId}><strong>Revision {item.revision ?? 1} · {sentence(item.revision_kind ?? "origin")}</strong><span><code>{item.resolvedId}</code> · {sentence(item.state)}{item.parent_candidate_id ? ` · parent ${item.parent_candidate_id}` : " · lineage origin"}</span><small title={item.definition_digest}>{item.definition_digest ? shortDigest(item.definition_digest) : "Definition digest not reported"}</small></article>) : <EmptyState title="No persisted lineage" description="Run-linked records cannot be revised in place." />}</div>
    </div>
    <fieldset>
      <legend>Revision intent</legend>
      <div className="choice-grid two">{(["clone", "tune"] as const).map((kind) => <label key={kind}><input type="radio" name="detection-revision-kind" checked={revisionKind === kind} onChange={() => setRevisionKind(kind)} disabled={!persisted} /><span><strong>{kind === "clone" ? "Clone unchanged rule behavior" : "Tune rule behavior"}</strong><small>{kind === "clone" ? "Branch attribution, title, known misses, fields, or public baselines." : "Change the structured selection or log source and retain a durable reason."}</small></span></label>)}</div>
    </fieldset>
    <div className="config-grid">
      <Field label="Revision title"><input value={revisionTitle} onChange={(event) => setRevisionTitle(event.target.value)} maxLength={200} disabled={!persisted} /></Field>
      <Field label="Required research reason" hint="Recorded in immutable tuning decisions and lifecycle history."><input value={revisionReason} onChange={(event) => setRevisionReason(event.target.value)} maxLength={1000} disabled={!persisted} /></Field>
    </div>
    {revisionKind === "tune" ? <div className="config-grid">
      <Field label="Tuned selection JSON" hint="Must remain a non-empty structured object."><textarea rows={9} value={selectionJson} onChange={(event) => setSelectionJson(event.target.value)} disabled={!persisted} /></Field>
      <Field label="Tuned log source JSON" hint="Change selection, log source, or both."><textarea rows={9} value={logsourceJson} onChange={(event) => setLogsourceJson(event.target.value)} disabled={!persisted} /></Field>
    </div> : null}
    <fieldset>
      <legend>Reviewed public comparison baselines</legend>
      {sourcesUnavailable ? <Callout tone="warning" title="Research source registry unavailable">Existing immutable pins remain visible, but new source pins cannot be discovered until the registry is available.</Callout> : null}
      {selectableBaselines.length ? <div className="choice-grid two">{selectableBaselines.map((baseline) => {
        const source = sourcesById.get(baseline.research_source_id);
        const selected = selectedBaselineIds.includes(baseline.research_source_id);
        return <label key={baseline.research_source_id}><input type="checkbox" checked={selected} disabled={!persisted || baseline.license_review === "prohibited"} onChange={() => setSelectedBaselineIds(selected ? selectedBaselineIds.filter((item) => item !== baseline.research_source_id) : [...selectedBaselineIds, baseline.research_source_id])} /><span><strong>{source?.document.name ?? baseline.research_source_id}</strong><small>{baseline.version} · {baseline.exact_ref ?? baseline.pin} · {sentence(baseline.use_classification ?? "legacy")} · {sentence(baseline.license_review)} license review</small></span></label>;
      })}</div> : <p className="field-note">No pinned, comparison-authorized public research source is registered.</p>}
      <PublicBaselineList baselines={selectableBaselines.filter((item) => selectedBaselineIds.includes(item.research_source_id))} sourcesById={sourcesById} empty="No public baseline will be attached to the new revision." />
    </fieldset>
    <div className="candidate-actions"><Button variant="primary" onClick={onSubmit} disabled={!persisted || revisionPending || !revisionReason.trim()}>{revisionKind === "clone" ? "Create immutable clone" : "Create immutable tune"}</Button></div>
    <div>
      <h3>Compare two revisions</h3>
      <div className="config-grid"><Field label="Baseline revision"><input value={`Revision ${candidate.revision ?? 1} · ${candidate.resolvedId}`} readOnly disabled /></Field><Field label="Candidate revision"><select value={compareId} onChange={(event) => setCompareId(event.target.value)} disabled={!comparisonChoices.length}><option value="">Select same-lineage revision</option>{comparisonChoices.map((item) => <option key={item.resolvedId} value={item.resourceId}>Revision {item.revision ?? 1} · {sentence(item.revision_kind ?? "origin")} · {item.resolvedId}</option>)}</select></Field></div>
      <div className="candidate-actions"><Button onClick={() => onCompare(compareId)} disabled={!persisted || !compareId || comparisonPending}>{comparisonPending ? "Comparing revisions…" : "Compare immutable revisions"}</Button></div>
    </div>
    {comparison ? <DetectionComparisonView comparison={comparison} sourcesById={sourcesById} /> : <Callout title="No comparison loaded">Choose another revision from this lineage to inspect source, rule, field, lifecycle, fixture, observed, and benign deltas.</Callout>}
  </div>;
}

function PublicBaselineList({ baselines, sourcesById, empty }: { baselines: PublicBaselineReference[]; sourcesById: Map<string, ResearchSourceResource>; empty: string }) {
  if (!baselines.length) return <Callout title="Public baseline pins">{empty}</Callout>;
  return <div className="record-grid">{baselines.map((baseline) => {
    const source = sourcesById.get(baseline.research_source_id);
    return <article key={`${baseline.research_source_id}-${baseline.source_digest}`}>
      <header><Badge tone={baseline.license_review === "reviewed" ? "success" : baseline.license_review === "prohibited" ? "danger" : "warning"}>{sentence(baseline.license_review)}</Badge><code title={baseline.source_digest}>{shortDigest(baseline.source_digest)}</code></header>
      <strong>{source?.document.name ?? baseline.research_source_id}</strong>
      <p>{source?.document.authority ? `${source.document.authority} · ` : ""}{sentence(baseline.relationship)} public comparison; {sentence(baseline.use_classification ?? "legacy")} source handling.</p>
      <DataList items={[{ label: "Version", value: baseline.version }, { label: "Source handling", value: sentence(baseline.use_classification ?? "legacy") }, { label: "Exact ref", value: baseline.exact_ref ?? "Legacy baseline" }, { label: "Immutable source pin", value: <code>{baseline.pin}</code> }, { label: "License", value: baseline.license }, { label: "Authorized use", value: sentence(baseline.use) }, { label: "Update status", value: sentence(baseline.update_status ?? "legacy") }]} />
      <details><summary>Show full public baseline identity</summary><DataList items={[{ label: "Research source ID", value: <code>{baseline.research_source_id}</code> }, { label: "Source digest", value: <code>{baseline.source_digest}</code> }, { label: "Retrieved", value: baseline.retrieved_at ?? "Legacy baseline" }, { label: "Last verified", value: baseline.last_verified_at ?? "Legacy baseline" }, { label: "File-level license review", value: baseline.file_level_license_review ?? "Legacy baseline" }, { label: "Trademark considerations", value: baseline.trademark_considerations ?? "Legacy baseline" }, { label: "Attribution", value: baseline.attribution ?? "Legacy baseline" }, { label: "Security review", value: baseline.security_review ?? "Legacy baseline" }, { label: "Schema", value: baseline.schema_version }]} /></details>
    </article>;
  })}</div>;
}

function SetDeltaView({ label, delta }: { label: string; delta: DetectionSetDelta }) {
  return <article><header><strong>{label}</strong><Badge tone={delta.added.length || delta.removed.length ? "warning" : "neutral"}>{delta.added.length + delta.removed.length ? "Changed" : "Stable"}</Badge></header><DataList items={[{ label: "Added", value: listText(delta.added) }, { label: "Removed", value: listText(delta.removed) }, { label: "Unchanged", value: listText(delta.unchanged) }]} /></article>;
}

function DetectionComparisonView({ comparison, sourcesById }: { comparison: DetectionComparisonResponse; sourcesById: Map<string, ResearchSourceResource> }) {
  const changedCategories = Object.values(comparison.deltas).filter((item) => item.changed).length;
  const { source, rule, fields, lifecycle: lifecycleDelta, fixtures, observed, benign } = comparison.deltas;
  return <div className="review-stack" aria-label="Detection revision comparison">
    <Callout tone={changedCategories ? "warning" : "success"} title="Immutable revision comparison">{changedCategories} of 7 delta categories changed. The comparison is constrained to lineage <code>{comparison.revision_root_id}</code>.</Callout>
    <DataList items={[
      { label: "Comparison ID", value: <code>{comparison.comparison_id}</code> },
      { label: "Baseline", value: <><code>{comparison.baseline.candidate_id}</code> · revision {comparison.baseline.revision} · {sentence(comparison.baseline.revision_kind)} · {sentence(comparison.baseline.state)}</> },
      { label: "Candidate", value: <><code>{comparison.candidate.candidate_id}</code> · revision {comparison.candidate.revision} · {sentence(comparison.candidate.revision_kind)} · {sentence(comparison.candidate.state)}</> },
      { label: "Baseline definition", value: <code>{comparison.baseline.definition_digest}</code> },
      { label: "Candidate definition", value: <code>{comparison.candidate.definition_digest}</code> },
    ]} />
    <div className="record-grid">
      <article>
        <header><Badge tone={source.changed ? "warning" : "success"}>{source.changed ? "Changed" : "Stable"}</Badge><strong>Source attribution</strong></header>
        <DataList items={[{ label: "Provenance changed", value: source.provenance.changed ? "Yes" : "No" }, { label: "Baseline provenance digest", value: <code>{source.provenance.baseline_digest}</code> }, { label: "Candidate provenance digest", value: <code>{source.provenance.candidate_digest}</code> }, { label: "Public baseline pins changed", value: source.public_baselines.changed ? "Yes" : "No" }]} />
        <p>Added: {source.public_baselines.added.map((item) => item.research_source_id).join(", ") || "none"} · Removed: {source.public_baselines.removed.map((item) => item.research_source_id).join(", ") || "none"} · Modified: {source.public_baselines.modified.map((item) => item.research_source_id).join(", ") || "none"}</p>
      </article>
      <article>
        <header><Badge tone={rule.changed ? "warning" : "success"}>{rule.changed ? "Changed" : "Stable"}</Badge><strong>Rule definition</strong></header>
        <DataList items={[{ label: "Changed fields", value: listText(rule.changed_fields) }, { label: "Baseline target language", value: rule.baseline.target_language }, { label: "Candidate target language", value: rule.candidate.target_language }, { label: "Baseline log source digest", value: <code>{rule.baseline.logsource_digest}</code> }, { label: "Candidate log source digest", value: <code>{rule.candidate.logsource_digest}</code> }, { label: "Baseline selection digest", value: <code>{rule.baseline.selection_digest}</code> }, { label: "Candidate selection digest", value: <code>{rule.candidate.selection_digest}</code> }, { label: "Baseline rule source digest", value: rule.baseline.rule_source_digest ? <code>{rule.baseline.rule_source_digest}</code> : "None" }, { label: "Candidate rule source digest", value: rule.candidate.rule_source_digest ? <code>{rule.candidate.rule_source_digest}</code> : "None" }]} />
      </article>
      <article>
        <header><Badge tone={fields.changed ? "warning" : "success"}>{fields.changed ? "Changed" : "Stable"}</Badge><strong>Field coverage</strong></header>
        <DataList items={[{ label: "Predicted added", value: listText(fields.predicted.added) }, { label: "Predicted removed", value: listText(fields.predicted.removed) }, { label: "Predicted unchanged", value: listText(fields.predicted.unchanged) }, { label: "Observed added", value: listText(fields.observed.added) }, { label: "Observed removed", value: listText(fields.observed.removed) }, { label: "Observed unchanged", value: listText(fields.observed.unchanged) }, { label: "Field drift changed", value: fields.drift.changed ? "Yes" : "No" }, { label: "Baseline drift", value: driftText(fields.drift.baseline) }, { label: "Candidate drift", value: driftText(fields.drift.candidate) }]} />
      </article>
      <article>
        <header><Badge tone={lifecycleDelta.changed ? "warning" : "success"}>{lifecycleDelta.changed ? "Changed" : "Stable"}</Badge><strong>Lifecycle proof</strong></header>
        <DataList items={[{ label: "Baseline state", value: sentence(lifecycleDelta.baseline_state) }, { label: "Candidate state", value: sentence(lifecycleDelta.candidate_state) }, { label: "Baseline actions", value: listText(lifecycleDelta.baseline_actions) }, { label: "Candidate actions", value: listText(lifecycleDelta.candidate_actions) }, { label: "Baseline history digest", value: <code>{lifecycleDelta.baseline_history_digest}</code> }, { label: "Candidate history digest", value: <code>{lifecycleDelta.candidate_history_digest}</code> }]} />
      </article>
      <article>
        <header><Badge tone={fixtures.changed ? "warning" : "success"}>{fixtures.changed ? "Changed" : "Stable"}</Badge><strong>Malicious fixtures</strong></header>
        <DataList items={[{ label: "Added fixture IDs", value: listText(fixtures.added_fixture_ids) }, { label: "Removed fixture IDs", value: listText(fixtures.removed_fixture_ids) }, { label: "Changed fixture IDs", value: listText(fixtures.changed_fixture_ids) }, { label: "All added IDs", value: listText(fixtures.fixture_ids.added) }, { label: "All removed IDs", value: listText(fixtures.fixture_ids.removed) }, { label: "All unchanged IDs", value: listText(fixtures.fixture_ids.unchanged) }, { label: "Baseline matches", value: fixtures.baseline_match_count }, { label: "Candidate matches", value: fixtures.candidate_match_count }]} />
      </article>
      <article>
        <header><Badge tone={observed.changed ? "warning" : "success"}>{observed.changed ? "Changed" : "Stable"}</Badge><strong>Observed evidence</strong></header>
        <DataList items={[{ label: "Evidence IDs added", value: listText(observed.evidence_ids.added) }, { label: "Evidence IDs removed", value: listText(observed.evidence_ids.removed) }, { label: "Evidence IDs unchanged", value: listText(observed.evidence_ids.unchanged) }, { label: "Run IDs added", value: listText(observed.run_ids.added) }, { label: "Run IDs removed", value: listText(observed.run_ids.removed) }, { label: "Run IDs unchanged", value: listText(observed.run_ids.unchanged) }]} />
      </article>
      <article>
        <header><Badge tone={benign.changed ? "warning" : "success"}>{benign.changed ? "Changed" : "Stable"}</Badge><strong>Benign evaluation</strong></header>
        <DataList items={[{ label: "Added fixture IDs", value: listText(benign.added_fixture_ids) }, { label: "Removed fixture IDs", value: listText(benign.removed_fixture_ids) }, { label: "Changed fixture IDs", value: listText(benign.changed_fixture_ids) }, { label: "All added IDs", value: listText(benign.fixture_ids.added) }, { label: "All removed IDs", value: listText(benign.fixture_ids.removed) }, { label: "All unchanged IDs", value: listText(benign.fixture_ids.unchanged) }, { label: "Notes added", value: listText(benign.notes.added) }, { label: "Notes removed", value: listText(benign.notes.removed) }, { label: "Notes unchanged", value: listText(benign.notes.unchanged) }, { label: "Baseline matches", value: benign.baseline_match_count }, { label: "Candidate matches", value: benign.candidate_match_count }]} />
      </article>
    </div>
    {source.public_baselines.added.length || source.public_baselines.removed.length || source.public_baselines.modified.length ? <div className="review-stack">
      <h3>Public baseline pin changes</h3>
      {source.public_baselines.added.length ? <><p className="field-note">Added reviewed pins</p><PublicBaselineList baselines={source.public_baselines.added} sourcesById={sourcesById} empty="None" /></> : null}
      {source.public_baselines.removed.length ? <><p className="field-note">Removed reviewed pins</p><PublicBaselineList baselines={source.public_baselines.removed} sourcesById={sourcesById} empty="None" /></> : null}
      {source.public_baselines.modified.map((item) => <details key={item.research_source_id}><summary>Modified pin for {item.research_source_id}</summary><div className="delta-columns"><PublicBaselineList baselines={[item.baseline]} sourcesById={sourcesById} empty="None" /><PublicBaselineList baselines={[item.candidate]} sourcesById={sourcesById} empty="None" /></div></details>)}
    </div> : null}
    <div className="record-grid"><SetDeltaView label="Predicted field set" delta={fields.predicted} /><SetDeltaView label="Observed field set" delta={fields.observed} /><SetDeltaView label="Malicious fixture set" delta={fixtures.fixture_ids} /><SetDeltaView label="Observed evidence set" delta={observed.evidence_ids} /><SetDeltaView label="Observed run set" delta={observed.run_ids} /><SetDeltaView label="Benign fixture set" delta={benign.fixture_ids} /><SetDeltaView label="Benign note set" delta={benign.notes} /></div>
    <details><summary>Show raw detection comparison</summary><pre aria-label="Raw detection revision comparison">{JSON.stringify(comparison, null, 2)}</pre></details>
  </div>;
}
