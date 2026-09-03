import type {
  ActionDefinition,
  Behavior,
  CatalogResponse,
  ComparisonResponse,
  RunRecord,
  RunnerProfile,
  Scenario,
} from "../types";

const port = (name: string, type: string, required = false) => ({ name, type, required });

export const demoBehaviors: Behavior[] = [
  {
    id: "sandbox.fixture.create.v1",
    title: "Place deterministic fixture",
    purpose: "Place bounded, synthetic research material in a runner-owned workspace.",
    execution_state: "action",
    safety_tier: "safe",
    platforms: ["windows", "linux", "macos"],
    techniques: ["fixture.delivery"],
    capabilities: ["filesystem.write", "sandbox.fixture"],
    inputs: [], outputs: [port("workspace", "artifact.sandbox.workspace.v1")],
    parameters: [{ name: "record_count", type: "integer", default: 8, minimum: 1, maximum: 50 }],
    simulation_id: "simulation.sandbox.fixture.create.v1", action_ids: ["sandbox.fixture.create.v1"],
    telemetry: ["file.create"], detection_hints: ["Monitor fixture placement in the authorized root."], limitations: [],
  },
  {
    id: "sandbox.program.fixed.v1",
    title: "Run reviewed fixture program",
    purpose: "Invoke a fixed reviewed program without exposing a free-form command surface.",
    execution_state: "action", safety_tier: "controlled", platforms: ["windows", "linux", "macos"],
    techniques: ["process.execution"], capabilities: ["process.spawn"],
    inputs: [port("workspace", "artifact.sandbox.workspace.v1", true)], outputs: [port("process", "observation.process.v1")],
    parameters: [{ name: "program_variant", type: "string", enum: ["metadata", "transform"], default: "metadata" }],
    simulation_id: "simulation.sandbox.program.fixed.v1", action_ids: ["sandbox.program.fixed.v1"],
    telemetry: ["process.start", "process.exit"], detection_hints: ["Correlate parent, binary digest, and workspace."], limitations: [],
  },
  {
    id: "endpoint.discovery.system.v1", title: "Collect bounded system facts",
    purpose: "Collect approved operating-system and process metadata from the selected sandbox.",
    execution_state: "action", safety_tier: "safe", platforms: ["windows", "linux", "macos"],
    techniques: ["system.discovery"], capabilities: ["sandbox.discovery", "filesystem.read"],
    inputs: [port("workspace", "artifact.sandbox.workspace.v1", true)], outputs: [port("records", "observation.discovery.records.v1")],
    parameters: [{ name: "record_limit", type: "integer", default: 25, minimum: 1, maximum: 100 }],
    simulation_id: "simulation.endpoint.discovery.system.v1", action_ids: ["endpoint.discovery.system.v1"],
    telemetry: ["process.query", "system.metadata"], detection_hints: ["Measure discovery process and API telemetry."], limitations: [],
  },
  {
    id: "sandbox.collection.stage.v1", title: "Stage selected records",
    purpose: "Package selected fixture records into an attributable local bundle.",
    execution_state: "action", safety_tier: "controlled", platforms: ["windows", "linux", "macos"],
    techniques: ["collection.staging"], capabilities: ["sandbox.collection", "filesystem.read", "filesystem.write"],
    inputs: [port("records", "observation.discovery.records.v1", true)], outputs: [port("bundle", "artifact.collection.bundle.v1")],
    parameters: [{ name: "bundle_format", type: "string", enum: ["jsonl", "zip"], default: "jsonl" }],
    simulation_id: "simulation.sandbox.collection.stage.v1", action_ids: ["sandbox.collection.stage.v1"],
    telemetry: ["file.read", "archive.create"], detection_hints: ["Observe archive creation and unusual read bursts."], limitations: [],
  },
  {
    id: "sandbox.network.loopback.v1", title: "Exercise internal transport",
    purpose: "Send a synthetic bundle only to a runner-enforced loopback sink.",
    execution_state: "action", safety_tier: "controlled", platforms: ["windows", "linux", "macos"],
    techniques: ["network.communication"], capabilities: ["sandbox.network", "network.loopback"],
    inputs: [port("bundle", "artifact.collection.bundle.v1", true)], outputs: [port("receipt", "receipt.transport.v1")],
    parameters: [{ name: "port", type: "integer", default: 4317, minimum: 1024, maximum: 65535 }],
    simulation_id: "simulation.sandbox.network.loopback.v1", action_ids: ["sandbox.network.loopback.v1"],
    telemetry: ["network.connect", "network.bytes"], detection_hints: ["Correlate process and loopback connection."], limitations: ["Loopback only in the packaged profile."],
  },
  {
    id: "sandbox.export.local.v1", title: "Use approved local fallback",
    purpose: "Preserve the bundle locally when transport is blocked or unavailable.",
    execution_state: "action", safety_tier: "controlled", platforms: ["windows", "linux", "macos"],
    techniques: ["collection.export"], capabilities: ["export.local", "filesystem.write"],
    inputs: [port("bundle", "artifact.collection.bundle.v1", true)], outputs: [port("receipt", "receipt.export.v1")],
    parameters: [{ name: "retention_label", type: "string", default: "ephemeral" }],
    simulation_id: "simulation.sandbox.export.local.v1", action_ids: ["sandbox.export.local.v1"],
    telemetry: ["file.create"], detection_hints: ["Observe writes to approved export roots."], limitations: [],
  },
  {
    id: "sandbox.cleanup.v1", title: "Reconcile and clean workspace",
    purpose: "Remove attributable fixture effects and emit a cleanup receipt.",
    execution_state: "action", safety_tier: "safe", platforms: ["windows", "linux", "macos"],
    techniques: ["cleanup"], capabilities: ["cleanup", "filesystem.write"],
    inputs: [port("workspace", "artifact.sandbox.workspace.v1", true)], outputs: [port("receipt", "receipt.cleanup.v1")],
    parameters: [{ name: "verify_removal", type: "boolean", default: true }],
    simulation_id: "simulation.sandbox.cleanup.v1", action_ids: ["sandbox.cleanup.v1"],
    telemetry: ["file.delete", "cleanup.receipt"], detection_hints: ["Reconcile created and removed artifacts."], limitations: [],
  },
  {
    id: "research.identity.credential.v1", title: "Credential-access research hypothesis",
    purpose: "Model credential-access observables without claiming an executable implementation.",
    execution_state: "metadata_only", safety_tier: "restricted", platforms: ["windows", "linux"],
    techniques: ["credential.access"], capabilities: ["research.metadata"], inputs: [], outputs: [], parameters: [],
    simulation_id: null, action_ids: [], telemetry: ["identity.audit"],
    detection_hints: ["Research access patterns and protected-object telemetry."],
    limitations: ["No installed execution action. Research and simulation metadata only."],
  },
];

export const demoActions: ActionDefinition[] = demoBehaviors.filter((item) => item.action_ids.length).map((item) => ({
  id: item.action_ids[0]!, title: item.title, purpose: item.purpose, safety_tier: item.safety_tier,
  capabilities: item.capabilities, platforms: item.platforms, inputs: item.inputs, outputs: item.outputs,
  parameters: item.parameters, mutates: item.capabilities.includes("filesystem.write"),
  cleanup_action_id: item.id === "sandbox.cleanup.v1" ? null : "sandbox.cleanup.v1",
}));

export const demoProfiles: RunnerProfile[] = [
  { id: "sandbox-simulate.v1", mode: "simulate", environment_type: "local-fixture", platforms: ["any"], scope: ["sandbox.workspace"], network_allowlist: ["loopback"], capabilities: [...new Set(demoBehaviors.flatMap((item) => item.capabilities))], safety_tiers: ["safe", "controlled"], approval_required: false, enabled_actions: [], blocked_actions: [], cleanup_policy: "always", budgets: { max_seconds: 120, max_steps: 20, max_bytes: 8_388_608 }, secrets: [] },
  { id: "sandbox-execute.v1", mode: "execute", environment_type: "runner-owned-sandbox", platforms: ["windows", "linux", "macos"], scope: ["sandbox.workspace"], network_allowlist: ["127.0.0.1/32"], capabilities: [...new Set(demoBehaviors.flatMap((item) => item.capabilities))], safety_tiers: ["safe", "controlled"], approval_required: true, enabled_actions: demoActions.map((item) => item.id), blocked_actions: [], cleanup_policy: "always", budgets: { max_seconds: 120, max_steps: 20, max_bytes: 8_388_608 }, secrets: [] },
  { id: "sandbox-observe-only.v1", mode: "execute", environment_type: "disposable-container", platforms: ["linux"], scope: ["sandbox.workspace"], network_allowlist: [], capabilities: ["filesystem.read", "endpoint.discovery", "system.discovery"], safety_tiers: ["safe"], approval_required: true, enabled_actions: ["endpoint.discovery.system.v1"], blocked_actions: demoActions.filter((item) => item.mutates).map((item) => item.id), cleanup_policy: "always", budgets: { max_seconds: 60, max_steps: 8, max_bytes: 1_048_576 }, secrets: [] },
];

export const demoScenario: Scenario = {
  schema_version: "bluefire.scenario.v1", id: "demo.endpoint.validation.v1", title: "Endpoint control validation",
  purpose: "Validate a bounded fixture, discovery, staging, transport-block, local fallback, and cleanup path.", start: "place_fixture",
  steps: [
    { id: "place_fixture", behavior_id: "sandbox.fixture.create.v1", parameters: { record_count: 8 }, inputs: {}, alternates: [] },
    { id: "run_fixture", behavior_id: "sandbox.program.fixed.v1", parameters: { program_variant: "metadata" }, inputs: { workspace: { from_step: "place_fixture", artifact: "workspace" } }, alternates: [] },
    { id: "discover", behavior_id: "endpoint.discovery.system.v1", parameters: { record_limit: 25 }, inputs: { workspace: { from_step: "place_fixture", artifact: "workspace" } }, alternates: [] },
    { id: "stage", behavior_id: "sandbox.collection.stage.v1", parameters: { bundle_format: "jsonl" }, inputs: { records: { from_step: "discover", artifact: "records" } }, alternates: [] },
    { id: "transport", behavior_id: "sandbox.network.loopback.v1", parameters: { port: 4317 }, inputs: { bundle: { from_step: "stage", artifact: "bundle" } }, alternates: [] },
    { id: "fallback", behavior_id: "sandbox.export.local.v1", parameters: { retention_label: "ephemeral" }, inputs: { bundle: { from_step: "stage", artifact: "bundle" } }, alternates: [] },
    { id: "cleanup", behavior_id: "sandbox.cleanup.v1", parameters: { verify_removal: true }, inputs: { workspace: { from_step: "place_fixture", artifact: "workspace" } }, alternates: [] },
  ],
  edges: [
    { from_step: "place_fixture", outcome: "success", to_step: "run_fixture" },
    { from_step: "run_fixture", outcome: "success", to_step: "discover" },
    { from_step: "discover", outcome: "success", to_step: "stage" },
    { from_step: "stage", outcome: "success", to_step: "transport" },
    { from_step: "transport", outcome: "success", to_step: "cleanup" },
    { from_step: "transport", outcome: "blocked", to_step: "fallback" },
    { from_step: "transport", outcome: "failed", to_step: "fallback" },
    { from_step: "fallback", outcome: "success", to_step: "cleanup" },
  ],
  provenance: { source: "BlueFire seeded demo", reference: "demo.endpoint.validation.v1", license: "MIT", derived: false, notes: "Synthetic and sanitized." },
  limitations: ["Demo data is synthetic and does not claim runner execution."],
  layout: {
    place_fixture: { x: 40, y: 150 }, run_fixture: { x: 330, y: 40 }, discover: { x: 330, y: 250 },
    stage: { x: 620, y: 250 }, transport: { x: 910, y: 120 }, fallback: { x: 910, y: 340 }, cleanup: { x: 1200, y: 220 },
  },
};

const simulatedSteps = demoScenario.steps.filter((step) => step.id !== "fallback").map((step) => ({
  step_id: step.id, behavior_id: step.behavior_id, status: "success", execution_disposition: "simulated",
  simulation_id: demoBehaviors.find((item) => item.id === step.behavior_id)?.simulation_id,
  action_id: null, telemetry: demoBehaviors.find((item) => item.id === step.behavior_id)?.telemetry ?? [],
}));

export const demoRuns: RunRecord[] = [
  {
    run_id: "demo-simulate-baseline", scenario_id: demoScenario.id, mode: "simulate", status: "completed",
    created_at: "2026-01-15T10:00:00Z", finalized_at: "2026-01-15T10:00:08Z",
    objective: demoScenario.purpose, objective_reached: true, runner_profile_id: "sandbox-simulate.v1",
    ai_enabled: false, autonomy: "off", autonomy_level: "off", steps: simulatedSteps,
    evidence: { records: simulatedSteps.map((step, index) => ({ evidence_id: `demo-evidence-${index + 1}`, step_id: step.step_id, behavior_id: step.behavior_id, action_id: null, provenance: "synthetic", producer: "deterministic-simulation", confidence: 1, limitations: ["Sanitized seeded preview; no independent observation occurred."], content: { summary: `Synthetic expected observable for ${step.step_id}.`, expected_telemetry: step.telemetry ?? [] }, kind: "expected-observable", summary: `Synthetic expected observable for ${step.step_id}.` })) },
    detections: { candidates: [{ candidate_id: "demo-detection-1", title: "Fixture staging correlation", behavior_id: "sandbox.collection.stage.v1", state: "fixture_exercised", target_language: "sigma", summary: "Parsed against the deterministic fixture only." }] },
    cleanup: { status: "simulated", outstanding_effects: 0 }, limitations: ["Seeded Simulate preview; no external effects occurred."], is_demo: true,
  },
  {
    run_id: "demo-simulate-defense-change", scenario_id: demoScenario.id, mode: "simulate", status: "completed",
    created_at: "2026-01-15T11:00:00Z", finalized_at: "2026-01-15T11:00:07Z",
    objective: demoScenario.purpose, objective_reached: false, runner_profile_id: "sandbox-simulate.v1",
    ai_enabled: true, autonomy: "assist", autonomy_level: "assist",
    steps: simulatedSteps.map((step) => step.step_id === "transport" ? { ...step, status: "blocked", execution_disposition: "control_blocked" } : step).filter((step) => step.step_id !== "cleanup").concat([{ ...simulatedSteps.at(-1)!, status: "success" }]),
    evidence: { records: [{ evidence_id: "demo-block-1", step_id: "transport", behavior_id: "sandbox.transfer.local.v1", action_id: null, provenance: "control_blocked", producer: "deterministic-simulation", confidence: 1, limitations: ["Seeded control-block fixture; no real control was exercised."], content: { summary: "Synthetic control-block fixture.", control: "fixture.control.block" }, kind: "policy-fixture", summary: "Synthetic control-block fixture." }] },
    detections: { candidates: [{ candidate_id: "demo-detection-1", title: "Fixture staging correlation", behavior_id: "sandbox.collection.stage.v1", state: "benign_evaluated", target_language: "sigma", summary: "Seeded benign-evaluation example." }] },
    cleanup: { status: "simulated", outstanding_effects: 0 }, limitations: ["Seeded Simulate comparison; no control was actually exercised."], is_demo: true,
  },
];

export const demoCatalog: CatalogResponse = {
  schema_version: "bluefire.catalog-response.v1", modes: ["simulate", "execute"],
  ai: {
    enabled: false, autonomy: "off", independent_of_mode: true, authority: "proposal_only",
    autonomy_levels: ["off", "assist", "auto"], active_provider: "deterministic-offline.v1", fallback_provider: "deterministic-offline.v1",
    providers: [{ provider_id: "deterministic-offline.v1", kind: "deterministic", model: "deterministic-planner.v1", health: { state: "ready", message: "Sanitized deterministic demo provider is ready.", credential_available: true }, proposal_application: "deterministic_only" }],
    levels: ["off", "assist", "auto"], provider_health: "ready",
  },
  behaviors: demoBehaviors, actions: demoActions, runner_profiles: demoProfiles,
};

export function compareDemoRuns(runIds: string[]): ComparisonResponse {
  const runs = runIds.map((id) => demoRuns.find((run) => run.run_id === id)).filter(Boolean) as RunRecord[];
  const summaries = runs.map((run) => ({
    run_id: run.run_id, mode: run.mode, profile_id: run.runner_profile_id ?? undefined,
    path: run.steps.map((step) => step.step_id), outcomes: Object.fromEntries(run.steps.map((step) => [step.step_id, step.status])),
    first_blocked_step: run.steps.find((step) => step.status === "blocked")?.step_id ?? null,
    objective_reached: run.objective_reached,
    evidence_provenance: Object.fromEntries(["synthetic", "control_blocked"].map((kind) => [kind, run.evidence?.records.filter((item) => item.provenance === kind).length ?? 0])),
    detection_states: Object.fromEntries((run.detections?.candidates ?? []).map((item) => [item.state, 1])),
    telemetry: [...new Set(run.steps.flatMap((step) => step.telemetry ?? []))], controls: run.steps.some((step) => step.status === "blocked") ? ["fixture.control.block"] : [],
    cleanup_success: true, counterfactual_steps: [],
  }));
  const baseline = summaries[0]!;
  const deltas = summaries.slice(1).map((summary) => ({
    from_run_id: baseline.run_id, to_run_id: summary.run_id,
    first_path_divergence: baseline.path.findIndex((step, index) => summary.path[index] !== step),
    first_blocked_changed: baseline.first_blocked_step !== summary.first_blocked_step,
    objective_changed: baseline.objective_reached !== summary.objective_reached, cleanup_changed: false,
    evidence_delta: {}, detection_delta: {}, telemetry_added: [], telemetry_removed: [],
    controls_added: summary.controls.filter((item) => !baseline.controls.includes(item)), controls_removed: [],
  }));
  return { comparison_id: "demo-comparison", baseline_run_id: baseline.run_id, run_ids: runs.map((run) => run.run_id), summaries, deltas };
}
