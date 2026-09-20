import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it } from "vitest";
import { AdaptiveRunPath } from "../src/components/AdaptiveRunPath";
import { demoCatalog } from "../src/lib/demo";
import type { AIProposal, EvidenceRecord, RunRecord } from "../src/types";

// Authored display fixtures only; no provider, tool, or host observation is involved.
const behavior = "endpoint.discovery.system.v1";
const action = "sandbox.discovery.list.v1";
const catalog = demoCatalog;

function permissionFields(mode: string) {
  const bits = Number.parseInt(mode, 8);
  return {
    permission_status: "available",
    effective_access: "not_evaluated",
    permission_mode_octal: mode,
    group_write_bit: Boolean(bits & 0o020),
    other_write_bit: Boolean(bits & 0o002),
    non_owner_write_bit: Boolean(bits & 0o022),
  };
}

function record(content: Record<string, unknown>, provenance: EvidenceRecord["provenance"] = "observed"): EvidenceRecord {
  const identity = String(content.permission_mode_octal ?? content.permission_status ?? content.observation_kind ?? "legacy");
  return { evidence_id: `evidence-${identity}-${provenance}`, provenance, producer: "authored-fixture", content };
}

function run(records: EvidenceRecord[], evidenceIds = records.map(item => item.evidence_id!)): RunRecord {
  const projectedEvidence = records.filter(item => evidenceIds.includes(item.evidence_id!)).map(item => ({ evidence_id: item.evidence_id, provenance: item.provenance, facts: item.content }));
  const proposal: AIProposal = {
    schema_version: "bluefire.ai-proposal.v2", proposal_id: "proposal-permissions", proposal_type: "select_registered_action",
    selected_step_id: "inspect", selected_behavior_id: behavior, selected_action_id: action, selected_edge: null,
    parameter_changes: [], rationale: "Use the observed permission facts.", alternatives: [], confidence: .8, requires_operator_review: false,
  };
  return {
    run_id: "authored-permission-run", mode: "execute", status: "completed",
    steps: [{ step_id: "inspect", behavior_id: behavior, action_id: action, status: "success", execution_disposition: "execute", planner_decision_id: "decision-1", evidence_ids: evidenceIds }],
    evidence: { records },
    ai_proposals: [{ schema_version: "bluefire.ai-proposal-record.v4", run_id: "authored-permission-run", current_step_id: "inspect", deterministic_decision_id: "decision-1", outcome: "success", application_status: "applied_reviewed_method", proposal, applied_step: { step_id: "inspect", behavior_id: behavior, action_id: action }, provider_called: false, planner_state: { observations: { attempts: [{ attempt_index: 0, step_id: "inspect", evidence: projectedEvidence }], remaining_budgets: { steps: 1, seconds: 5, retries: 0 }, unknowns: [] } } }],
  };
}

async function openObservations() {
  const user = userEvent.setup();
  await user.click(screen.getByText("Decision, observations and limits", { selector: "summary" }));
  return user;
}

it.each(["0640", "0660", "0666"])('renders observed mode %s and its write bits', async mode => {
  const evidence = record({ artifact_type: "file_observation", ...permissionFields(mode) });
  render(<AdaptiveRunPath run={run([evidence])} catalog={catalog} />);
  const user = await openObservations();
  const region = screen.getByRole("region", { name: "Recorded adaptive decision" });
  const permissions = within(region).getByRole("region", { name: "Observed file permissions" });
  expect(within(permissions).getByText(mode, { selector: "dd" })).toBeVisible();
  const groupRow = within(permissions).getByText("Group write bit", { selector: "dt" }).parentElement!;
  const otherRow = within(permissions).getByText("Other write bit", { selector: "dt" }).parentElement!;
  expect(within(groupRow).getByText(permissionFields(mode).group_write_bit ? "Enabled" : "Not enabled", { selector: "dd" })).toBeVisible();
  expect(within(otherRow).getByText(permissionFields(mode).other_write_bit ? "Enabled" : "Not enabled", { selector: "dd" })).toBeVisible();
  expect(within(region).getByText(/Effective access not evaluated\./)).toBeVisible();
  const observation = within(region).getByText("Observation 1", { selector: "strong" }).closest("li")!;
  await user.click(within(observation).getByText("Evidence reference", { selector: "summary" }));
  expect(within(observation).getByText(evidence.evidence_id!)).toBeVisible();
});

it.each(["unavailable_windows", "unsupported_platform"])('renders %s without guessed mode bits', async status => {
  const evidence = record({ artifact_type: "file_observation", permission_status: status, effective_access: "not_evaluated" });
  render(<AdaptiveRunPath run={run([evidence])} catalog={catalog} />);
  await openObservations();
  const region = screen.getByRole("region", { name: "Recorded adaptive decision" });
  const permissions = within(region).getByRole("region", { name: "Observed file permissions" });
  expect(within(permissions).getByText(status === "unavailable_windows" ? "Windows permissions not collected." : "Permissions not collected on this platform.")).toBeVisible();
  expect(within(permissions).queryByText(/^Mode$/)).not.toBeInTheDocument();
  expect(within(permissions).queryByText(/^Group write bit$/)).not.toBeInTheDocument();
  expect(within(permissions).queryByText(/^Other write bit$/)).not.toBeInTheDocument();
});

it.each([
  { group_write_bit: false },
  { group_write_bit: 1 },
  { permission_mode_octal: "660" },
  { permission_mode_octal: ["0660"] },
  { effective_access: "allowed" },
  { permission_status: "bogus" },
  { non_owner_write_bit: undefined },
])("redacts malformed recognized permission metadata %#", async override => {
  const fields: Record<string, unknown> = { ...permissionFields("0660"), ...override };
  if (Object.hasOwn(override, "non_owner_write_bit") && override.non_owner_write_bit === undefined) delete fields.non_owner_write_bit;
  const evidence = record({ artifact_type: "file_observation", ...fields });
  render(<AdaptiveRunPath run={run([evidence])} catalog={catalog} />);
  await openObservations();
  const region = screen.getByRole("region", { name: "Recorded adaptive decision" });
  expect(within(region).getByText("Permission metadata is incomplete or inconsistent.")).toBeVisible();
  expect(within(region).queryByText("0660", { selector: "dd" })).not.toBeInTheDocument();
});

it("ignores missing, unobserved, and nonfilesystem permission spoofs", async () => {
  const records = [
    record({ artifact_type: "file_observation", file_count: 2 }),
    record({ artifact_type: "file_observation", ...permissionFields("0666") }, "executed"),
    record({ artifact_type: "collector_observation", observation_kind: "collection_semantics", ...permissionFields("0666") }),
  ];
  render(<AdaptiveRunPath run={run(records)} catalog={catalog} />);
  await openObservations();
  expect(screen.queryByText("Observed file permissions")).not.toBeInTheDocument();
});

it("keeps distinct current-attempt observations separate", async () => {
  const first = record({ artifact_type: "file_observation", ...permissionFields("0640") });
  const second = record({ artifact_type: "file_observation", ...permissionFields("0666") });
  render(<AdaptiveRunPath run={run([first, second])} catalog={catalog} />);
  await openObservations();
  const region = screen.getByRole("region", { name: "Recorded adaptive decision" });
  expect(within(region).getAllByText("Observation 1", { selector: "strong" })).toHaveLength(1);
  expect(within(region).getAllByText("Observation 2", { selector: "strong" })).toHaveLength(1);
  expect(within(region).getByText("0640")).toBeVisible();
  expect(within(region).getByText("0666")).toBeVisible();
});

it("uses the decision projection instead of newer unrelated run evidence", async () => {
  const current = record({ artifact_type: "file_observation", ...permissionFields("0640") });
  const newer = record({ artifact_type: "file_observation", ...permissionFields("0666") });
  render(<AdaptiveRunPath run={run([current, newer], [current.evidence_id!])} catalog={catalog} />);
  await openObservations();
  const region = screen.getByRole("region", { name: "Recorded adaptive decision" });
  expect(within(region).getByText("0640")).toBeVisible();
  expect(within(region).queryByText("0666")).not.toBeInTheDocument();
});

it("retains earlier projected permission evidence with its source position and step", async () => {
  const earlier = record({ artifact_type: "file_observation", ...permissionFields("0640") });
  const newer = record({ artifact_type: "file_observation", ...permissionFields("0666") });
  const value = run([earlier, newer], [newer.evidence_id!]);
  const decision = value.ai_proposals![0]!;
  const observations = (decision.planner_state as Record<string, unknown>).observations as Record<string, unknown>;
  observations.attempts = [
    { attempt_index: 0, step_id: "earlier-inspect", evidence: [{ evidence_id: earlier.evidence_id, provenance: earlier.provenance, facts: earlier.content }] },
    { attempt_index: 1, step_id: "inspect", evidence: [] },
  ];
  render(<AdaptiveRunPath run={value} catalog={catalog} />);
  await openObservations();
  const region = screen.getByRole("region", { name: "Recorded adaptive decision" });
  expect(within(region).getByText("0640")).toBeVisible();
  expect(within(region).getByText("From run position 1")).toBeVisible();
  expect(within(region).getByText("None retained for this attempt")).toBeVisible();
  const observation = within(region).getByText("Observation 1", { selector: "strong" }).closest("li")!;
  await userEvent.setup().click(within(observation).getByText("Evidence reference", { selector: "summary" }));
  expect(within(observation).getByText("earlier-inspect", { selector: "code" })).toBeVisible();
  expect(within(region).queryByText("0666")).not.toBeInTheDocument();
});
