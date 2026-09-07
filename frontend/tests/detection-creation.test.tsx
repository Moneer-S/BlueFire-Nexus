import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { DetectionAICreation } from "../src/components/DetectionAICreation";
import { DetectionLabPage } from "../src/pages/DetectionLab";
import { api } from "../src/lib/api";
import { checkedCreationEnvelope, readCreationDraft, storeCreationDraft, type DetectionCreationDecision, type DetectionCreationEnvelope, type DetectionCreationSource, type DetectionCreationValidation, type RunDetectionSelection } from "../src/lib/detection-creation";
import { AssistanceProvider, useAssistanceSelection } from "../src/state/AssistanceContext";

const digest = `sha256:${"a".repeat(64)}`, reviewed = `sha256:${"b".repeat(64)}`;
const runId = "run-20300101T000000Z-1234567890abcdef", jobId = `job-${"c".repeat(32)}`, parentId = `job-${"d".repeat(32)}`;
const selection: RunDetectionSelection = { kind: "run_detection", run_id: runId, source_binding_digest: digest, behavior_id: "sandbox.collection.records.v1", target_language: "sqlite", case_role: "attack" };
const generated = "SELECT fixture_id FROM logs WHERE retained_record_count > 0";
function source(): DetectionCreationSource { return { schema_version: "bluefire.detection-creation-source.v1", run_id: runId, run_title: "Observed collection", mode: "execute", source_run: { run_id: runId }, source_binding_digest: digest, observed_count: 2, evidence_count: 4, available: true, reason: null,
  behaviors: [{ behavior_id: selection.behavior_id, title: "Record collection", step_ids: ["collect"], observed_count: 1 }, { behavior_id: "sandbox.collection.archive.v1", title: "Whole-file collection", step_ids: ["archive"], observed_count: 1 }],
  languages: [{ id: "sqlite", available: true, reason: null, backend: { name: "SQLite" } }, { id: "sigma", available: false, reason: "Sigma backend unavailable", backend: {} }], limitations: ["Development evidence only."] }; }
function envelope(): DetectionCreationEnvelope { return { job: { schema_version: "bluefire.job.v1", job_id: jobId, kind: "detection.ai.create", state: "completed", request: { assistance_turn: { parent_job_id: parentId, step_id: "create" }, submitted_request: { selection }, context: { selected: selection, source: { source_run: { run_id: runId }, source_binding_digest: digest } }, provider_binding_digest: digest, observed_ids: ["evidence-selected"] }, progress: {} },
  proposal: { schema_version: "bluefire.detection-source-creation-proposal.v1", proposal_digest: digest, selected: selection, source_run: { run_id: runId }, title: "Retained collection", source: generated, reason: "Review observed retention fields.", evidence_refs: ["evidence-selected"], limitations: ["Separate benign tests remain necessary."], provider: { provider_id: "chosen.v1", model: "configured-model" }, provider_binding_digest: digest }, review_ready: true, decision: null, application_job: null, application: null, evaluation: null }; }
function accepted(body: DetectionCreationDecision): DetectionCreationEnvelope { return { ...envelope(), review_ready: false, decision: body, application_job: body.decision === "accept" ? { schema_version: "bluefire.job.v1", job_id: `job-${"e".repeat(32)}`, kind: "detection.ai.create.apply", state: "queued", request: { proposal_job_id: jobId, decision: body, assistance_turn: envelope().job.request!.assistance_turn }, progress: {} } : null }; }
function validation(body: { proposal_digest: string; title: string; source: string }): DetectionCreationValidation { return { ...body, reviewed_digest: reviewed, validation: { valid: true, target_language: "sqlite", backend: { name: "SQLite" } } }; }
function Witness() { return <output aria-label="Published selection">{JSON.stringify(useAssistanceSelection())}</output>; }
function mount(review = false) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const view = render(<QueryClientProvider client={client}><MemoryRouter><AssistanceProvider><Witness /><DetectionAICreation runId={runId} jobId={review ? jobId : undefined} /></AssistanceProvider></MemoryRouter></QueryClientProvider>);
  return { ...view, client, user: userEvent.setup() };
}
function stubReview() { vi.spyOn(api, "detectionCreation").mockResolvedValue(envelope()); return vi.spyOn(api, "validateDetectionCreation").mockImplementation(async (_id, body) => validation(body)); }

it("requires a choice for ambiguous behaviors and publishes the exact new-rule selection", async () => {
  vi.spyOn(api, "detectionCreationSource").mockResolvedValue(source());
  const submit = vi.spyOn(api, "submitAssistance");
  const { user } = mount();
  expect(await screen.findByRole("button", { name: "Draft rule with Assistant" })).toBeDisabled();
  expect(screen.getByLabelText("Published selection")).toBeEmptyDOMElement();
  await user.selectOptions(screen.getByLabelText(/Behavior to detect/), selection.behavior_id);
  await user.selectOptions(screen.getByLabelText(/Development case/), "benign");
  expect(screen.getByRole("button", { name: "Draft rule with Assistant" })).toBeEnabled();
  expect(JSON.parse(screen.getByLabelText("Published selection").textContent!)).toMatchObject({ kind: "run_detection", selected: { ...selection, case_role: "benign" } });
  expect(screen.getByRole("option", { name: /Sigma rule/ })).toBeDisabled();
  expect(submit).not.toHaveBeenCalled();
});

it("explains unavailable observations without publishing a creation request", async () => {
  vi.spyOn(api, "detectionCreationSource").mockResolvedValue({ ...source(), available: false, reason: "No independent observations are retained.", observed_count: 0, behaviors: [] });
  mount();
  expect(await screen.findByText("No independent observations are retained.")).toBeVisible();
  expect(screen.queryByRole("button", { name: "Draft rule with Assistant" })).not.toBeInTheDocument();
  expect(screen.getByLabelText("Published selection")).toBeEmptyDOMElement();
});

it("does not load or auto-select existing candidates in explicit creation mode", async () => {
  vi.spyOn(api, "detectionCreationSource").mockResolvedValue({ ...source(), behaviors: [source().behaviors[0]!] });
  vi.spyOn(api, "runs").mockResolvedValue({ schema_version: "bluefire.runs.v1", runs: [], unavailable_run_count: 0 });
  vi.spyOn(api, "runDetail").mockImplementation(() => new Promise(() => {}));
  const candidates = vi.spyOn(api, "detections");
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/detection-lab?run=${runId}&create=1`]}><AssistanceProvider><Witness /><DetectionLabPage /></AssistanceProvider></MemoryRouter></QueryClientProvider>);
  expect(await screen.findByRole("button", { name: "Draft rule with Assistant" })).toBeEnabled();
  expect(candidates).not.toHaveBeenCalled();
  expect(screen.queryByRole("tablist", { name: "Detection candidate details" })).not.toBeInTheDocument();
  expect(JSON.parse(screen.getByLabelText("Published selection").textContent!)).toMatchObject({ kind: "run_detection", selected: selection });
});

it("preserves edited source across status reads and remount without applying it", async () => {
  stubReview(); const save = vi.spyOn(api, "reviewDetectionCreation");
  const first = mount(true);
  const editor = await screen.findByLabelText(/Rule source/);
  await first.user.clear(editor); await first.user.type(editor, "SELECT fixture_id FROM logs");
  await act(async () => { first.client.setQueryData(["detection-creation", jobId], structuredClone(envelope())); });
  expect(editor).toHaveValue("SELECT fixture_id FROM logs");
  first.unmount(); mount(true);
  expect(await screen.findByLabelText(/Rule source/)).toHaveValue("SELECT fixture_id FROM logs");
  expect(save).not.toHaveBeenCalled();
});

it("invalidates a previous source check when text changes", async () => {
  const check = stubReview();
  const { user } = mount(true);
  await screen.findByLabelText(/Rule source/);
  await user.click(screen.getByRole("button", { name: "Check source" }));
  expect(await screen.findByText(/Source validated/)).toBeVisible();
  await user.type(screen.getByLabelText(/Rule source/), " LIMIT 1");
  expect(screen.queryByText(/Source validated/)).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Check source" }));
  await waitFor(() => expect(check).toHaveBeenCalledTimes(2));
  expect(check.mock.calls[1]![1].source).toBe(`${generated} LIMIT 1`);
});

it("validates and retains the exact edited decision before requesting one asynchronous save", async () => {
  const check = stubReview();
  const save = vi.spyOn(api, "reviewDetectionCreation").mockImplementation(async (_id, body) => {
    expect(readCreationDraft(jobId, envelope().proposal!)?.decision).toEqual(body);
    return accepted(body);
  });
  const { user } = mount(true);
  await screen.findByLabelText(/Rule source/);
  await user.type(screen.getByLabelText(/Rule source/), " LIMIT 1");
  await user.type(screen.getByLabelText("Reviewed by"), "Lab operator");
  await user.click(screen.getByRole("button", { name: "Save and evaluate this rule" }));
  await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
  expect(check).toHaveBeenCalledTimes(1);
  expect(save.mock.calls[0]![1]).toEqual({ decision: "accept", proposal_digest: digest, reviewed_digest: reviewed, title: "Retained collection", source: `${generated} LIMIT 1`, reviewed_by: "Lab operator" });
  expect(await screen.findByText("Save and evaluation: Queued")).toBeVisible();
  expect(screen.queryByRole("link", { name: "Open saved rule" })).not.toBeInTheDocument();
});

it("recovers a lost decision response with the same source and no new validation or generation", async () => {
  const check = stubReview();
  const save = vi.spyOn(api, "reviewDetectionCreation").mockRejectedValueOnce(new Error("Connection lost")).mockImplementation(async (_id, body) => accepted(body));
  const first = mount(true); await screen.findByLabelText(/Rule source/);
  await first.user.type(screen.getByLabelText("Reviewed by"), "Lab operator");
  await first.user.click(screen.getByRole("button", { name: "Save and evaluate this rule" }));
  await screen.findByText("Connection lost");
  const body = save.mock.calls[0]![1]; first.unmount();
  const second = mount(true); await screen.findByLabelText(/Rule source/);
  expect(screen.getByLabelText(/Rule source/)).toHaveAttribute("readonly");
  await second.user.click(screen.getByRole("button", { name: "Recover saved decision" }));
  await waitFor(() => expect(save).toHaveBeenCalledTimes(2));
  expect(save.mock.calls[1]![1]).toEqual(body); expect(check).toHaveBeenCalledTimes(1);
});

it("keeps a syntax failure editable without saving a placeholder candidate", async () => {
  stubReview(); vi.mocked(api.validateDetectionCreation).mockRejectedValueOnce(new Error("Query syntax is invalid"));
  const save = vi.spyOn(api, "reviewDetectionCreation");
  const { user } = mount(true); await screen.findByLabelText(/Rule source/);
  await user.type(screen.getByLabelText("Reviewed by"), "Lab operator");
  await user.click(screen.getByRole("button", { name: "Save and evaluate this rule" }));
  expect(await screen.findByText("Query syntax is invalid")).toBeVisible();
  expect(screen.getByLabelText(/Rule source/)).not.toHaveAttribute("readonly");
  expect(save).not.toHaveBeenCalled();
  await user.type(screen.getByLabelText(/Rule source/), " LIMIT 1");
  expect(screen.getByRole("button", { name: "Save and evaluate this rule" })).toBeEnabled();
});

it("renders the server's accepted source while retaining different local text", async () => {
  const proposal = envelope().proposal!;
  storeCreationDraft(jobId, proposal, { proposal_digest: digest, title: "My draft", source: "SELECT fixture_id FROM logs" });
  const decision: DetectionCreationDecision = { decision: "accept", proposal_digest: digest, reviewed_digest: reviewed, title: "Reviewed elsewhere", source: `${generated} LIMIT 2`, reviewed_by: "Other reviewer" };
  vi.spyOn(api, "detectionCreation").mockResolvedValue(accepted(decision));
  mount(true);
  expect(await screen.findByLabelText(/Rule source/)).toHaveValue(decision.source);
  expect(screen.getByLabelText("Rule title")).toHaveValue(decision.title);
  expect(readCreationDraft(jobId, proposal)?.title).toBe("My draft");
});

it("stops the owning Assistant operation rather than inventing a new run action", async () => {
  stubReview(); const cancel = vi.spyOn(api, "controlJob").mockResolvedValue(envelope().job);
  const { user } = mount(true); await screen.findByLabelText(/Rule source/);
  await user.click(screen.getByRole("button", { name: "Stop this operation" }));
  expect(cancel).toHaveBeenCalledWith(parentId, "cancel");
});

it("refuses to show an application that belongs to another proposal", () => {
  const value = envelope();
  value.application = { schema_version: "bluefire.detection-source-creation-application.v1", proposal_job_id: `job-${"f".repeat(32)}`, application_job_id: `job-${"e".repeat(32)}`, proposal_digest: digest, reviewed_digest: reviewed, candidate_id: `detection-${"a".repeat(20)}`, resource_digest: digest, definition_digest: digest, actual_source_digest: digest, evaluation_id: "evaluation", run_id: runId, source_binding_digest: digest, operator_modified: false, development_case: true };
  expect(() => checkedCreationEnvelope(value, jobId)).toThrow("saved rule does not match");
});

it("does not submit recovery while the exact decision still cannot be stored", async () => {
  stubReview();
  const save = vi.spyOn(api, "reviewDetectionCreation");
  const { user } = mount(true); await screen.findByLabelText(/Rule source/);
  await user.type(screen.getByLabelText("Reviewed by"), "Lab operator");
  const storage = vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("Storage denied"); });
  await user.click(screen.getByRole("button", { name: "Save and evaluate this rule" }));
  expect(await screen.findByText(/edits are visible here but could not be retained/)).toBeVisible();
  expect(save).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Recover saved decision" }));
  expect(save).not.toHaveBeenCalled();
  expect(readCreationDraft(jobId, envelope().proposal!)).toBeUndefined();
  storage.mockRestore();
});

function completed(): DetectionCreationEnvelope {
  const body: DetectionCreationDecision = { decision: "accept", proposal_digest: digest, reviewed_digest: reviewed, title: "Retained collection", source: generated, reviewed_by: "Lab operator" };
  const value=accepted(body), candidateId=`detection-${"a".repeat(20)}`;
  value.application_job!.state="completed";
  const sourceRecord={run_id:runId,manifest_digest:digest,evidence_digest:digest,observed_records_digest:digest,observed_count:2,evidence_count:4,excluded_provenance_counts:{executed:2}};
  value.proposal!.source_run=sourceRecord;
  value.job.request!.context={selected:selection,source:{source_run:sourceRecord,source_binding_digest:digest}};
  value.application={schema_version:"bluefire.detection-source-creation-application.v1",proposal_job_id:jobId,application_job_id:value.application_job!.job_id,proposal_digest:digest,reviewed_digest:reviewed,candidate_id:candidateId,resource_digest:digest,definition_digest:digest,actual_source_digest:digest,evaluation_id:"detection-evaluation-selected",run_id:runId,source_binding_digest:digest,operator_modified:false,development_case:true};
  value.evaluation={schema_version:"bluefire.detection-run-evaluation.v1",evaluation_id:value.application.evaluation_id,development_case:true,question:"Does this rule match observed collection?",case_role:"attack",case_role_basis:"operator_declared",candidate:{candidate_id:candidateId,revision_root_id:candidateId,revision:1,definition_digest:digest,query_sha256:digest,source_sha256:digest,target_language:"sqlite",parser_backend:{name:"SQLite"}},source:sourceRecord,
    result:{state:"not_matched",match_count:0,evaluated_evidence_ids:["evidence-selected"],matched_evidence_ids:[],gap_count:0,gap_evidence_ids:[],mapped_fields:[],available_fields:[],unsupported_fields:[],missing_fields:[],diagnostic_codes:[]},backend:{name:"SQLite",executed:true},created_at:"2030-01-01T00:00:00Z",limitations:[]};
  return value;
}
it.each(["evidence_digest", "manifest_digest", "observed_records_digest"])("rejects changed %s in a same-run evaluation", (field) => {
  const value=completed();
  expect(checkedCreationEnvelope(value,jobId)).toBe(value);
  value.evaluation!.source={...value.evaluation!.source,[field]:reviewed};
  expect(()=>checkedCreationEnvelope(value,jobId)).toThrow("evaluation does not match");
});
it("rejects an application owned by another Assistant operation", () => {
  const value=completed();
  value.application_job!.request!.assistance_turn={parent_job_id:`job-${"f".repeat(32)}`,step_id:"create"};
  expect(()=>checkedCreationEnvelope(value,jobId)).toThrow("save operation could not be verified");
});
it("opens only the confirmed saved rule and preserves a missing-telemetry result as unknown", async () => {
  const value=completed();
  value.evaluation!.result={...value.evaluation!.result,state:"insufficient_evidence",match_count:null,gap_count:1,missing_fields:["retained_record_count"]};
  value.evaluation!.backend.executed=false;
  vi.spyOn(api,"detectionCreation").mockResolvedValue(value);
  const save=vi.spyOn(api,"reviewDetectionCreation");
  mount(true);
  const link=await screen.findByRole("link",{name:"Open saved rule"});
  expect(link).toHaveAttribute("href",`/detection-lab?run=${runId}&candidate=${value.application!.candidate_id}&candidate_scope=registry`);
  expect(screen.getByText("Insufficient evidence or backend unavailable")).toBeVisible();
  expect(screen.queryByText("0 matched records")).not.toBeInTheDocument();
  expect(screen.getByText("Development evidence")).toBeVisible();
  expect(save).not.toHaveBeenCalled();
});
it("keeps stopped accepted work visible without offering to restart its application", async () => {
  const value=accepted({decision:"accept",proposal_digest:digest,reviewed_digest:reviewed,title:"Retained collection",source:generated,reviewed_by:"Lab operator"});
  value.job.progress.stopped=true;value.application_job!.state="cancelled";
  vi.spyOn(api,"detectionCreation").mockResolvedValue(value);
  mount(true);
  expect(await screen.findByText("Operation stopped")).toBeVisible();
  expect(screen.queryByRole("button",{name:"Recover saved decision"})).not.toBeInTheDocument();
});

it("exports the exact accepted source and its evaluation instead of an earlier local draft", async () => {
  const value=completed();
  storeCreationDraft(jobId,value.proposal!,{proposal_digest:digest,title:"Unsubmitted local draft",source:"SELECT fixture_id FROM logs LIMIT 9"});
  vi.spyOn(api,"detectionCreation").mockResolvedValue(value);
  const blobs=vi.fn<(blob:Blob)=>string>(()=>"blob:creation-artifact");
  vi.stubGlobal("URL",class extends URL { static createObjectURL=blobs; static revokeObjectURL=vi.fn(); });
  const names:string[]=[];
  vi.spyOn(HTMLAnchorElement.prototype,"click").mockImplementation(function(this:HTMLAnchorElement){names.push(this.download);});
  const {user}=mount(true);
  await user.click(await screen.findByRole("button",{name:"Download rule source"}));
  await user.click(screen.getByRole("button",{name:"Download evaluation"}));
  const text=(blob:Blob)=>new Promise((resolve)=>{const reader=new FileReader();reader.onload=()=>resolve(reader.result);reader.readAsText(blob);});
  expect(names).toEqual([`${value.application!.candidate_id}.sql`,`${value.application!.candidate_id}-evaluation.json`]);
  expect(await text(blobs.mock.calls[0]![0])).toBe(generated);
  expect(await text(blobs.mock.calls[1]![0])).toBe(`${JSON.stringify(value.evaluation,null,2)}\n`);
});

it("focuses the measured result when an operator's asynchronous save finishes", async () => {
  stubReview();
  const value=completed();
  const pending=accepted(value.decision!);
  vi.spyOn(api,"reviewDetectionCreation").mockResolvedValue(pending);
  const { user, client }=mount(true);
  await user.type(await screen.findByLabelText("Reviewed by"),"Lab operator");
  await user.click(screen.getByRole("button",{name:"Save and evaluate this rule"}));
  await screen.findByText("Save and evaluation: Queued");
  await act(async()=>{client.setQueryData(["detection-creation",jobId],value);});
  expect(await screen.findByRole("heading",{name:"Rule saved and evaluated"})).toHaveFocus();
  expect(screen.getByRole("heading",{name:"0 matched records"})).toBeVisible();
  expect(screen.getByLabelText(/Rule source/)).not.toBeVisible();
  expect(screen.getByText("Development evidence")).toBeVisible();
  await user.click(screen.getByText(/^Approved source ·/));
  expect(screen.getByLabelText(/Rule source/)).toBeVisible();
  expect(screen.getByLabelText(/Rule source/)).toHaveValue(generated);
  expect(screen.getByLabelText(/Rule source/)).toHaveAttribute("readonly");
});

it("does not steal focus from other work when an accepted save finishes", async () => {
  stubReview();
  const value=completed();
  vi.spyOn(api,"reviewDetectionCreation").mockResolvedValue(accepted(value.decision!));
  const { user, client }=mount(true);
  await user.type(await screen.findByLabelText("Reviewed by"),"Lab operator");
  await user.click(screen.getByRole("button",{name:"Save and evaluate this rule"}));
  await screen.findByText("Save and evaluation: Queued");
  const outside=document.createElement("button"); outside.textContent="Other workspace"; document.body.append(outside); outside.focus();
  try {
    await act(async()=>{client.setQueryData(["detection-creation",jobId],value);});
    await screen.findByRole("heading",{name:"Rule saved and evaluated"});
    expect(outside).toHaveFocus();
  } finally { outside.remove(); }
});
