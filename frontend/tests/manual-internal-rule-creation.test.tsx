import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Link, MemoryRouter, Route, Routes } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { api, ApiError } from "../src/lib/api";
import { demoCatalog } from "../src/lib/demo";
import { DetectionLabPage } from "../src/pages/DetectionLab";
import { permissionSelection } from "../src/components/PermissionConditionControl";
import { isManualInternalConditionsText, manualDetectionDefinition, readManualInternalConditions } from "../src/lib/manual-detection-definition";
import { buildStructuredSelection, structuredRuleFields, structuredRuleOperators } from "../src/lib/structured-rule-selection";
import { NewInternalRuleConditions } from "../src/components/NewInternalRuleConditions";
import type { DetectionResource } from "../src/types";

const key = "bluefire.detection-draft.v1:manual-new-rule";
const id = `detection-${"a".repeat(20)}`;
const collection = { artifact_type: "collector_observation", observation_kind: "collection_semantics" };
const origin: DetectionResource = { kind: "detections", id, status: "hypothesis", digest: "sha256:origin", created_at: "2026-10-01", updated_at: "2026-10-01", document: { candidate_id: id, revision_root_id: id, revision: 1, revision_kind: "origin", title: "Saved collection rule", target_language: "internal", behavior_id: "sandbox.collection.stage.v1", state: "hypothesis", selection: collection, logsource: { category: "collection", product: "bluefire" } } };

function setup() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  vi.spyOn(api, "detections").mockResolvedValue({ schema_version: "v1", candidates: [] });
  vi.spyOn(api, "runs").mockResolvedValue({ schema_version: "v1", unavailable_run_count: 0, runs: [] });
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  vi.spyOn(api, "resources").mockResolvedValue({ schema_version: "v1", kind: "research-sources", resources: [] });
  vi.spyOn(api, "detectionHealth").mockResolvedValue({ schema_version: "v1", ready: true, persistence_ready: true, candidate_resources: 0, invalid_candidate_resources: 0, languages: { internal: { ready: true, authoritative: true, backend: "Structured matcher" } }, limits: { source_bytes: 262144, fixture_bytes: 1048576, fixtures_per_action: 128, evidence_per_action: 256, notes_per_action: 64 } });
  const save = vi.spyOn(api, "upsertDetection").mockRejectedValue(new Error("Authored save refusal"));
  const effects = [vi.spyOn(api, "detectionAction"), vi.spyOn(api, "evaluateDetectionRun"), vi.spyOn(api, "suggestDetectionRevision"), vi.spyOn(api, "submitRun"), vi.spyOn(api, "aiDraft")];
  const mount = () => render(<QueryClientProvider client={client}><MemoryRouter initialEntries={["/detection-lab"]}><Link to="/elsewhere">Leave lab</Link><Link to="/detection-lab">Return to lab</Link><Routes><Route path="/detection-lab" element={<DetectionLabPage />} /><Route path="/elsewhere" element={<p>Elsewhere</p>} /></Routes></MemoryRouter></QueryClientProvider>);
  let view = mount();
  return { user: userEvent.setup(), save, effects, remount: () => { view.unmount(); client.clear(); view = mount(); } };
}

async function internal(user: ReturnType<typeof userEvent.setup>) {
  await user.type(await screen.findByRole("textbox", { name: "Title" }), "Collection rule");
  await user.selectOptions(screen.getByRole("combobox", { name: "Target language" }), "internal");
  await user.selectOptions(screen.getByRole("combobox", { name: "Condition starter" }), "collection");
}

async function add(user: ReturnType<typeof userEvent.setup>, index: number, field: string, value: string, operator = "equals") {
  await user.click(screen.getByRole("button", { name: "Add condition" }));
  const fieldControl = screen.getByLabelText(`Field for condition ${index}`);
  expect(fieldControl).toBeVisible();
  expect(fieldControl.tagName).toBe("SELECT");
  await user.selectOptions(fieldControl, field);
  if (operator !== "equals") {
    const operatorControl = screen.getByLabelText(`Operator for condition ${index}`);
    expect(operatorControl).toBeVisible();
    expect(operatorControl.tagName).toBe("SELECT");
    await user.selectOptions(operatorControl, operator);
  }
  const input = screen.getByLabelText(`Value for condition ${index}`);
  expect(input).toBeVisible();
  if (input.tagName === "INPUT") { await user.clear(input); await user.type(input, value); }
  else {
    expect(input.tagName).toBe("SELECT");
    await user.selectOptions(input, value);
  }
}

it("applies typed collection conditions before first save and submits the exact definition without side effects", async () => {
  const { user, save, effects } = setup();
  await internal(user);
  await add(user, 3, "record_count", "8");
  await add(user, 4, "other_write_bit", "false");
  await add(user, 5, "permission_mode_octal", "0660");
  await add(user, 6, "path", "evidence/", "startswith");
  await add(user, 7, "path", ".jsonl", "endswith");
  expect(screen.getByRole("button", { name: "Save rule draft" })).toBeDisabled();
  expect(save).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Apply conditions" }));
  expect(save).not.toHaveBeenCalled();
  const retained = JSON.parse(JSON.parse(sessionStorage.getItem(key)!).value.internalConditions);
  const expected = { ...collection, record_count: 8, other_write_bit: false, permission_mode_octal: "0660", "path|startswith": "evidence/", "path|endswith": ".jsonl" };
  expect(JSON.parse(retained.source)).toEqual(expected);
  expect(retained.draft).toBeNull();
  await user.click(screen.getByRole("button", { name: "Save rule draft" }));
  await screen.findByText("Authored save refusal");
  expect(save).toHaveBeenCalledExactlyOnceWith({ title: "Collection rule", behavior_id: "sandbox.collection.stage.v1", target_language: "internal", selection: expected, logsource: { category: "collection", product: "bluefire" }, predicted_fields: ["artifact_type", "observation_kind", "record_count", "other_write_bit", "permission_mode_octal", "path"], provenance: { source: "operator-authored", license: "Review required" }, known_misses: ["Requires declared observation fields."] });
  for (const effect of effects) expect(effect).not.toHaveBeenCalled();
});

it("retains applied and invalid pending conditions across navigation, reload, and language switches", async () => {
  const { user, save, effects, remount } = setup();
  await internal(user);
  await user.click(screen.getByRole("button", { name: "Apply conditions" }));
  await add(user, 3, "record_count", "1e3");
  expect(screen.getByRole("button", { name: "Apply conditions" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Save rule draft" })).toBeDisabled();
  await user.selectOptions(screen.getByRole("combobox", { name: "Target language" }), "sqlite");
  expect(screen.getByText(/Your internal conditions are kept/)).toBeVisible();
  expect(screen.getByRole("button", { name: "Save rule draft" })).toBeDisabled();
  await user.click(screen.getByRole("link", { name: "Leave lab" }));
  await user.click(screen.getByRole("link", { name: "Return to lab" }));
  await user.click(await screen.findByRole("button", { name: "Review internal conditions" }));
  remount();
  expect(await screen.findByRole("textbox", { name: "Value for condition 3" })).toHaveValue("1e3");
  expect(screen.getByRole("button", { name: "Save rule draft" })).toBeDisabled();
  const retained = JSON.parse(JSON.parse(sessionStorage.getItem(key)!).value.internalConditions);
  expect(JSON.parse(retained.source)).toEqual(collection);
  expect(retained.draft.conditions[2].value).toBe("1e3");
  await user.click(screen.getByRole("button", { name: "Discard condition edits" }));
  expect(screen.queryByRole("textbox", { name: "Value for condition 3" })).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Save rule draft" })).toBeEnabled();
  remount();
  expect(await screen.findByRole("textbox", { name: "Value for condition 2" })).toHaveValue("collection_semantics");
  expect(screen.getByRole("button", { name: "Save rule draft" })).toBeEnabled();
  expect(save).not.toHaveBeenCalled();
  for (const effect of effects) expect(effect).not.toHaveBeenCalled();
});

it("does not let empty or duplicate conditions replace an applied definition", async () => {
  const { user, save } = setup();
  await internal(user);
  await user.click(screen.getByRole("button", { name: "Apply conditions" }));
  await user.click(screen.getByRole("button", { name: "Add condition" }));
  expect(screen.getByRole("alert")).toHaveTextContent("already present");
  expect(screen.getByRole("button", { name: "Save rule draft" })).toBeDisabled();
  await user.click(screen.getByRole("button", { name: "Discard condition edits" }));
  await user.click(screen.getByRole("button", { name: "Remove Evidence type condition 1" }));
  await user.click(screen.getByRole("button", { name: "Remove Observation kind condition 1" }));
  expect(screen.getByRole("alert")).toHaveTextContent("empty rule");
  expect(screen.getByRole("button", { name: "Apply conditions" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Save rule draft" })).toBeDisabled();
  expect(save).not.toHaveBeenCalled();
});

it.each(["world_writable", "non_owner_writable"] as const)("restores legacy %s inputs and applies their exact permission selection", async condition => {
  sessionStorage.setItem(key, JSON.stringify({ binding: "manual-new-rule", value: { title: "Legacy", behaviorId: "sandbox.collection.stage.v1", language: "internal", permissionCondition: condition } }));
  const { user, save } = setup();
  expect(await screen.findByRole("combobox", { name: "Value for condition 4" })).toHaveValue("true");
  expect(screen.getByRole("button", { name: "Save rule draft" })).toBeDisabled();
  await user.click(screen.getByRole("button", { name: "Apply conditions" }));
  await user.click(screen.getByRole("button", { name: "Save rule draft" }));
  await screen.findByText("Authored save refusal");
  expect(save.mock.calls[0]![0]).toMatchObject({ selection: permissionSelection(condition), predicted_fields: Object.keys(permissionSelection(condition)) });
});

it("keeps other languages on their existing starter and restores the applied internal definition", async () => {
  const { user, save } = setup();
  await internal(user);
  await user.click(screen.getByRole("button", { name: "Apply conditions" }));
  await user.selectOptions(screen.getByRole("combobox", { name: "Target language" }), "sigma");
  await user.click(screen.getByRole("button", { name: "Save rule draft" }));
  await screen.findByText("Authored save refusal");
  expect(save.mock.calls[0]![0]).toMatchObject({ target_language: "sigma", selection: permissionSelection("staged"), predicted_fields: ["artifact_type", "path"], logsource: { category: "file_event", product: "generic" } });
  await user.selectOptions(screen.getByRole("combobox", { name: "Target language" }), "internal");
  expect(screen.getByRole("textbox", { name: "Value for condition 2" })).toHaveValue("collection_semantics");
  expect(screen.getByRole("button", { name: "Save rule draft" })).toBeEnabled();
});

it("clears both applied and pending conditions only after confirming discard", async () => {
  const { user, remount } = setup();
  await internal(user);
  await user.click(screen.getByRole("button", { name: "Apply conditions" }));
  await add(user, 3, "record_count", "8");
  await user.click(screen.getByRole("button", { name: "Discard New rule inputs" }));
  await user.click(screen.getByRole("button", { name: "Keep editing" }));
  expect(screen.getByRole("textbox", { name: "Value for condition 3" })).toHaveValue("8");
  await user.click(screen.getByRole("button", { name: "Discard New rule inputs" }));
  await user.click(screen.getByRole("button", { name: "Discard these inputs" }));
  expect(sessionStorage.getItem(key)).toBeNull();
  remount();
  await user.selectOptions(await screen.findByRole("combobox", { name: "Target language" }), "internal");
  expect(screen.getByRole("textbox", { name: "Value for condition 2" })).toHaveValue("staged/");
  expect(screen.queryByRole("textbox", { name: "Value for condition 3" })).not.toBeInTheDocument();
});

it("clones the exact collection origin with the submitted field metadata after explicit recovery", async () => {
  const { user, save } = setup();
  save.mockRejectedValue(new ApiError("Existing definition is immutable", "detection_revision_required", { existing_candidate_id: id }, 409));
  const existing = { ...origin, document: { ...origin.document, predicted_fields: ["path"] } };
  vi.spyOn(api, "detection").mockResolvedValue({ schema_version: "v1", candidate: existing });
  const clone = vi.spyOn(api, "cloneDetection").mockRejectedValue(new Error("Authored clone refusal"));
  await internal(user);
  await user.click(screen.getByRole("button", { name: "Apply conditions" }));
  await user.click(screen.getByRole("button", { name: "Save rule draft" }));
  const start = await screen.findByRole("button", { name: "Start another draft" });
  expect(clone).not.toHaveBeenCalled();
  await user.click(start);
  await screen.findByText("Authored clone refusal");
  expect(clone).toHaveBeenCalledExactlyOnceWith(id, { title: "Collection rule", reason: "Start another operator-authored draft from the same starter definition.", predicted_fields: ["artifact_type", "observation_kind"] });
  expect(existing.document.predicted_fields).toEqual(["path"]);
});

it.each(["selection", "type", "logsource", "origin"])("refuses duplicate-origin recovery for mismatched %s", async mismatch => {
  const { user, save } = setup();
  save.mockRejectedValue(new ApiError("Existing definition is immutable", "detection_revision_required", { existing_candidate_id: id }, 409));
  const bad = structuredClone(origin);
  if (mismatch === "selection") bad.document.selection = permissionSelection("staged");
  if (mismatch === "type") bad.document.selection = { ...collection, record_count: "8" };
  if (mismatch === "logsource") bad.document.logsource = { category: "file_event", product: "generic" };
  if (mismatch === "origin") bad.document.revision_kind = "tune";
  vi.spyOn(api, "detection").mockResolvedValue({ schema_version: "v1", candidate: bad });
  const clone = vi.spyOn(api, "cloneDetection");
  await internal(user);
  if (mismatch === "type") await add(user, 3, "record_count", "8");
  await user.click(screen.getByRole("button", { name: "Apply conditions" }));
  await user.click(screen.getByRole("button", { name: "Save rule draft" }));
  expect(await screen.findByText(/saved rule does not match this starter definition/)).toBeVisible();
  expect(screen.queryByRole("button", { name: "Start another draft" })).not.toBeInTheDocument();
  expect(clone).not.toHaveBeenCalled();
});

it("ignores a delayed duplicate-origin read after condition edits", async () => {
  const { user, save } = setup();
  save.mockRejectedValue(new ApiError("Existing definition is immutable", "detection_revision_required", { existing_candidate_id: id }, 409));
  let finish!: (value: Awaited<ReturnType<typeof api.detection>>) => void;
  const read = vi.spyOn(api, "detection").mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  await internal(user);
  await user.click(screen.getByRole("button", { name: "Apply conditions" }));
  await user.click(screen.getByRole("button", { name: "Save rule draft" }));
  await waitFor(() => expect(read).toHaveBeenCalled());
  await add(user, 3, "record_count", "9");
  await act(async () => finish({ schema_version: "v1", candidate: origin }));
  expect(screen.queryByRole("region", { name: "Matching saved rule" })).not.toBeInTheDocument();
  expect(screen.getByRole("textbox", { name: "Value for condition 3" })).toHaveValue("9");
});

it("preserves unsupported retained condition bytes until confirmed discard", async () => {
  const internalConditions = JSON.stringify({ source: '{"unknown":true}', draft: null });
  expect(isManualInternalConditionsText(internalConditions)).toBe(false);
  const raw = JSON.stringify({ binding: "manual-new-rule", value: { title: "Unrecognized", behaviorId: "sandbox.collection.stage.v1", language: "internal", internalConditions } });
  sessionStorage.setItem(key, raw);
  const { user, save } = setup();
  expect(await screen.findByRole("alert")).toHaveTextContent("stored bytes have been left untouched");
  expect(sessionStorage.getItem(key)).toBe(raw);
  await user.click(screen.getByRole("button", { name: "Discard New rule inputs" }));
  await user.click(screen.getByRole("button", { name: "Discard these inputs" }));
  expect(sessionStorage.getItem(key)).toBeNull();
  expect(save).not.toHaveBeenCalled();
});

function longConditions(value: string) {
  return structuredRuleFields.filter(field => field.type === "string").flatMap(field => structuredRuleOperators(field.key).map(operator => ({ field: field.key, operator, value: field.key === "permission_mode_octal" && operator === "equals" ? "0660" : value })));
}

it("keeps a valid large applied selection and pending edits visible when browser retention exceeds its limit", async () => {
  const conditions = longConditions("\\".repeat(4096));
  const built = buildStructuredSelection(conditions);
  if (!built.ok) throw new Error(built.error);
  const source = JSON.stringify(built.selection);
  const envelope = JSON.stringify({ source, draft: { source, conditions } });
  expect(envelope.length).toBeGreaterThan(1048576);
  expect(readManualInternalConditions(envelope)?.draft?.conditions).toEqual(conditions);
  sessionStorage.setItem(key, JSON.stringify({ binding: "manual-new-rule", value: { title: "Large rule", behaviorId: "sandbox.collection.stage.v1", language: "internal", internalConditions: JSON.stringify({ source, draft: null }) } }));
  const { user, remount, save } = setup();
  await user.clear(await screen.findByLabelText("Value for condition 1"));
  expect(screen.getByLabelText("Value for condition 2")).toHaveValue("\\".repeat(4096));
  expect(screen.getByRole("button", { name: "Save rule draft" })).toBeDisabled();
  expect(screen.getByRole("alert")).toHaveTextContent("only for this open session");
  const escaped = longConditions("\u0001".repeat(4096));
  const pending = { source, conditions: escaped };
  expect(JSON.stringify(pending).length).toBeGreaterThan(1048576);
  expect(readManualInternalConditions(JSON.stringify({ source, draft: pending }))?.draft).toEqual(pending);
  const valueInputs = screen.getAllByLabelText(/^Value for condition \d+$/, { selector: "input" });
  expect(escaped).toHaveLength(28);
  expect(valueInputs).toHaveLength(escaped.length);
  escaped.forEach((condition, index) => fireEvent.change(valueInputs[index]!, { target: { value: condition.value } }));
  expect(screen.getByText(/exceed the selection text limit/)).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Apply conditions" }));
  remount();
  expect(await screen.findByLabelText("Value for condition 1")).toHaveValue("\u0001".repeat(4096));
  expect(screen.getByLabelText("Value for condition 2")).toHaveValue("\u0001".repeat(4096));
  expect(screen.getByRole("button", { name: "Save rule draft" })).toBeDisabled();
  await user.click(screen.getByRole("button", { name: "Discard New rule inputs" }));
  await user.click(screen.getByRole("button", { name: "Discard these inputs" }));
  expect(save).not.toHaveBeenCalled();
});

it("refuses an oversized Apply without hiding or replacing the editable pending conditions", async () => {
  const value = { source: "{}", draft: { source: "{}", conditions: longConditions("\u0001".repeat(4096)) } };
  const onChange = vi.fn();
  render(<NewInternalRuleConditions value={value} onChange={onChange} />);
  expect(screen.getByRole("alert")).toHaveTextContent("exceed the selection text limit");
  expect(screen.getByRole("button", { name: "Apply conditions" })).toBeDisabled();
  expect(screen.getByText(/before saving this rule draft/)).toBeVisible();
  await userEvent.setup().click(screen.getByRole("button", { name: "Apply conditions" }));
  expect(onChange).not.toHaveBeenCalled();
  expect(screen.getByRole("textbox", { name: "Value for condition 1" })).toHaveValue("\u0001".repeat(4096));
});

it.each([
  ["malformed", "{"],
  ["unsupported", '{"unknown":true}'],
  ["oversized", '{"path":"other"}'.padEnd(262145, " ")],
])("still refuses a differing %s pending source after validating the applied source", (_label, pendingSource) => {
  const source = JSON.stringify(collection);
  const text = JSON.stringify({ source, draft: { source: pendingSource, conditions: [{ field: "path", operator: "equals", value: "pending" }] } });
  expect(readManualInternalConditions(text)).toBeNull();
  expect(isManualInternalConditionsText(text)).toBe(false);
});

it.each([
  { field: "path", operator: "equals", value: false },
  { field: "unknown", operator: "equals", value: "pending" },
  { field: "path", operator: "regex", value: "pending" },
])("does not let identical source text bypass pending-condition schema validation: %j", condition => {
  const source = JSON.stringify(collection);
  const text = JSON.stringify({ source, draft: { source, conditions: [condition] } });
  expect(readManualInternalConditions(text)).toBeNull();
  expect(isManualInternalConditionsText(text)).toBe(false);
});

it("requires valid applied conditions and refuses a usable definition while edits remain pending", () => {
  const source = JSON.stringify(collection);
  expect(manualDetectionDefinition("internal", { source, draft: null })?.selection).toEqual(collection);
  expect(manualDetectionDefinition("internal", { source, draft: { source, conditions: [{ field: "path", operator: "equals", value: "pending" }] } })).toBeNull();
  for (const invalidSource of ["{", "{}", '{"unknown":true}']) {
    expect(manualDetectionDefinition("internal", { source: invalidSource, draft: null })).toBeNull();
  }
});

it("retains a differing supported pending source as a mismatch without granting Save", async () => {
  const conditions = { source: JSON.stringify(collection), draft: { source: '{"path":"other"}', conditions: [{ field: "path", operator: "equals", value: "pending" }] } };
  const internalConditions = JSON.stringify(conditions);
  expect(readManualInternalConditions(internalConditions)).toEqual(conditions);
  const raw = JSON.stringify({ binding: "manual-new-rule", value: { title: "Mismatched source", behaviorId: "sandbox.collection.stage.v1", language: "internal", internalConditions } });
  sessionStorage.setItem(key, raw);
  const { user, save, effects } = setup();
  expect(await screen.findByRole("alert")).toHaveTextContent("different selection");
  expect(screen.getByRole("button", { name: "Save rule draft" })).toBeDisabled();
  expect(screen.queryByRole("button", { name: "Apply conditions" })).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Save rule draft" }));
  expect(sessionStorage.getItem(key)).toBe(raw);
  expect(save).not.toHaveBeenCalled();
  for (const effect of effects) expect(effect).not.toHaveBeenCalled();
});
