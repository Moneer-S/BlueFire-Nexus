import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { StructuredRuleEditor } from "../src/components/StructuredRuleEditor";
import { api } from "../src/lib/api";
import { demoCatalog } from "../src/lib/demo";
import type { StructuredRuleDraft } from "../src/lib/structured-rule-selection";
import { DetectionLabPage } from "../src/pages/DetectionLab";
import type { DetectionResource } from "../src/types";

const selection = { observation_kind: "collection_semantics", container: "jsonl", record_count: 8, retained_record_count: 8, redacted_record_count: 0, empty_record_count: 0 };

function editor(value: Record<string, unknown>) {
  const apply = vi.fn();
  function Harness() {
    const [source, setSource] = useState(JSON.stringify(value));
    const [draft, setDraft] = useState<StructuredRuleDraft | null>(null);
    return <><StructuredRuleEditor source={source} draft={draft} onDraft={setDraft} onApply={next => { apply(JSON.parse(next)); setSource(next); setDraft(null); }} /><output data-testid="selection">{source}</output></>;
  }
  render(<Harness />);
  return { user: userEvent.setup(), apply };
}

it("removes only the collection format after explicit application", async () => {
  const { user, apply } = editor(selection);
  await user.click(screen.getByRole("button", { name: "Remove Collection format condition 2" }));
  expect(apply).not.toHaveBeenCalled();
  expect(JSON.parse(screen.getByTestId("selection").textContent!)).toEqual(selection);
  await user.click(screen.getByRole("button", { name: "Apply conditions" }));
  const { container, ...expected } = selection; void container;
  expect(apply).toHaveBeenCalledExactlyOnceWith(expected);
  expect(selection.container).toBe("jsonl");
});

it("authors a numeric count and boolean without converting the octal text", async () => {
  const { user, apply } = editor({ record_count: 8, other_write_bit: true, permission_mode_octal: "0666" });
  await user.clear(screen.getByRole("textbox", { name: /Value for condition 1/ }));
  await user.type(screen.getByRole("textbox", { name: /Value for condition 1/ }), "12");
  await user.selectOptions(screen.getByRole("combobox", { name: /Value for condition 2/ }), "false");
  await user.clear(screen.getByRole("textbox", { name: /Value for condition 3/ }));
  await user.type(screen.getByRole("textbox", { name: /Value for condition 3/ }), "0660");
  await user.click(screen.getByRole("button", { name: "Apply conditions" }));
  expect(apply).toHaveBeenCalledExactlyOnceWith({ record_count: 12, other_write_bit: false, permission_mode_octal: "0660" });
});

it("does not apply an invalid count or duplicate predicate and can discard the draft", async () => {
  const { user, apply } = editor({ record_count: 8, observation_kind: "collection_semantics" });
  await user.clear(screen.getByRole("textbox", { name: /Value for condition 1/ }));
  await user.type(screen.getByRole("textbox", { name: /Value for condition 1/ }), "1e3");
  expect(screen.getByRole("alert")).toHaveTextContent("non-negative whole number");
  expect(screen.getByRole("button", { name: "Apply conditions" })).toBeDisabled();
  await user.click(screen.getByRole("button", { name: "Discard condition edits" }));
  expect(screen.getByRole("textbox", { name: /Value for condition 1/ })).toHaveValue("8");
  await user.click(screen.getByRole("button", { name: "Add condition" }));
  expect(screen.getByRole("alert")).toHaveTextContent("already present");
  expect(apply).not.toHaveBeenCalled();
});

it("keeps unknown and complex selectors intact with no partial visual controls", () => {
  const original = { ...selection, "custom.condition": { any: [1, "1", true] } };
  const { apply } = editor(original);
  expect(screen.getByText("Visual editing unavailable")).toBeVisible();
  expect(screen.queryByRole("button", { name: "Apply conditions" })).not.toBeInTheDocument();
  expect(JSON.parse(screen.getByTestId("selection").textContent!)).toEqual(original);
  expect(apply).not.toHaveBeenCalled();
});

it("refreshes supported and unsupported source changes without stale controls or callbacks", () => {
  const onDraft = vi.fn();
  const onApply = vi.fn();
  const first = '{"path":"first"}';
  const unsupported = '{"custom":{"keep":"unchanged"}}';
  const current = '{"record_count":8}';
  const view = render(<StructuredRuleEditor source={first} draft={null} onDraft={onDraft} onApply={onApply} />);
  expect(screen.getByLabelText("Value for condition 1")).toHaveValue("first");
  fireEvent.change(screen.getByLabelText("Value for condition 1"), { target: { value: "unapplied" } });
  expect(onDraft).toHaveBeenLastCalledWith({ source: first, conditions: [{ field: "path", operator: "equals", value: "unapplied" }] });
  view.rerender(<StructuredRuleEditor source={unsupported} draft={null} onDraft={onDraft} onApply={onApply} />);
  expect(screen.getByText("Visual editing unavailable")).toBeVisible();
  expect(screen.queryByLabelText("Value for condition 1")).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Apply conditions" })).not.toBeInTheDocument();
  expect(onDraft).toHaveBeenCalledTimes(1);
  expect(onApply).not.toHaveBeenCalled();
  view.rerender(<StructuredRuleEditor source={current} draft={null} onDraft={onDraft} onApply={onApply} />);
  expect(screen.getByLabelText("Field for condition 1")).toHaveValue("record_count");
  expect(screen.getByLabelText("Value for condition 1")).toHaveValue("8");
  expect(screen.getByRole("button", { name: "Apply conditions" })).toBeDisabled();
  fireEvent.change(screen.getByLabelText("Value for condition 1"), { target: { value: "9" } });
  const pending: StructuredRuleDraft = { source: current, conditions: [{ field: "record_count", operator: "equals", value: "9" }] };
  expect(onDraft).toHaveBeenCalledTimes(2);
  expect(onDraft).toHaveBeenLastCalledWith(pending);
  view.rerender(<StructuredRuleEditor source={current} draft={pending} onDraft={onDraft} onApply={onApply} />);
  expect(onApply).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Apply conditions" }));
  expect(onApply).toHaveBeenCalledExactlyOnceWith(JSON.stringify({ record_count: 9 }, null, 2));
});

it("refuses empty rules while allowing a supported condition to be added", async () => {
  const { user, apply } = editor({ container: "gzip" });
  await user.click(screen.getByRole("button", { name: /Remove Collection format/ }));
  expect(screen.getByRole("button", { name: "Apply conditions" })).toBeDisabled();
  expect(screen.getByRole("alert")).toHaveTextContent("empty rule");
  await user.click(screen.getByRole("button", { name: "Add condition" }));
  await user.type(screen.getByRole("textbox", { name: /Value for condition 1/ }), "collection_semantics");
  await user.click(screen.getByRole("button", { name: "Apply conditions" }));
  expect(apply).toHaveBeenCalledExactlyOnceWith({ observation_kind: "collection_semantics" });
});

const id = `detection-${"a".repeat(20)}`;
function lab(value: Record<string, unknown> = selection, language = "internal") {
  const parent: DetectionResource = { kind: "detections", id, status: "parsed", digest: "sha256:authored-resource", created_at: "2026-10-01", updated_at: "2026-10-01", document: { candidate_id: id, revision_root_id: id, revision: 1, revision_kind: "origin", definition_digest: "sha256:authored-definition", title: "Collection baseline", state: "parsed", target_language: language, behavior_id: "sandbox.collection.records.v1", selection: structuredClone(value), logsource: { product: "bluefire", category: "collection" } } };
  const before = structuredClone(parent);
  vi.spyOn(api, "detections").mockResolvedValue({ schema_version: "v1", candidates: [parent] });
  vi.spyOn(api, "runs").mockResolvedValue({ schema_version: "v1", unavailable_run_count: 0, runs: [] });
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  vi.spyOn(api, "resources").mockResolvedValue({ schema_version: "v1", kind: "research-sources", resources: [] });
  vi.spyOn(api, "detectionHealth").mockResolvedValue({ schema_version: "v1", ready: true, persistence_ready: true, candidate_resources: 1, invalid_candidate_resources: 0, languages: { internal: { ready: true, authoritative: true, backend: "Structured matcher" } }, limits: { source_bytes: 262144, fixture_bytes: 1048576, fixtures_per_action: 128, evidence_per_action: 256, notes_per_action: 64 } });
  vi.spyOn(api, "detectionRunEvaluations").mockResolvedValue({ evaluations: [] });
  const tune = vi.spyOn(api, "tuneDetection").mockRejectedValue(new Error("Authored backend refusal"));
  const evaluate = vi.spyOn(api, "evaluateDetectionRun");
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const mount = () => render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/detection-lab?candidate=${id}&candidate_scope=registry`]}><DetectionLabPage /></MemoryRouter></QueryClientProvider>);
  let view = mount();
  return { user: userEvent.setup(), tune, evaluate, parent, before, remount: () => { view.unmount(); view = mount(); } };
}

async function openTune(user: ReturnType<typeof userEvent.setup>, internal = true) {
  await user.click(await screen.findByRole("tab", { name: "Revisions" }));
  await user.click(screen.getByText(internal ? "Revise this rule" : "Advanced clone and tune"));
  await user.click(screen.getByRole("radio", { name: /Tune rule behavior/ }));
  const reason = screen.getByRole("textbox", { name: /Required research reason/ });
  await user.click(reason);
  await user.paste("Compare the same content across collection formats.");
  expect(reason).toHaveValue("Compare the same content across collection formats.");
}

it("submits the precise immutable tune payload only after applying visual edits", async () => {
  const { user, tune, evaluate, parent, before } = lab();
  await openTune(user);
  await user.click(screen.getByRole("button", { name: "Remove Collection format condition 2" }));
  expect(screen.getByRole("button", { name: "Save revised rule" })).toBeDisabled();
  await user.click(screen.getByText("Advanced structured inputs"));
  expect(screen.getByRole("textbox", { name: /Tuned selection JSON/ })).toBeDisabled();
  expect(tune).not.toHaveBeenCalled();
  expect(evaluate).not.toHaveBeenCalled();
  await user.click(screen.getByRole("tab", { name: "Candidate" }));
  await user.click(screen.getByRole("tab", { name: "Revisions" }));
  await user.click(screen.getByText("Revise this rule"));
  expect(screen.queryByRole("button", { name: /Remove Collection format/ })).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Save revised rule" })).toBeDisabled();
  await user.click(screen.getByRole("button", { name: "Apply conditions" }));
  await user.click(screen.getByRole("button", { name: "Save revised rule" }));
  await waitFor(() => expect(tune).toHaveBeenCalledTimes(1));
  const { container, ...expected } = selection; void container;
  expect(tune).toHaveBeenCalledWith(id, { reason: "Compare the same content across collection formats.", title: "Collection baseline", public_baselines: [], selection: expected, logsource: before.document.logsource });
  expect(await screen.findByText("Authored backend refusal")).toBeVisible();
  expect(parent).toEqual(before);
  expect(evaluate).not.toHaveBeenCalled();
});

it("preserves unsupported selection values in an ordinary advanced tune request", async () => {
  const value = { ...selection, "custom|contains": ["keep", { nested: true }] };
  const { user, tune, parent, before } = lab(value);
  await openTune(user);
  expect(screen.getByText("Visual editing unavailable")).toBeVisible();
  await user.click(screen.getByText("Advanced structured inputs"));
  expect(JSON.parse((screen.getByRole("textbox", { name: /Tuned selection JSON/ }) as HTMLTextAreaElement).value)).toEqual(value);
  const logsource = screen.getByRole("textbox", { name: /Tuned log source JSON/ });
  await user.clear(logsource); await user.paste('{"product":"bluefire","category":"collection-review"}');
  await user.click(screen.getByRole("button", { name: "Save revised rule" }));
  await waitFor(() => expect(tune).toHaveBeenCalledTimes(1));
  expect(tune).toHaveBeenCalledWith(id, expect.objectContaining({ selection: value, logsource: { product: "bluefire", category: "collection-review" } }));
  expect(parent).toEqual(before);
});

it("leaves non-internal rule tuning on its existing advanced path", async () => {
  const { user, tune } = lab({ observed: true }, "sqlite");
  await openTune(user, false);
  expect(screen.queryByRole("region", { name: "Visual rule conditions" })).not.toBeInTheDocument();
  await user.click(screen.getByText("Advanced structured inputs"));
  expect(screen.getByRole("textbox", { name: /Tuned selection JSON/ })).toBeEnabled();
  expect(tune).not.toHaveBeenCalled();
});

it("retains unapplied condition edits across a full page remount", async () => {
  const { user, tune, remount } = lab();
  await openTune(user);
  await user.click(screen.getByRole("button", { name: "Remove Collection format condition 2" }));
  remount();
  await user.click(await screen.findByText("Revise this rule"));
  expect(screen.getByText(/Unsaved inputs/)).toHaveTextContent("Draft kept in this browser tab");
  expect(screen.queryByRole("button", { name: /Remove Collection format/ })).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Save revised rule" })).toBeDisabled();
  await user.click(screen.getByRole("button", { name: "Apply conditions" }));
  await user.click(screen.getByRole("button", { name: "Save revised rule" }));
  await waitFor(() => expect(tune).toHaveBeenCalledTimes(1));
  expect(tune.mock.calls[0]![1].selection).not.toHaveProperty("container");
});

it("global discard removes unapplied visual edits and restores the saved definition", async () => {
  const { user, tune, remount } = lab();
  await openTune(user);
  await user.click(screen.getByRole("button", { name: "Remove Collection format condition 2" }));
  await user.click(screen.getByRole("button", { name: "Discard local inputs" }));
  await user.click(screen.getByRole("button", { name: "Discard these inputs" }));
  remount();
  await openTune(user);
  expect(screen.getByRole("button", { name: "Remove Collection format condition 2" })).toBeVisible();
  expect(screen.getByRole("button", { name: "Apply conditions" })).toBeDisabled();
  expect(screen.queryByRole("button", { name: "Discard condition edits" })).not.toBeInTheDocument();
  expect(tune).not.toHaveBeenCalled();
});

it("uses human-readable suggestions without rewriting untouched custom text", async () => {
  const { user, apply } = editor({ artifact_type: "custom-observation", observation_kind: "filesystem", container: "jsonl" });
  expect(screen.getByRole("textbox", { name: "Value for condition 1" })).toHaveValue("custom-observation");
  await user.selectOptions(screen.getByRole("combobox", { name: "Suggested value for condition 2" }), screen.getByRole("option", { name: "Collection contents" }));
  await user.selectOptions(screen.getByRole("combobox", { name: "Suggested value for condition 3" }), screen.getByRole("option", { name: "Gzip compressed records" }));
  await user.click(screen.getByRole("button", { name: "Apply conditions" }));
  expect(apply).toHaveBeenCalledExactlyOnceWith({ artifact_type: "custom-observation", observation_kind: "collection_semantics", container: "gzip" });
});

function retainedCandidateDraft() {
  const key = Object.keys(sessionStorage).find(name => name.startsWith("bluefire.detection-draft.v1:") && JSON.parse(sessionStorage.getItem(name)!).value?.selectionJson !== undefined)!;
  expect(key).toBeTruthy();
  return { key, record: JSON.parse(sessionStorage.getItem(key)!) };
}

it("loads legacy retained inputs without a visual-draft field", async () => {
  const { user, remount } = lab();
  await openTune(user);
  const { key, record } = retainedCandidateDraft();
  delete record.value.structuredSelectionDraft;
  sessionStorage.setItem(key, JSON.stringify(record));
  remount();
  await user.click(await screen.findByText("Revise this rule"));
  expect(screen.getByRole("textbox", { name: /Required research reason/ })).toHaveValue("Compare the same content across collection formats.");
  expect(screen.getByRole("button", { name: "Remove Collection format condition 2" })).toBeVisible();
  expect(screen.queryByText(/retained draft could not be read/)).not.toBeInTheDocument();
});

it("preserves malformed retained draft bytes and reports their refusal", async () => {
  const { user, remount, tune } = lab();
  await openTune(user);
  const { key, record } = retainedCandidateDraft();
  record.value.structuredSelectionDraft = '{"source":"{}","conditions":[{"field":"unknown","operator":"equals","value":"do not overwrite"}]}';
  const raw = JSON.stringify(record);
  sessionStorage.setItem(key, raw);
  remount();
  expect(await screen.findByText(/retained draft could not be read/)).toBeVisible();
  expect(sessionStorage.getItem(key)).toBe(raw);
  expect(tune).not.toHaveBeenCalled();
});

it("refuses a retained visual draft bound to a different selection until explicitly discarded", async () => {
  const { user, remount, tune } = lab();
  await openTune(user);
  const { key, record } = retainedCandidateDraft();
  record.value.structuredSelectionDraft = JSON.stringify({ source: '{"container":"gzip"}', conditions: [{ field: "container", operator: "equals", value: "ustar" }] });
  sessionStorage.setItem(key, JSON.stringify(record));
  remount();
  await user.click(await screen.findByText("Revise this rule"));
  expect(screen.getByRole("alert")).toHaveTextContent("different selection");
  expect(screen.getByRole("button", { name: "Save revised rule" })).toBeDisabled();
  expect(screen.queryByRole("button", { name: "Apply conditions" })).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Discard condition edits" }));
  expect(screen.getByRole("button", { name: "Remove Collection format condition 2" })).toBeVisible();
  expect(tune).not.toHaveBeenCalled();
});
