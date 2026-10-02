import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Link, MemoryRouter, Route, Routes } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { api } from "../src/lib/api";
import { demoCatalog } from "../src/lib/demo";
import { DetectionLabPage } from "../src/pages/DetectionLab";
import type { DetectionResource } from "../src/types";

const id = `detection-${"b".repeat(20)}`;
const otherId = `detection-${"d".repeat(20)}`;
const title = "Collection internal";
const refusal = "Authored backend refusal; no evaluation result is assumed.";

function resource(candidateId: string, name: string, state: string): DetectionResource {
  return {
    kind: "detections", id: candidateId, status: state, digest: `sha256:${candidateId}`,
    created_at: "2026-09-06", updated_at: "2026-09-06",
    document: {
      candidate_id: candidateId, revision_root_id: candidateId, revision: 1, title: name,
      target_language: "internal", behavior_id: "sandbox.collection.stage.v1", state,
      selection: { observation_kind: "collection_semantics", record_count: 1, other_write_bit: true },
      logsource: { category: "collection", product: "bluefire" },
      parser_backend: { name: "bluefire-structured-matcher" },
    },
  };
}

function setup(state = "fixture_exercised") {
  const candidates = [resource(id, title, state), resource(otherId, "Other internal", state)];
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  vi.spyOn(api, "detections").mockImplementation(async () => ({ schema_version: "v1", candidates }));
  vi.spyOn(api, "runs").mockResolvedValue({ schema_version: "v1", unavailable_run_count: 0, runs: [] });
  const readRun = vi.spyOn(api, "runDetail").mockRejectedValue(new Error("No source run was selected."));
  vi.spyOn(api, "catalog").mockResolvedValue(demoCatalog);
  vi.spyOn(api, "resources").mockResolvedValue({ schema_version: "v1", kind: "research-sources", resources: [] });
  vi.spyOn(api, "detectionHealth").mockResolvedValue({
    schema_version: "v1", ready: true, persistence_ready: true,
    candidate_resources: 2, invalid_candidate_resources: 0,
    languages: { internal: { ready: true, authoritative: true, backend: "bluefire-structured-matcher" } },
    limits: { source_bytes: 262144, fixture_bytes: 1048576, fixtures_per_action: 128, evidence_per_action: 256, notes_per_action: 64 },
  });
  vi.spyOn(api, "detectionRunEvaluations").mockResolvedValue({ evaluations: [] });
  // Exercise the real page request path, but never fabricate a successful evaluation.
  const action = vi.spyOn(api, "detectionAction").mockRejectedValue(new Error(refusal));
  const otherActions = [
    vi.spyOn(api, "upsertDetection").mockRejectedValue(new Error("Unexpected rule creation")),
    vi.spyOn(api, "cloneDetection").mockRejectedValue(new Error("Unexpected clone")),
    vi.spyOn(api, "tuneDetection").mockRejectedValue(new Error("Unexpected tune")),
    vi.spyOn(api, "evaluateDetectionRun").mockRejectedValue(new Error("Unexpected observed evaluation")),
    vi.spyOn(api, "suggestDetectionRevision").mockRejectedValue(new Error("Unexpected assistance")),
  ];
  const mount = (path: string) => render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}>
    <Link to="/elsewhere">Leave lab</Link><Link to="/detection-lab">Return to lab</Link>
    <Routes><Route path="/detection-lab" element={<DetectionLabPage />} /><Route path="/elsewhere" element={<p>Elsewhere</p>} /></Routes>
  </MemoryRouter></QueryClientProvider>);
  let view = mount(`/detection-lab?candidate=${id}&candidate_scope=registry`);
  return {
    user: userEvent.setup(), candidates, client, action,
    remount: () => { view.unmount(); client.clear(); view = mount("/detection-lab"); },
    expectNoOtherActions: () => { otherActions.forEach(spy => expect(spy).not.toHaveBeenCalled()); expect(readRun).not.toHaveBeenCalled(); },
  };
}

type User = ReturnType<typeof userEvent.setup>;
const evaluateButton = () => screen.getByRole("button", { name: "Evaluate benign fixtures" });
const notesInput = () => screen.getByRole("textbox", { name: "Benign evaluation notes" });
const change = (label: string, value: string) => fireEvent.change(screen.getByLabelText(label, { exact: true }), { target: { value } });

async function openFixtures(user: User) {
  await screen.findByRole("heading", { name: title });
  await user.click(screen.getByRole("tab", { name: "Fixtures" }));
}

async function advancedInput(user: User) {
  const summary = screen.getByText("Advanced benign samples JSON", { selector: "summary" });
  if (!summary.closest("details")!.open) await user.click(summary);
  return screen.getByRole("textbox", { name: /^Benign fixtures JSON/ });
}

async function addSample(user: User, name = "ordinary") {
  await user.click(screen.getByRole("button", { name: "Add sample" }));
  change("Sample name 1", name);
}

async function addField(user: User, index: number, field: string, value: string) {
  await user.click(screen.getByRole("button", { name: "Add field to sample 1" }));
  await user.selectOptions(screen.getByRole("combobox", { name: `Field ${index} for sample 1` }), field);
  change(`Value ${index} for sample 1`, value);
}

async function applySample(user: User, count = "1") {
  await addSample(user);
  await addField(user, 1, "record_count", count);
  await user.click(screen.getByRole("button", { name: "Apply samples" }));
}

it.each(["fixture_exercised", "observed_exercised"])("submits exact typed and omitted fields only after explicit evaluation from %s", async state => {
  const { user, action, expectNoOtherActions } = setup(state);
  await openFixtures(user);
  await addSample(user, "normal-collection");
  await addField(user, 1, "record_count", "0");
  await addField(user, 2, "other_write_bit", "false");
  await addField(user, 3, "permission_mode_octal", "0600");
  await addField(user, 4, "path", "");
  await addField(user, 5, "observation_kind", "collection_semantics");
  await user.click(screen.getByRole("button", { name: "Remove field 5 from sample 1" }));
  expect(screen.getByText(/Missing rule fields: Observation kind/)).toBeVisible();
  expect(action).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Apply samples" }));
  const expected = [{ fixture_id: "normal-collection", record_count: 0, other_write_bit: false, permission_mode_octal: "0600", path: "" }];
  expect(JSON.parse((await advancedInput(user) as HTMLTextAreaElement).value)).toEqual(expected);
  expect(evaluateButton()).toBeDisabled();
  fireEvent.change(notesInput(), { target: { value: " \n " } });
  expect(evaluateButton()).toBeDisabled();
  fireEvent.change(notesInput(), { target: { value: "Normal collection\n\n  Authored for review  " } });
  expect(evaluateButton()).toBeEnabled();
  expect(action).not.toHaveBeenCalled();
  expectNoOtherActions();
  await user.click(evaluateButton());
  await screen.findByText(refusal);
  expect(action).toHaveBeenCalledTimes(1);
  expect(action).toHaveBeenCalledWith(id, "evaluate-benign", { fixtures: expected, notes: ["Normal collection", "Authored for review"] });
  expectNoOtherActions();
});

it("blocks evaluation and advanced edits while valid or invalid sample edits are pending, then restores applied inputs on discard", async () => {
  const { user, action, expectNoOtherActions } = setup();
  await openFixtures(user);
  await applySample(user);
  fireEvent.change(notesInput(), { target: { value: "Review the ordinary sample" } });
  const advanced = await advancedInput(user);
  const applied = (advanced as HTMLTextAreaElement).value;
  expect(evaluateButton()).toBeEnabled();
  change("Sample name 1", "pending-name");
  expect(screen.getByRole("button", { name: "Apply samples" })).toBeEnabled();
  expect(evaluateButton()).toBeDisabled();
  expect(advanced).toBeDisabled();
  expect(advanced).toHaveValue(applied);
  change("Value 1 for sample 1", "-1");
  expect(screen.getByRole("button", { name: "Apply samples" })).toBeDisabled();
  await user.click(evaluateButton());
  expect(action).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Discard sample edits" }));
  expect(screen.getByLabelText("Sample name 1", { exact: true })).toHaveValue("ordinary");
  expect(screen.getByLabelText("Value 1 for sample 1", { exact: true })).toHaveValue("1");
  expect(advanced).toHaveValue(applied);
  expect(advanced).toBeEnabled();
  expect(notesInput()).toHaveValue("Review the ordinary sample");
  expect(evaluateButton()).toBeEnabled();
  expect(action).not.toHaveBeenCalled();
  expectNoOtherActions();
});

it("retains applied samples, invalid pending values and notes across candidate changes, navigation and reload without evaluation", async () => {
  const { user, action, remount, expectNoOtherActions } = setup();
  await openFixtures(user);
  await applySample(user);
  fireEvent.change(notesInput(), { target: { value: "Keep the original applied sample" } });
  change("Value 1 for sample 1", "-1");
  await user.click(screen.getByRole("button", { name: /Other internal/ }));
  await user.click(screen.getByRole("tab", { name: "Fixtures" }));
  expect(screen.queryByLabelText("Sample name 1", { exact: true })).not.toBeInTheDocument();
  expect(notesInput()).toHaveValue("");
  await user.click(screen.getByRole("button", { name: /Collection internal/ }));
  expect(screen.getByLabelText("Value 1 for sample 1", { exact: true })).toHaveValue("-1");
  await user.click(screen.getByRole("link", { name: "Leave lab" }));
  await user.click(screen.getByRole("link", { name: "Return to lab" }));
  expect(await screen.findByLabelText("Value 1 for sample 1", { exact: true })).toHaveValue("-1");
  remount();
  expect(await screen.findByLabelText("Value 1 for sample 1", { exact: true })).toHaveValue("-1");
  expect(notesInput()).toHaveValue("Keep the original applied sample");
  const advanced = await advancedInput(user);
  expect(JSON.parse((advanced as HTMLTextAreaElement).value)).toEqual([{ fixture_id: "ordinary", record_count: 1 }]);
  expect(advanced).toBeDisabled();
  expect(evaluateButton()).toBeDisabled();
  expect(screen.getByRole("button", { name: "Apply samples" })).toBeDisabled();
  change("Value 1 for sample 1", "2");
  await user.click(screen.getByRole("button", { name: "Apply samples" }));
  expect(JSON.parse((advanced as HTMLTextAreaElement).value)).toEqual([{ fixture_id: "ordinary", record_count: 2 }]);
  expect(action).not.toHaveBeenCalled();
  expectNoOtherActions();
});

it("isolates authoritative candidate versions while restoring each version's own applied and pending sample edits", async () => {
  const { user, candidates, client, action, expectNoOtherActions } = setup();
  await openFixtures(user);
  await applySample(user);
  fireEvent.change(notesInput(), { target: { value: "Version one notes" } });
  change("Sample name 1", "version-one-pending");
  act(() => client.setQueryData(["detections"], { schema_version: "v1", candidates: structuredClone(candidates) }));
  expect(screen.getByLabelText("Sample name 1", { exact: true })).toHaveValue("version-one-pending");
  const changed = structuredClone(candidates);
  changed[0]!.digest = "sha256:authoritative-version-two";
  changed[0]!.document.revision = 2;
  changed[0]!.document.selection = { observation_kind: "filesystem" };
  act(() => client.setQueryData(["detections"], { schema_version: "v1", candidates: changed }));
  await waitFor(() => expect(screen.getByRole("tab", { name: "Candidate" })).toHaveAttribute("aria-selected", "true"));
  await user.click(screen.getByRole("tab", { name: "Fixtures" }));
  expect(screen.queryByLabelText("Sample name 1", { exact: true })).not.toBeInTheDocument();
  expect(notesInput()).toHaveValue("");
  await addSample(user, "version-two");
  await user.click(screen.getByRole("button", { name: "Apply samples" }));
  fireEvent.change(notesInput(), { target: { value: "Version two notes" } });
  act(() => client.setQueryData(["detections"], { schema_version: "v1", candidates }));
  await waitFor(() => expect(screen.getByLabelText("Sample name 1", { exact: true })).toHaveValue("version-one-pending"));
  expect(notesInput()).toHaveValue("Version one notes");
  expect(evaluateButton()).toBeDisabled();
  expect(JSON.parse((await advancedInput(user) as HTMLTextAreaElement).value)).toEqual([{ fixture_id: "ordinary", record_count: 1 }]);
  act(() => client.setQueryData(["detections"], { schema_version: "v1", candidates: changed }));
  await waitFor(() => expect(screen.getByLabelText("Sample name 1", { exact: true })).toHaveValue("version-two"));
  expect(notesInput()).toHaveValue("Version two notes");
  expect(evaluateButton()).toBeEnabled();
  expect(action).not.toHaveBeenCalled();
  expectNoOtherActions();
});

it("preserves complex advanced JSON through reload and submits it unchanged through the existing benign action", async () => {
  const { user, action, remount, expectNoOtherActions } = setup();
  await openFixtures(user);
  const source = '[\n  {"fixture_id":"complex-sample", "custom":{"values":[false,0,null]}, "record_count":[0,1]}\n]';
  fireEvent.change(await advancedInput(user), { target: { value: source } });
  fireEvent.change(notesInput(), { target: { value: "Explicit complex synthetic record" } });
  expect(screen.getByText(/Use JSON for these samples/)).toBeVisible();
  expect(screen.queryByRole("button", { name: "Apply samples" })).not.toBeInTheDocument();
  expect(action).not.toHaveBeenCalled();
  remount();
  await screen.findByText(/Use JSON for these samples/);
  expect(await advancedInput(user)).toHaveValue(source);
  expect(notesInput()).toHaveValue("Explicit complex synthetic record");
  expect(evaluateButton()).toBeEnabled();
  expect(action).not.toHaveBeenCalled();
  await user.click(evaluateButton());
  await screen.findByText(refusal);
  expect(action).toHaveBeenCalledTimes(1);
  expect(action).toHaveBeenCalledWith(id, "evaluate-benign", { fixtures: JSON.parse(source), notes: ["Explicit complex synthetic record"] });
  expect(await advancedInput(user)).toHaveValue(source);
  expectNoOtherActions();
});

it("keeps benign authoring and evaluation gated by the existing lifecycle states", async () => {
  const { user, candidates, client, action, expectNoOtherActions } = setup("parsed");
  await openFixtures(user);
  for (const state of ["parsed", "hypothesis", "benign_evaluated", "rejected"]) {
    const changed = structuredClone(candidates);
    changed[0]!.status = state;
    changed[0]!.document.state = state;
    changed[0]!.digest = `sha256:state-${state}`;
    act(() => client.setQueryData(["detections"], { schema_version: "v1", candidates: changed }));
    await waitFor(() => expect(screen.getByRole("tab", { name: "Candidate" })).toHaveAttribute("aria-selected", "true"));
    await user.click(screen.getByRole("tab", { name: "Fixtures" }));
    expect(screen.getByRole("button", { name: "Add sample" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Apply samples" })).toBeDisabled();
    expect(await advancedInput(user)).toBeDisabled();
    expect(notesInput()).toBeDisabled();
    expect(evaluateButton()).toBeDisabled();
  }
  expect(action).not.toHaveBeenCalled();
  expectNoOtherActions();
});

it("clears applied samples, pending edits and notes only after explicit workspace discard confirmation", async () => {
  const { user, candidates, action, expectNoOtherActions } = setup();
  const originalCandidates = structuredClone(candidates);
  await openFixtures(user);
  await applySample(user);
  fireEvent.change(notesInput(), { target: { value: "Keep until explicitly discarded" } });
  change("Sample name 1", "unfinished-sample");
  await user.click(screen.getByRole("button", { name: "Discard local inputs" }));
  await user.click(screen.getByRole("button", { name: "Keep editing" }));
  expect(screen.getByLabelText("Sample name 1", { exact: true })).toHaveValue("unfinished-sample");
  expect(notesInput()).toHaveValue("Keep until explicitly discarded");
  await user.click(screen.getByRole("button", { name: "Discard local inputs" }));
  await user.click(screen.getByRole("button", { name: "Discard these inputs" }));
  await user.click(screen.getByRole("tab", { name: "Fixtures" }));
  expect(screen.queryByLabelText("Sample name 1", { exact: true })).not.toBeInTheDocument();
  expect(await advancedInput(user)).toHaveValue("");
  expect(notesInput()).toHaveValue("");
  expect(screen.queryByRole("button", { name: "Discard sample edits" })).not.toBeInTheDocument();
  expect(evaluateButton()).toBeDisabled();
  expect(candidates).toEqual(originalCandidates);
  expect(action).not.toHaveBeenCalled();
  expectNoOtherActions();
});

it("restores legacy applied samples and notes when the optional structured draft field is absent", async () => {
  const { user, remount, action, expectNoOtherActions } = setup();
  await openFixtures(user);
  await applySample(user);
  fireEvent.change(notesInput(), { target: { value: "Notes from the existing JSON workflow" } });
  const key = Object.keys(sessionStorage).find(key => key.startsWith("bluefire.detection-draft.v1:") && key.includes(id) && !key.includes(":observed:"))!;
  expect(key).toBeTruthy();
  const stored = JSON.parse(sessionStorage.getItem(key)!);
  const applied = stored.value.benign;
  delete stored.value.structuredBenignDraft;
  const legacy = JSON.stringify(stored);
  sessionStorage.setItem(key, legacy);
  remount();
  expect(await screen.findByLabelText("Sample name 1", { exact: true })).toHaveValue("ordinary");
  expect(screen.getByLabelText("Value 1 for sample 1", { exact: true })).toHaveValue("1");
  expect(notesInput()).toHaveValue("Notes from the existing JSON workflow");
  expect(await advancedInput(user)).toHaveValue(applied);
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Discard sample edits" })).not.toBeInTheDocument();
  expect(evaluateButton()).toBeEnabled();
  expect(sessionStorage.getItem(key)).toBe(legacy);
  expect(action).not.toHaveBeenCalled();
  expectNoOtherActions();
});

it("leaves an unrecognized structured draft's original storage bytes untouched until confirmed discard", async () => {
  const { user, remount, action, expectNoOtherActions } = setup();
  await openFixtures(user);
  await applySample(user);
  fireEvent.change(notesInput(), { target: { value: "Preserve this original retained record" } });
  const key = Object.keys(sessionStorage).find(key => key.startsWith("bluefire.detection-draft.v1:") && key.includes(id) && !key.includes(":observed:"))!;
  expect(key).toBeTruthy();
  const stored = JSON.parse(sessionStorage.getItem(key)!);
  stored.value.structuredBenignDraft = JSON.stringify({ source: stored.value.benign, samples: [], future_format: "keep these unknown inputs" });
  const unrecognized = JSON.stringify(stored);
  sessionStorage.setItem(key, unrecognized);
  remount();
  await screen.findByRole("heading", { name: title });
  expect(screen.getByRole("alert")).toHaveTextContent("stored bytes have been left untouched");
  expect(sessionStorage.getItem(key)).toBe(unrecognized);
  await user.click(screen.getByRole("tab", { name: "Fixtures" }));
  expect(await advancedInput(user)).toHaveValue("");
  expect(notesInput()).toHaveValue("");
  expect(evaluateButton()).toBeDisabled();
  expect(sessionStorage.getItem(key)).toBe(unrecognized);
  await user.click(screen.getByRole("button", { name: "Discard local inputs" }));
  await user.click(screen.getByRole("button", { name: "Keep editing" }));
  expect(sessionStorage.getItem(key)).toBe(unrecognized);
  await user.click(screen.getByRole("button", { name: "Discard local inputs" }));
  await user.click(screen.getByRole("button", { name: "Discard these inputs" }));
  expect(sessionStorage.getItem(key)).toBeNull();
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  expect(action).not.toHaveBeenCalled();
  expectNoOtherActions();
});
