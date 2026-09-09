import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { DetectionRunEvaluations } from "../src/components/DetectionRunEvaluations";
import { api } from "../src/lib/api";
import { demoRuns } from "../src/lib/demo";
import type { DetectionCandidate } from "../src/types";

const id = "detection-evaluation-draft";
const candidate: DetectionCandidate = { candidate_id: id, state: "parsed", target_language: "sqlite", revision: 2, rule_source: "SELECT fixture_id FROM logs" };
const firstRun = demoRuns[0]!.run_id;
const secondRun = demoRuns[1]!.run_id;

function setup() {
  vi.spyOn(api, "detectionRunEvaluations").mockResolvedValue({ evaluations: [] });
  const evaluate = vi.spyOn(api, "evaluateDetectionRun").mockRejectedValue(new Error("The backend refused this evaluation."));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  let props = { candidate, resourceId: id, resourceDigest: "sha256:first-definition", sourceRunId: firstRun };
  const tree = () => <QueryClientProvider client={client}><MemoryRouter><DetectionRunEvaluations {...props} runs={demoRuns} revisions={[{ id, label: "Current" }, { id: "earlier", label: "Earlier revision" }]}/></MemoryRouter></QueryClientProvider>;
  let view = render(tree());
  return { evaluate, user: userEvent.setup(), change: (values: Partial<typeof props>) => { props = { ...props, ...values }; view.rerender(tree()); }, remount: () => { view.unmount(); client.clear(); view = render(tree()); } };
}

async function edit(user: ReturnType<typeof userEvent.setup>) {
  const question = screen.getByRole("textbox", { name: "Experiment question" });
  await user.clear(question); await user.type(question, "Check the retained collection");
  await user.selectOptions(screen.getByRole("combobox", { name: "Evaluation source run" }), secondRun);
  await user.selectOptions(screen.getByRole("combobox", { name: /Activity label/ }), "benign");
  await user.selectOptions(screen.getByRole("combobox", { name: "Related revision reports" }), "earlier");
}

it("retains all evaluation inputs across remount without evaluating cached text", async () => {
  const { user, remount, evaluate } = setup();
  await edit(user); remount();
  expect(screen.getByRole("textbox", { name: "Experiment question" })).toHaveValue("Check the retained collection");
  expect(screen.getByRole("combobox", { name: "Evaluation source run" })).toHaveValue(secondRun);
  expect(screen.getByRole("combobox", { name: /Activity label/ })).toHaveValue("benign");
  expect(screen.getByRole("combobox", { name: "Related revision reports" })).toHaveValue("earlier");
  expect(evaluate).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Evaluate full observed run" }));
  await screen.findByText("The backend refused this evaluation.");
  expect(evaluate).toHaveBeenCalledWith(id, { run_id: secondRun, question: "Check the retained collection", case_role: "benign", activity_label: "benign", evaluation_use: "unspecified" });
  remount();
  expect(screen.getByRole("textbox", { name: "Experiment question" })).toHaveValue("Check the retained collection");
  expect(evaluate).toHaveBeenCalledTimes(1);
});

it("isolates exact candidate version and source context while retaining the original inputs", async () => {
  const { user, change, evaluate } = setup();
  await edit(user);
  change({ sourceRunId: secondRun });
  expect(screen.getByRole("textbox", { name: "Experiment question" })).not.toHaveValue("Check the retained collection");
  expect(screen.getByRole("combobox", { name: /Activity label/ })).toHaveValue("unknown");
  change({ sourceRunId: firstRun });
  expect(screen.getByRole("textbox", { name: "Experiment question" })).toHaveValue("Check the retained collection");
  change({ resourceDigest: "sha256:next-definition", candidate: { ...candidate, revision: 3 } });
  expect(screen.getByRole("textbox", { name: "Experiment question" })).not.toHaveValue("Check the retained collection");
  change({ resourceDigest: "sha256:first-definition", candidate });
  expect(screen.getByRole("textbox", { name: "Experiment question" })).toHaveValue("Check the retained collection");
  expect(evaluate).not.toHaveBeenCalled();
});

it("keeps storage-failed edits in the session and discards only after confirmation", async () => {
  const { user, remount, evaluate } = setup();
  vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new DOMException("Full", "QuotaExceededError"); });
  await edit(user); remount();
  expect(screen.getByRole("alert")).toHaveTextContent("only for this open session");
  expect(screen.getByRole("textbox", { name: "Experiment question" })).toHaveValue("Check the retained collection");
  await user.click(screen.getByRole("button", { name: "Discard evaluation inputs" }));
  await user.click(screen.getByRole("button", { name: "Keep editing" }));
  expect(screen.getByRole("textbox", { name: "Experiment question" })).toHaveValue("Check the retained collection");
  await user.click(screen.getByRole("button", { name: "Discard evaluation inputs" }));
  await user.click(screen.getByRole("button", { name: "Discard these inputs" }));
  expect(screen.getByRole("combobox", { name: /Activity label/ })).toHaveValue("unknown");
  expect(screen.getByRole("combobox", { name: "Evaluation source run" })).toHaveValue(firstRun);
  expect(screen.getByRole("button", { name: "Discard evaluation inputs" })).toHaveFocus();
  expect(evaluate).not.toHaveBeenCalled();
});

it("rejects an unknown persisted case role without overwriting the stored record", async () => {
  const { user, remount, evaluate } = setup();
  await edit(user);
  const key = Object.keys(sessionStorage).find(key => key.startsWith("bluefire.detection-draft.v1:"))!;
  const retained = JSON.parse(sessionStorage.getItem(key)!);
  retained.value.role = "unreviewed-role";
  const raw = JSON.stringify(retained); sessionStorage.setItem(key, raw);
  remount();
  expect(screen.getByRole("alert")).toHaveTextContent("stored bytes have been left untouched");
  expect(screen.getByRole("combobox", { name: /Activity label/ })).toHaveValue("unknown");
  expect(sessionStorage.getItem(key)).toBe(raw);
  expect(evaluate).not.toHaveBeenCalled();
});

it("does not attach a delayed refusal to a changed candidate definition", async () => {
  const { user, change, evaluate } = setup();
  let fail!: (error: Error) => void;
  evaluate.mockImplementation(() => new Promise((_resolve, reject) => { fail = reject; }));
  await edit(user);
  await user.click(screen.getByRole("button", { name: "Evaluate full observed run" }));
  change({ resourceDigest: "sha256:next-definition" });
  await act(async () => fail(new Error("Old definition refused")));
  expect(screen.queryByText("Old definition refused")).not.toBeInTheDocument();
  expect(screen.getByRole("textbox", { name: "Experiment question" })).not.toHaveValue("Check the retained collection");
  expect(evaluate).toHaveBeenCalledTimes(1);
});

it("exports every retained input with its exact candidate/source binding", async () => {
  const { user, evaluate } = setup();
  await edit(user);
  let exported: Blob | undefined;
  vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: vi.fn((blob: Blob) => { exported = blob; return "blob:local-inputs"; }), revokeObjectURL: vi.fn() }));
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
  await user.click(screen.getByRole("button", { name: "Export evaluation inputs" }));
  const raw = await new Promise<string>(resolve => { const reader = new FileReader(); reader.onload = () => resolve(String(reader.result)); reader.readAsText(exported!); });
  const payload = JSON.parse(raw);
  expect(payload.inputs).toEqual({ runId: secondRun, question: "Check the retained collection", role: "benign", relatedId: "earlier", evaluationUse: "unspecified" });
  expect(JSON.parse(payload.binding)).toMatchObject({ resourceId: id, resourceDigest: "sha256:first-definition", sourceRunId: firstRun, candidate });
  expect(evaluate).not.toHaveBeenCalled();
});

it("retains independent-use input separately without rewriting older role drafts", async () => {
  const { user, remount, evaluate } = setup();
  await edit(user);
  await user.selectOptions(screen.getByRole("combobox", { name: /Use of this data/ }), "independent");
  remount();
  expect(screen.getByRole("combobox", { name: /Use of this data/ })).toHaveValue("independent");
  expect(evaluate).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Evaluate full observed run" }));
  await screen.findByText("The backend refused this evaluation.");
  expect(evaluate).toHaveBeenLastCalledWith(id, { run_id: secondRun, question: "Check the retained collection", case_role: "benign", activity_label: "benign", evaluation_use: "independent" });
});
