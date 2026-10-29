import { act, cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { CompositionKnowledge } from "../src/components/CompositionKnowledge";
import { compositionKnowledgeApi, type CompositionKnowledge as KnowledgeResponse } from "../src/lib/composition-knowledge";
import { knowledgeFixture, knowledgeResponse } from "./composition-knowledge-fixture";

vi.mock("../src/lib/api", () => ({ DEMO_MODE: false, request: vi.fn(), ApiError: class extends Error {} }));
afterEach(() => { cleanup(); vi.restoreAllMocks(); });
const shell = (objective: ReturnType<typeof knowledgeFixture>["objective"]) => <MemoryRouter><CompositionKnowledge objective={objective} /></MemoryRouter>;

it("opens explicitly, keeps failed-route findings, and distinguishes observed records from runner claims", async () => {
  const user = userEvent.setup();
  const { objective, value } = knowledgeFixture();
  const read = vi.spyOn(compositionKnowledgeApi, "read").mockResolvedValue(value);
  render(shell(objective));
  expect(read).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Findings across attempts" }));
  const failed = await screen.findByRole("region", { name: "Findings from attempt 1" });
  expect(failed).toHaveTextContent("Failed");
  expect(failed).toHaveTextContent("Observed");
  expect(failed).toHaveTextContent("0640");
  expect(failed).toHaveTextContent("Permissions (octal)");
  expect(screen.getByRole("region", { name: "Findings from attempt 2" })).toHaveTextContent("Runner-reported");
  expect(screen.getByText("Recorded history")).toBeInTheDocument();
  expect(within(failed).getByRole("link", { name: "Open source run" })).toHaveAttribute("href", "/runs/run-knowledge-1");
  const sourceDetails = within(failed).getByText("Source details and 3 more fields");
  expect(within(failed).getByText("0640").closest("details")).toBeNull();
  expect(within(failed).getByText("128").closest("details")).toBeNull();
  await user.click(sourceDetails);
  expect(failed).toHaveTextContent("Historical finding; current resource state has not been checked.");
  expect(read).toHaveBeenCalledOnce();
});

it("bounds selection without hiding the ninth attempt and loads only after an explicit request", async () => {
  const user = userEvent.setup();
  const { objective } = knowledgeFixture(9);
  const read = vi.spyOn(compositionKnowledgeApi, "read").mockImplementation(async (owner, ids) => knowledgeResponse(owner, ids));
  render(shell(objective));
  await user.click(screen.getByRole("button", { name: "Findings across attempts" }));
  await screen.findByRole("region", { name: "Findings from attempt 9" });
  await user.click(screen.getByText("Choose attempts"));
  expect(screen.getAllByRole("checkbox")).toHaveLength(9);
  expect(screen.getByRole("checkbox", { name: "Attempt 1 Failed" })).toBeDisabled();
  await user.click(screen.getByRole("checkbox", { name: "Attempt 2 Completed" }));
  await user.click(screen.getByRole("checkbox", { name: "Attempt 1 Failed" }));
  expect(read).toHaveBeenCalledOnce();
  expect(screen.queryByRole("region", { name: "Findings from attempt 9" })).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Load selected findings" }));
  await screen.findByRole("region", { name: "Findings from attempt 1" });
  const selected = read.mock.calls[1]![1];
  expect(selected).toHaveLength(8);
  expect(selected).toContain(objective.attempts[0]!.request.composition_attempt.attempt_id);
  expect(selected).not.toContain(objective.attempts[1]!.request.composition_attempt.attempt_id);
});

it("discards a delayed response after switching objectives", async () => {
  const user = userEvent.setup();
  const first = knowledgeFixture(1, "a"), second = knowledgeFixture(1, "b");
  let resolve!: (value: KnowledgeResponse) => void;
  const read = vi.spyOn(compositionKnowledgeApi, "read").mockReturnValueOnce(new Promise(done => { resolve = done; })).mockResolvedValueOnce(second.value);
  const view = render(shell(first.objective));
  await user.click(screen.getByRole("button", { name: "Findings across attempts" }));
  expect(screen.getByRole("status")).toHaveTextContent("Opening recorded findings");
  view.rerender(shell(second.objective));
  await act(async () => resolve(first.value));
  expect(screen.queryByRole("region", { name: "Findings across attempts" })).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Findings across attempts" }));
  await screen.findByRole("region", { name: "Findings from attempt 1" });
  expect(read.mock.calls[1]![0].owner.job_id).toBe(second.objective.owner.job_id);
});

it("discards responses for a previous selection and keeps a closed panel closed", async () => {
  const user = userEvent.setup();
  const { objective, value } = knowledgeFixture();
  const completions: Array<(value: KnowledgeResponse) => void> = [];
  const read = vi.spyOn(compositionKnowledgeApi, "read").mockImplementation(() => new Promise(done => completions.push(done)));
  render(shell(objective));
  await user.click(screen.getByRole("button", { name: "Findings across attempts" }));
  await user.click(screen.getByText("Choose attempts"));
  await user.click(screen.getByRole("checkbox", { name: "Attempt 1 Failed" }));
  await act(async () => completions[0]!(value));
  expect(screen.queryByRole("region", { name: "Findings from attempt 1" })).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Load selected findings" }));
  await user.click(screen.getByRole("button", { name: "Hide findings" }));
  await act(async () => completions[1]!(knowledgeResponse(objective, [objective.attempts[1]!.request.composition_attempt.attempt_id])));
  expect(screen.queryByRole("region", { name: "Findings across attempts" })).not.toBeInTheDocument();
  expect(read).toHaveBeenCalledTimes(2);
});

it("keeps transport errors, unavailable sources and empty evidence distinct", async () => {
  const user = userEvent.setup();
  const { objective, value } = knowledgeFixture();
  value.attempts[0] = { ...value.attempts[0]!, source_status: "unavailable", source_binding: null, problem: "source_integrity_unavailable", findings: [], findings_total: 0, findings_truncated: false };
  value.attempts[1] = { ...value.attempts[1]!, findings: [], findings_total: 0 };
  const read = vi.spyOn(compositionKnowledgeApi, "read").mockRejectedValueOnce(new Error("Connection interrupted")).mockResolvedValueOnce(value);
  render(shell(objective));
  await user.click(screen.getByRole("button", { name: "Findings across attempts" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Saved findings unavailable");
  expect(screen.queryByRole("region", { name: "Findings from attempt 1" })).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Try again" }));
  const unavailable = await screen.findByRole("region", { name: "Findings from attempt 1" });
  expect(unavailable).toHaveTextContent("Saved source could not be verified");
  expect(within(unavailable).queryByRole("link")).not.toBeInTheDocument();
  expect(screen.getByRole("region", { name: "Findings from attempt 2" })).toHaveTextContent("no summarized findings");
  expect(read).toHaveBeenCalledTimes(2);
});

it("supports keyboard opening and renders evidence text without interpreting markup", async () => {
  const user = userEvent.setup();
  const { objective, value } = knowledgeFixture(1);
  value.attempts[0]!.findings[0]!.summary = { status: "<img src=x onerror=alert(1)>" };
  vi.spyOn(compositionKnowledgeApi, "read").mockResolvedValue(value);
  render(shell(objective));
  await user.tab();
  expect(screen.getByRole("button", { name: "Findings across attempts" })).toHaveFocus();
  await user.keyboard("{Enter}");
  expect(await screen.findByText("<img src=x onerror=alert(1)>")).toBeInTheDocument();
  expect(screen.queryByRole("img")).not.toBeInTheDocument();
});
