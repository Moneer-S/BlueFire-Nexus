import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, afterEach, expect, it, vi } from "vitest";
import { EngineActionReview } from "../src/components/EngineActionReview";
import { ApiError } from "../src/lib/api";
import { engineExperimentApi } from "../src/lib/engine-experiment-api";
import { acceptedAction, actionDigest, actionWorkspace, preparedAction } from "./engine-action-fixture";
vi.mock("../src/lib/engine-experiment-api", () => ({ engineExperimentApi: { workspace: vi.fn(), prepare: vi.fn(), submit: vi.fn() } }));
const close = vi.fn(), accepted = vi.fn();
const props = () => ({ open: true, onClose: close, experiment: actionWorkspace(), onAccepted: accepted });
beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(new Date("2026-11-04T12:01:00Z"));
  close.mockReset(); accepted.mockReset();
  vi.mocked(engineExperimentApi.workspace).mockReset().mockResolvedValue(actionWorkspace());
  vi.mocked(engineExperimentApi.prepare).mockReset().mockResolvedValue(preparedAction());
  vi.mocked(engineExperimentApi.submit).mockReset().mockResolvedValue(acceptedAction());
});
afterEach(() => vi.useRealTimers());
async function ready() { await screen.findByText("Intended outcome"); return screen.getByRole("button", { name: "Start baseline exploration" }); }
it("loads an unselected canonical review, requires acknowledgment, and locks repeated submissions", async () => {
  let finish!: (value: ReturnType<typeof acceptedAction>) => void;
  vi.mocked(engineExperimentApi.submit).mockReturnValue(new Promise(resolve => { finish = resolve; }));
  render(<EngineActionReview {...props()} />);
  const button = await ready();
  expect(engineExperimentApi.workspace).toHaveBeenCalledExactlyOnceWith(actionWorkspace().experiment_id);
  expect(button).toBeDisabled(); expect(screen.getByText("Exact identities and review binding").closest("details")).not.toHaveAttribute("open");
  expect(screen.getByText("Local test gateway")).toBeVisible(); expect(screen.getByText(/600s · 40 actions/)).toBeVisible();
  fireEvent.click(screen.getByRole("checkbox")); fireEvent.click(button); fireEvent.click(button);
  await waitFor(() => expect(engineExperimentApi.submit).toHaveBeenCalledTimes(1));
  await act(async () => finish(acceptedAction()));
  expect(accepted).toHaveBeenCalledWith(acceptedAction()); expect(close).toHaveBeenCalledTimes(1);
});
it("resets acknowledgment on reopen and supports Escape with focus restoration", async () => {
  const user = userEvent.setup();
  const trigger = document.createElement("button"); document.body.append(trigger); trigger.focus();
  const view = render(<EngineActionReview {...props()} />); await ready();
  await user.click(screen.getByRole("checkbox"));
  await user.keyboard("{Escape}"); expect(close).toHaveBeenCalledTimes(1);
  view.rerender(<EngineActionReview {...props()} open={false} />);
  await waitFor(() => expect(trigger).toHaveFocus());
  view.rerender(<EngineActionReview {...props()} />); await ready();
  expect(screen.getByRole("checkbox")).not.toBeChecked(); trigger.remove();
});
it("refuses changed workspace and expired review without submission", async () => {
  const view = render(<EngineActionReview {...props()} />); await ready(); fireEvent.click(screen.getByRole("checkbox"));
  view.rerender(<EngineActionReview {...props()} experiment={{ ...actionWorkspace(), revision: 2 }} />);
  expect(screen.getByRole("button", { name: "Start baseline exploration" })).toBeDisabled();
  expect(screen.getByRole("alert")).toHaveTextContent("workspace changed");
  view.rerender(<EngineActionReview {...props()} />);
  vi.setSystemTime(new Date("2026-11-04T12:11:00Z"));
  fireEvent.click(screen.getByRole("button", { name: "Start baseline exploration" }));
  await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/stale or expired/));
  expect(engineExperimentApi.submit).not.toHaveBeenCalled();
});
it("rechecks canonical presentation drift before submitting", async () => {
  render(<EngineActionReview {...props()} />); await ready();
  vi.mocked(engineExperimentApi.workspace).mockResolvedValue({ ...actionWorkspace(), workspace_digest: actionDigest("9") });
  fireEvent.click(screen.getByRole("checkbox")); fireEvent.click(screen.getByRole("button", { name: "Start baseline exploration" }));
  await screen.findByRole("alert"); expect(engineExperimentApi.submit).not.toHaveBeenCalled();
});
it("recovers ambiguous acceptance by retrying the same reference without preparing again", async () => {
  vi.mocked(engineExperimentApi.submit).mockRejectedValueOnce(new Error("network interrupted")).mockResolvedValueOnce(acceptedAction());
  render(<EngineActionReview {...props()} />); await ready();
  fireEvent.click(screen.getByRole("checkbox")); fireEvent.click(screen.getByRole("button", { name: "Start baseline exploration" }));
  await screen.findByText(/Acceptance is unconfirmed/);
  fireEvent.click(screen.getByRole("button", { name: "Retry exact prepared request" }));
  await waitFor(() => expect(accepted).toHaveBeenCalled());
  expect(engineExperimentApi.prepare).toHaveBeenCalledTimes(1);
  expect(engineExperimentApi.submit).toHaveBeenNthCalledWith(1, preparedAction()); expect(engineExperimentApi.submit).toHaveBeenNthCalledWith(2, preparedAction());
});
it("preserves an uncertain reference across closing and reopening, requiring fresh acknowledgment", async () => {
  vi.mocked(engineExperimentApi.submit).mockRejectedValueOnce(new Error("network interrupted")).mockResolvedValueOnce(acceptedAction());
  const view = render(<EngineActionReview {...props()} />); await ready();
  fireEvent.click(screen.getByRole("checkbox")); fireEvent.click(screen.getByRole("button", { name: "Start baseline exploration" }));
  await screen.findByText(/Acceptance is unconfirmed/);
  view.rerender(<EngineActionReview {...props()} open={false} />); view.rerender(<EngineActionReview {...props()} />);
  expect(screen.getByRole("checkbox")).not.toBeChecked();
  expect(screen.getByRole("button", { name: "Retry exact prepared request" })).toBeDisabled();
  fireEvent.click(screen.getByRole("checkbox")); fireEvent.click(screen.getByRole("button", { name: "Retry exact prepared request" }));
  await waitFor(() => expect(accepted).toHaveBeenCalled()); expect(engineExperimentApi.prepare).toHaveBeenCalledTimes(1);
});
it("treats an explicit stale refusal as final for this review", async () => {
  vi.mocked(engineExperimentApi.submit).mockRejectedValue(new ApiError("Review changed", "engine_action_stale", undefined, 409));
  render(<EngineActionReview {...props()} />); await ready(); fireEvent.click(screen.getByRole("checkbox")); fireEvent.click(screen.getByRole("button", { name: "Start baseline exploration" }));
  await screen.findByText("Review changed"); expect(screen.getByRole("button", { name: "Start baseline exploration" })).toBeDisabled();
});
