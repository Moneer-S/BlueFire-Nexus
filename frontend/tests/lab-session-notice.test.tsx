import { act, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { LabSessionNotice } from "../src/components/LabSessionNotice";

const provider = (deadline?: number) => [{ provider_id: "owned", kind: "chat_completions", model: "fixture", health: { lab_session_expires_at_ms: deadline } }];
afterEach(() => vi.useRealTimers());

it("does not invent a session deadline for a direct or offline installation", () => {
  const view = render(<LabSessionNotice providers={provider()} />);
  expect(screen.queryByLabelText("Lab session time limit")).not.toBeInTheDocument();
  view.rerender(<LabSessionNotice providers={provider(Number.NaN)} />);
  expect(screen.queryByLabelText("Lab session time limit")).not.toBeInTheDocument();
});

it("warns and supplies restart guidance when the server deadline passes, even without another response", () => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2030-01-01T00:00:00Z"));
  render(<LabSessionNotice providers={provider(Date.now() + 180_000)} />);
  expect(screen.getByText("Lab session ends in about 3 minutes")).toBeInTheDocument();
  expect(screen.queryByRole("status")).not.toBeInTheDocument();
  act(() => vi.advanceTimersByTime(60_000));
  expect(screen.getByRole("status")).toHaveTextContent("Lab session ends in about 2 minutes");
  act(() => vi.advanceTimersByTime(120_000));
  expect(screen.getByRole("status")).toHaveTextContent("Lab session time limit reached");
  expect(screen.getByText(/Review saved jobs and any interrupted cleanup/)).toBeInTheDocument();
  expect(screen.getByText(/Work does not restart automatically/)).toBeInTheDocument();
});

it("uses fresh enrollment metadata without retaining the old expired countdown", () => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2030-01-01T00:00:00Z"));
  const view = render(<LabSessionNotice providers={provider(Date.now() - 1)} />);
  expect(screen.getByRole("status")).toHaveTextContent("time limit reached");
  view.rerender(<LabSessionNotice providers={provider(Date.now() + 900_000)} />);
  expect(screen.getByText("Lab session ends in about 15 minutes")).toBeInTheDocument();
  expect(screen.queryByRole("status")).not.toBeInTheDocument();
});
