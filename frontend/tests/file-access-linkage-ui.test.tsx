import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { CompositionAttempts } from "../src/components/CompositionAttempts";
import { compositionApi, FILE_ACCESS_PACK } from "../src/lib/composition";
import { fileAccessLinkageApi } from "../src/lib/file-access-linkage";
import { linkageFixture } from "./file-access-linkage-fixture";

vi.mock("../src/lib/api", () => ({ DEMO_MODE: false, request: vi.fn(), ApiError: class extends Error {} }));

function mount(state: "established" | "unknown" = "established", selected: boolean | string = true) {
  const { objective, attempt } = linkageFixture(state);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const selectedId = typeof selected === "string" ? selected : selected ? attempt.request.composition_attempt.attempt_id : null;
  const path = `/composition?control=keep-control&objective=keep-objective&proposal=keep-proposal&pack=${FILE_ACCESS_PACK}${selectedId ? `&attempt=${selectedId}` : ""}`;
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}>
    <CompositionAttempts objective={objective} />
  </MemoryRouter></QueryClientProvider>);
  return { objective, attempt, client };
}

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it("loads only the selected saved comparison and keeps source record identities in links", async () => {
  const { objective, attempt, value } = linkageFixture();
  const read = vi.spyOn(fileAccessLinkageApi, "read").mockResolvedValue(value);
  const submit = vi.spyOn(compositionApi, "submit");
  mount();
  await screen.findByRole("region", { name: "Baseline and fresh retest" });
  expect(read).toHaveBeenCalledWith(objective.owner.job_id, attempt.request.composition_attempt.attempt_id);
  expect(await screen.findByRole("link", { name: /Baseline reads/ })).toHaveAttribute("href", `/file-access?control=${value.control_owner_id}&operation=${value.baseline.operation_job_id}`);
  expect(screen.getByRole("link", { name: /Reviewed change/ })).toHaveAttribute("href", `/file-access?control=${value.control_owner_id}&operation=${value.change.operation_job_id}`);
  expect(screen.getByRole("link", { name: /Retest run/ })).toHaveAttribute("href", "/runs/run-proof");
  expect(read).toHaveBeenCalledTimes(1);
  expect(submit).not.toHaveBeenCalled();
});

it("shows loading and transport errors without a successful comparison", async () => {
  const submit = vi.spyOn(compositionApi, "submit");
  let reject!: (error: Error) => void;
  vi.spyOn(fileAccessLinkageApi, "read").mockReturnValue(new Promise((_resolve, fail) => { reject = fail; }));
  mount();
  // The selected-attempt component immediately requests the saved projection.
  expect(await screen.findByText("Opening baseline and retest evidence")).toBeInTheDocument();
  expect(screen.queryByRole("heading", { name: "Non-owner access blocked; owner access preserved" })).not.toBeInTheDocument();
  reject(new Error("Saved projection unavailable"));
  expect(await screen.findByText("Saved comparison unavailable")).toBeInTheDocument();
  expect(screen.queryByRole("heading", { name: "Non-owner access blocked; owner access preserved" })).not.toBeInTheDocument();
  expect(submit).not.toHaveBeenCalled();
});

it("renders unknown saved evidence without promoting it to success", async () => {
  const { value } = linkageFixture("unknown");
  vi.spyOn(fileAccessLinkageApi, "read").mockResolvedValue(value);
  const submit = vi.spyOn(compositionApi, "submit");
  mount("unknown");
  expect(await screen.findByRole("heading", { name: "The retest has no verified conclusion yet" })).toBeInTheDocument();
  const comparison = screen.getByRole("region", { name: "Baseline and fresh retest" });
  expect(comparison).toHaveTextContent("Unknown");
  expect(comparison).toHaveTextContent("Not verified");
  expect(screen.queryByRole("heading", { name: "Non-owner access blocked; owner access preserved" })).not.toBeInTheDocument();
  expect(submit).not.toHaveBeenCalled();
});

it("does not link an unknown retest run that has not been finalized", async () => {
  const { value } = linkageFixture("unknown");
  vi.spyOn(fileAccessLinkageApi, "read").mockResolvedValue(value);
  mount("unknown");
  const comparison = await screen.findByRole("region", { name: "Baseline and fresh retest" });
  expect(comparison).toHaveTextContent("Retest run is not finalized.");
  expect(screen.queryByRole("link", { name: "Retest run" })).not.toBeInTheDocument();
});

it("preserves objective and proposal selection when opening a retest comparison", () => {
  const submit = vi.spyOn(compositionApi, "submit");
  const { objective, attempt } = mount("established", false);
  const link = screen.getByRole("link", { name: "Compare with the recorded baseline" });
  expect(link).toHaveAttribute("href", expect.stringContaining(`objective=${objective.owner.job_id}`));
  expect(link).toHaveAttribute("href", expect.stringContaining("proposal=keep-proposal"));
  expect(link).toHaveAttribute("href", expect.stringContaining(`attempt=${attempt.request.composition_attempt.attempt_id}`));
  expect(submit).not.toHaveBeenCalled();
});

it("shows an invalid selected-attempt notice without fetching a comparison", () => {
  const read = vi.spyOn(fileAccessLinkageApi, "read");
  const submit = vi.spyOn(compositionApi, "submit");
  mount("established", "attempt-ffffffffffffffffffffffffffffffff");
  expect(screen.getByText("This attempt is not part of the selected objective")).toBeInTheDocument();
  expect(read).not.toHaveBeenCalled();
  expect(submit).not.toHaveBeenCalled();
});
