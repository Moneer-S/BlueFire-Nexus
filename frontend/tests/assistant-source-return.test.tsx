import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { ExperimentAssistant } from "../src/components/ExperimentAssistant";
import { api } from "../src/lib/api";
import { auditReviewSourceHref } from "../src/lib/audit-assistance";
import { detectionCreationSelectionPath } from "../src/lib/detection-creation";
import { receiverScenarioSetupPath } from "../src/lib/receiver-navigation";
import { AssistanceProvider, type WorkspaceSelection } from "../src/state/AssistanceContext";
import { ProductProvider } from "../src/state/ProductContext";
import { receiverAssistantFixture } from "./receiver-assistance-fixture";

const digest = `sha256:${"a".repeat(64)}`;
const creation = { kind: "run_detection" as const, run_id: `run-20300101T000000Z-${"1".repeat(16)}`,
  source_binding_digest: digest, behavior_id: "discovery.process.v1", target_language: "sigma" as const, case_role: "benign" as const };
const receiver = receiverAssistantFixture().request.selection;
const existingReceiver = receiverAssistantFixture(true).request.selection;
const audit = { kind: "s3_audit_review" as const, workflow_job_id: `job-${"2".repeat(32)}`,
  review_id: `job-${"3".repeat(32)}`, review_digest: digest };

function Location() {
  const location = useLocation();
  return <output data-testid="source-location">{location.pathname}{location.search}</output>;
}

it.each<{ name: string; selection: WorkspaceSelection; href: string }>([
  { name: "detection behavior and evaluation choices", selection: { kind: "run_detection", selected: creation, title: "Process observations", manualEdits: false }, href: detectionCreationSelectionPath(creation) },
  { name: "receiver scenario and run intent", selection: { kind: "receiver", selected: receiver, title: "Receiver redaction", manualEdits: false }, href: receiverScenarioSetupPath(receiver)! },
  { name: "existing receiver owner", selection: { kind: "receiver", selected: existingReceiver, title: "Receiver results", manualEdits: false }, href: `/compare?receiver_job=${existingReceiver.kind === "receiver_test" ? existingReceiver.receiver_job_id : ""}` },
  { name: "exact audit review", selection: { kind: "audit", selected: audit, title: "Object access review", manualEdits: false }, href: auditReviewSourceHref(audit) },
])("reopens captured $name without submitting or changing the draft", async ({ selection, href }) => {
  sessionStorage.setItem("bluefire.assistance.selection.v1", JSON.stringify(selection));
  sessionStorage.setItem("bluefire.assistance.draft.v1", "Explain this saved selection.");
  const submit = vi.spyOn(api, "submitAssistance");
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={["/overview"]}><ProductProvider><AssistanceProvider>
    <Location /><ExperimentAssistant providers={[]} />
  </AssistanceProvider></ProductProvider></MemoryRouter></QueryClientProvider>);
  await userEvent.setup().click(screen.getByRole("button", { name: /^Assistant/ }));
  expect(screen.getByRole("region", { name: "Previous selection" })).toHaveTextContent(selection.title);
  const reopen = screen.getByRole("link", { name: "Reopen source" });
  expect(reopen).toHaveAttribute("href", href);
  expect(screen.getByRole("button", { name: "Start work" })).toBeDisabled();
  await userEvent.setup().click(reopen);
  expect(screen.getByTestId("source-location").textContent).toBe(href);
  expect(screen.getByLabelText("What would you like to do?")).toHaveValue("Explain this saved selection.");
  expect(submit).not.toHaveBeenCalled();
  expect(JSON.parse(sessionStorage.getItem("bluefire.assistance.selection.v1")!)).toEqual(selection);
});

it("does not substitute a different setup for a captured receiver intent that cannot round-trip", async () => {
  if (receiver.kind !== "receiver_scenario") throw new Error("Expected a receiver scenario fixture");
  const intent = { ...receiver.run_intent };
  delete intent.collectors;
  const selection: WorkspaceSelection = { kind: "receiver", selected: { ...receiver, run_intent: intent }, title: "Earlier receiver setup", manualEdits: false };
  sessionStorage.setItem("bluefire.assistance.selection.v1", JSON.stringify(selection));
  const submit = vi.spyOn(api, "submitAssistance");
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter><ProductProvider><AssistanceProvider>
    <ExperimentAssistant providers={[]} />
  </AssistanceProvider></ProductProvider></MemoryRouter></QueryClientProvider>);
  await userEvent.setup().click(screen.getByRole("button", { name: /^Assistant/ }));
  expect(screen.queryByRole("link", { name: "Reopen source" })).not.toBeInTheDocument();
  expect(screen.getByText("This exact setup cannot be reopened. Your captured context and draft are preserved.")).toBeVisible();
  expect(screen.getByRole("button", { name: "Start work" })).toBeDisabled();
  expect(submit).not.toHaveBeenCalled();
  expect(JSON.parse(sessionStorage.getItem("bluefire.assistance.selection.v1")!)).toEqual(selection);
});
