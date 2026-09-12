import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState, type ComponentProps } from "react";
import { expect, it, vi } from "vitest";
import { CanonicalPlanReview } from "../src/components/CanonicalPlanReview";
import { demoCatalog } from "../src/lib/demo";

const reviewRenders = vi.hoisted(() => [] as number[]);
vi.mock("../src/components/Primitives", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/components/Primitives")>();
  return { ...actual, DataList: (props: ComponentProps<typeof actual.DataList>) => {
    reviewRenders.push(props.items.length);
    return <actual.DataList {...props} />;
  } };
});

type Review = ComponentProps<typeof CanonicalPlanReview>;
const initial: Review = {
  plan: { mode: "execute", steps: [{ step_id: "original_step", behavior_id: "fixture.v1", parameters: {}, inputs: {} }], edges: [] },
  cleanup: { policy: "always" },
  scope: { scope_refs: ["owned.workspace"] },
  binding: { state_digest: "state-original", plan_digest: "plan-original", target_scope_digest: "scope-original", profile_id: "profile-original", maximum_tier: "controlled" },
  envelope: { schema_version: "bluefire.approval-envelope.v1", scenario_id: "owned-experiment", envelope_digest: "envelope-original", steps: [{ step_id: "original_step", options: [{ behavior_id: "fixture.v1", is_primary: true, contract_digest: "behavior-original", contract: { title: "Original fixture method" }, resolved_parameters: {}, actions: [] }] }] },
};

function TypingParent() {
  const [identity, setIdentity] = useState("");
  return <><label>Operator label<input value={identity} onChange={(event) => setIdentity(event.target.value)} /></label><output aria-label="Current operator label">{identity}</output><CanonicalPlanReview {...initial} /></>;
}

it("keeps the actual plan display unchanged while its parent handles every typed character", async () => {
  const user = userEvent.setup();
  render(<TypingParent />);
  expect(screen.getAllByText("Original fixture method")[0]).toBeVisible();
  expect(reviewRenders.length).toBeGreaterThan(0);
  reviewRenders.length = 0;
  let typed = "";
  for (const character of "operator-a") {
    typed += character;
    await user.type(screen.getByRole("textbox", { name: "Operator label" }), character);
    expect(screen.getByLabelText("Current operator label")).toHaveTextContent(typed);
    expect(reviewRenders).toEqual([]);
  }
});

it.each(["plan", "scope", "cleanup", "binding", "envelope"] as const)("renders a changed %s instead of retaining the previous review", (part) => {
  const view = render(<CanonicalPlanReview {...initial} />);
  reviewRenders.length = 0;
  const next = { ...initial };
  if (part === "plan") next.plan = { ...initial.plan, steps: [{ step_id: "replacement_step", parameters: {}, inputs: {} }] };
  if (part === "scope") next.scope = { scope_refs: ["replacement.workspace"] };
  if (part === "cleanup") next.cleanup = { policy: "manual" };
  if (part === "binding") next.binding = { ...initial.binding!, profile_id: "profile-replacement", state_digest: "state-replacement" };
  if (part === "envelope") next.envelope = { ...initial.envelope!, envelope_digest: "envelope-replacement", steps: [] };
  view.rerender(<CanonicalPlanReview {...next} />);
  expect(reviewRenders.length).toBeGreaterThan(0);
  if (part === "plan") expect(screen.getByText("Replacement step")).toBeVisible();
  if (part === "scope") expect(screen.getByText("Replacement workspace")).toBeVisible();
  if (part === "cleanup") expect(screen.getByText("Manual")).toBeVisible();
  if (part === "binding") expect(screen.getByText("Profile replacement")).toBeVisible();
  if (part === "envelope") {
    expect(screen.getByText("0 methods")).toBeVisible();
    expect(screen.queryByText("Original fixture method")).not.toBeInTheDocument();
  }
});

it.each(["simulate", "execute"] as const)("names the bound runner profile without inventing an environment for %s", (mode) => {
  render(<CanonicalPlanReview {...initial} plan={{ ...initial.plan, mode, runner_profile_id: "plan-profile" }} />);
  const term = screen.getByText("Environment profile", { selector: "dt" });
  expect(term.nextElementSibling).toHaveTextContent("Profile original");
  expect(screen.queryByText("Environment", { selector: "dt" })).not.toBeInTheDocument();
});

it("uses the recorded plan profile when Simulate has no Execute binding", () => {
  render(<CanonicalPlanReview plan={{ mode: "simulate", runner_profile_id: "sandbox-simulate.v1", steps: [], edges: [] }} cleanup={{ policy: "always" }} />);
  const term = screen.getByText("Environment profile", { selector: "dt" });
  expect(term.nextElementSibling).toHaveTextContent("Local simulation");
  expect(screen.getByText("Simulated cleanup; no external files are removed. Policy: Always.")).toBeVisible();
  expect(screen.queryByText("Remove created lab files after the run")).not.toBeInTheDocument();
});

it("updates cleanup wording with the exact mode while retaining its policy and full plan", async () => {
  const plan = { mode: "simulate", runner_profile_id: "sandbox-simulate.v1", steps: [], edges: [] };
  const view = render(<CanonicalPlanReview plan={plan} cleanup={{ policy: "manual" }} />);
  expect(screen.getByText("Simulated cleanup; no external files are removed. Policy: Manual.")).toBeVisible();
  await userEvent.setup().click(screen.getByText("Run identities and full plan"));
  const recordedPlan = screen.getByText("Run identities and full plan").closest("details")!.querySelector("pre")!;
  expect(recordedPlan).toBeVisible();
  expect(recordedPlan.textContent).toBe(JSON.stringify(plan, null, 2));
  view.rerender(<CanonicalPlanReview plan={{ ...plan, mode: "execute" }} cleanup={{ policy: "always" }} />);
  expect(screen.getByText("Remove created lab files after the run")).toBeVisible();
  expect(screen.queryByText(/no external files are removed/)).not.toBeInTheDocument();
  view.rerender(<CanonicalPlanReview plan={{ steps: [], edges: [] }} />);
  expect(screen.queryByText(/no external files are removed/)).not.toBeInTheDocument();
});

it("names simulated methods and settings while retaining exact reviewed values", async () => {
  const behavior = { ...demoCatalog.behaviors[0]!, id: "sandbox.collection.atomic-gzip.v1", title: "Compress selected records — Atomic gzip" };
  const plan = { mode: "simulate", steps: [{ step_id: "stage_collection", behavior_id: behavior.id, parameters: { stage_variant: "heldout", redact_values: false }, inputs: {} }], edges: [] };
  render(<CanonicalPlanReview plan={plan} catalog={{ ...demoCatalog, behaviors: [behavior] }} />);
  expect(screen.getByText(behavior.title)).toBeVisible();
  expect(screen.getByText("Alternate staging folder")).toBeVisible();
  expect(screen.getByText("No")).toBeVisible();
  await userEvent.setup().click(screen.getByText("Step details"));
  expect(screen.getByText("stage_collection", { selector: "code" })).toBeVisible();
  const recordedParameters = screen.getByText("Parameters", { selector: "dt" }).nextElementSibling!.querySelector("pre")!;
  expect(recordedParameters).toBeVisible();
  expect(recordedParameters.textContent).toBe(JSON.stringify(plan.steps[0]!.parameters, null, 2));
});
