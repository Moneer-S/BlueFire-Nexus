import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState, type ComponentProps } from "react";
import { expect, it, vi } from "vitest";
import { CanonicalPlanReview } from "../src/components/CanonicalPlanReview";

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
  if (part === "scope") expect(screen.getByText("replacement.workspace")).toBeVisible();
  if (part === "cleanup") expect(screen.getByText("Manual")).toBeVisible();
  if (part === "binding") expect(screen.getByText("profile-replacement")).toBeVisible();
  if (part === "envelope") {
    expect(screen.getByText("0 methods")).toBeVisible();
    expect(screen.queryByText("Original fixture method")).not.toBeInTheDocument();
  }
});
