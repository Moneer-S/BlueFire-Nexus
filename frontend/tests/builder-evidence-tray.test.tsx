import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ComponentProps } from "react";
import { MemoryRouter } from "react-router-dom";
import { expect, it } from "vitest";
import { BuilderEvidenceTray } from "../src/components/BuilderEvidenceTray";
import { demoBehaviors } from "../src/lib/demo";
import type { Behavior, ScenarioStep } from "../src/types";

const behavior: Behavior = {
  ...structuredClone(demoBehaviors[0]!), id: "test.collection.v1", title: "Collect reviewed records",
  outputs: [
    { name: "reviewed_records", type: "artifact.reviewed.records.v1", description: "The records selected by this method.", multiple: true },
    { name: "collection_receipt", type: "receipt.collection.v1", description: "The declared collection receipt." },
  ],
  telemetry: ["file.create", "file.read"],
  detection_hints: ["Correlate collection writes with the selected source."],
  limitations: ["A declared output does not establish independent observation."],
};
const step: ScenarioStep = { id: "collect_selected", behavior_id: behavior.id, parameters: {}, inputs: {}, alternates: [] };
type TrayProps = ComponentProps<typeof BuilderEvidenceTray>;

function Fixture({ tray }: { tray: TrayProps }) {
  return <MemoryRouter><div className="workbench-builder">
    <BuilderEvidenceTray {...tray} />
    <aside aria-label="Method inspector"><h2>Method</h2><input aria-label="Method parameter" defaultValue="Existing parameter" /></aside>
  </div></MemoryRouter>;
}

function mount(tray: TrayProps = { step, ordinal: 8, behavior }) {
  const view = render(<Fixture tray={tray} />);
  return { ...view, update: (next: TrayProps) => view.rerender(<Fixture tray={next} />) };
}

it("selects expected evidence with the keyboard and moves Tab into the labelled detail panel", async () => {
  const user = userEvent.setup();
  mount();
  await user.click(screen.getByRole("button", { name: /^Step evidence/ }));
  const list = screen.getByRole("tablist", { name: "Expected step evidence" });
  const first = within(list).getByRole("tab", { name: /^Reviewed records/ });
  const second = within(list).getByRole("tab", { name: /^Collection receipt/ });
  expect(first).toHaveAttribute("aria-selected", "true");
  expect(screen.getByRole("tabpanel")).toHaveTextContent(behavior.outputs[0]!.description!);

  first.focus();
  await user.keyboard("{ArrowDown}");
  expect(second).toHaveFocus();
  expect(second).toHaveAttribute("aria-selected", "true");
  expect(first).toHaveAttribute("tabindex", "-1");
  const panel = screen.getByRole("tabpanel");
  expect(panel).toHaveAttribute("aria-labelledby", second.id);
  expect(second).toHaveAttribute("aria-controls", panel.id);
  expect(panel).toHaveTextContent(behavior.outputs[1]!.description!);
  expect(panel).not.toHaveTextContent(behavior.outputs[0]!.description!);
  await user.tab();
  expect(panel).toHaveFocus();

  second.focus();
  await user.keyboard("{ArrowDown}");
  expect(within(list).getByRole("tab", { name: "Expected observations" })).toHaveFocus();
  expect(panel).toHaveTextContent("File create");
  expect(panel).toHaveTextContent(behavior.detection_hints[0]!);
  await user.keyboard("{End}");
  expect(within(list).getByRole("tab", { name: "Method limitations" })).toHaveFocus();
  expect(panel).toHaveTextContent(behavior.limitations[0]!);
  await user.keyboard("{Home}");
  expect(first).toHaveFocus();
  expect(first).toHaveAttribute("aria-selected", "true");
  await user.keyboard("{ArrowUp}");
  expect(within(list).getByRole("tab", { name: "Method limitations" })).toHaveFocus();
});

it("resets the evidence selection for another step and for a replacement method", async () => {
  const user = userEvent.setup();
  const view = mount();
  await user.click(screen.getByRole("button", { name: /^Step evidence/ }));
  await user.click(screen.getByRole("tab", { name: /^Collection receipt/ }));
  const nextStep = { ...step, id: "collect_other" };
  view.update({ step: nextStep, ordinal: 9, behavior });
  expect(screen.getByRole("button", { name: /^Step evidence/ })).toHaveAttribute("aria-expanded", "true");
  expect(screen.getByRole("button", { name: /^Step evidence/ })).toHaveTextContent("Step 9");
  expect(screen.getByRole("tab", { name: /^Reviewed records/ })).toHaveAttribute("aria-selected", "true");
  expect(screen.getByRole("tabpanel")).toHaveTextContent(behavior.outputs[0]!.description!);

  await user.click(screen.getByRole("tab", { name: /^Collection receipt/ }));
  const replacement: Behavior = { ...behavior, id: "test.metadata.v1", title: "Inspect reviewed metadata",
    outputs: [{ name: "file_metadata", type: "artifact.file.metadata.v1", description: "Metadata declared by the replacement method." }] };
  view.update({ step: { ...nextStep, behavior_id: replacement.id }, ordinal: 9, behavior: replacement });
  expect(screen.getByRole("button", { name: /^Step evidence/ })).toHaveTextContent(replacement.title);
  expect(screen.queryByRole("tab", { name: /^Collection receipt/ })).not.toBeInTheDocument();
  expect(screen.getByRole("tab", { name: /^File metadata/ })).toHaveAttribute("aria-selected", "true");
  expect(screen.getByRole("tabpanel")).toHaveTextContent(replacement.outputs[0]!.description!);
});

it("starts collapsed and retains the Method inspector and its edits when opened and closed", async () => {
  const user = userEvent.setup();
  mount();
  const toggle = screen.getByRole("button", { name: /^Step evidence/ });
  const inspector = screen.getByRole("complementary", { name: "Method inspector" });
  const parameter = within(inspector).getByRole("textbox", { name: "Method parameter" });
  expect(toggle).toHaveAttribute("aria-expanded", "false");
  expect(screen.queryByRole("tablist")).not.toBeInTheDocument();
  await user.clear(parameter);
  await user.type(parameter, "Keep my method edit");
  await user.click(toggle);
  expect(screen.getByRole("tablist")).toBeVisible();
  expect(inspector).toBeVisible();
  await user.click(toggle);
  expect(toggle).toHaveAttribute("aria-expanded", "false");
  expect(toggle).toHaveFocus();
  expect(screen.queryByRole("tabpanel")).not.toBeInTheDocument();
  expect(inspector).toBeVisible();
  expect(parameter).toHaveValue("Keep my method edit");
});

it("explains empty and unavailable selections while linking to ordinary run history", async () => {
  const user = userEvent.setup();
  const view = mount({});
  await user.click(screen.getByRole("button", { name: /^Step evidence/ }));
  expect(screen.getByText("Select a step to inspect its evidence")).toBeVisible();
  expect(screen.queryByRole("tablist")).not.toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Open run results" })).toHaveAttribute("href", "/runs");
  view.update({ step, ordinal: 8 });
  expect(screen.getByText("This method is unavailable")).toBeVisible();
  expect(screen.getByText(/Choose an available method in step details/)).toBeVisible();
  expect(screen.queryByRole("tabpanel")).not.toBeInTheDocument();
});

it("keeps observation and limitation guidance useful when a method declares no evidence", async () => {
  const user = userEvent.setup();
  const empty: Behavior = { ...behavior, outputs: [], telemetry: [], detection_hints: [], limitations: [] };
  mount({ step, ordinal: 8, behavior: empty });
  await user.click(screen.getByRole("button", { name: /^Step evidence/ }));
  expect(screen.getByText("No output artifacts declared.")).toBeVisible();
  expect(screen.getAllByRole("tab")).toHaveLength(2);
  expect(screen.getByRole("tab", { name: "Expected observations" })).toHaveAttribute("aria-selected", "true");
  expect(screen.getByRole("tabpanel")).toHaveTextContent("This method declares no observation types.");
  expect(screen.getByRole("tabpanel")).toHaveTextContent("No detection guidance is declared.");
  await user.click(screen.getByRole("tab", { name: "Method limitations" }));
  expect(screen.getByRole("tabpanel")).toHaveTextContent("No method-specific evidence limitations are declared.");
});
