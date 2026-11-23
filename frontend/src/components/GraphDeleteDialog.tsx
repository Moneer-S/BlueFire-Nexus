import * as Dialog from "@radix-ui/react-dialog";
import { useRef } from "react";
import { displayTitle } from "../lib/display-title";
import { branchLabels } from "../lib/graph-view";
import type { BuilderFlowEdge } from "../lib/graph-routes";
import type { Behavior, Scenario } from "../types";
import type { GraphDeletionSummary } from "../state/useGraphDeletion";
import { Button } from "./Primitives";

export function graphStepName(scenario: Scenario, behaviors: Map<string, Behavior>, id: string) {
  const index = scenario.steps.findIndex(step => step.id === id);
  const title = (behavior: string) => displayTitle(behaviors.get(behavior)?.title ?? "Unavailable step");
  const name = title(scenario.steps[index]?.behavior_id ?? "");
  return scenario.steps.filter(step => title(step.behavior_id) === name).length > 1 ? `${name} (step ${index + 1})` : name;
}

export function graphDeletionSummary(scenario: Scenario, behaviors: Map<string, Behavior>, elements: { nodes: { id: string }[]; edges: BuilderFlowEdge[] }): GraphDeletionSummary {
  const name = (id: string) => graphStepName(scenario, behaviors, id);
  return {
    steps: elements.nodes.map(node => name(node.id)),
    connections: elements.edges.map(edge => edge.data?.kind === "route"
      ? `Route ${edge.data.number}: ${name(edge.source)} → ${name(edge.target)} · ${branchLabels[edge.data.outcome!]}`
      : `Input connection: ${name(edge.source)} → ${name(edge.target)}`),
  };
}

export function GraphDeleteDialog({ summary, confirm, cancel, restoreFocus }: {
  summary: GraphDeletionSummary | null;
  confirm: () => void;
  cancel: () => void;
  restoreFocus: () => void;
}) {
  const cancelButton = useRef<HTMLButtonElement>(null);
  return <Dialog.Root open={Boolean(summary)} onOpenChange={open => { if (!open) cancel(); }}>
    <Dialog.Portal>
      <Dialog.Overlay className="dialog-overlay builder-command-overlay" />
      <Dialog.Content className="dialog-content builder-command-dialog"
        onOpenAutoFocus={event => { event.preventDefault(); cancelButton.current?.focus(); }}
        onCloseAutoFocus={event => { event.preventDefault(); restoreFocus(); }}
        onEscapeKeyDown={event => event.stopPropagation()}>
        <Dialog.Title>Delete from experiment?</Dialog.Title>
        <Dialog.Description>{summary?.steps.length ? "Connections to the deleted steps will also be removed." : "Only these connections will be removed. The steps will remain."} You can undo this change.</Dialog.Description>
        {summary?.steps.length ? <><h3>Steps</h3><ul>{summary.steps.map((name, index) => <li key={index}>{name}</li>)}</ul></> : null}
        {summary?.connections.length ? <><h3>Connections</h3><ul>{summary.connections.map((name, index) => <li key={index}>{name}</li>)}</ul></> : null}
        <div className="dialog-actions">
          <button ref={cancelButton} className="button button-secondary button-medium" onClick={cancel}>Cancel</button>
          <Button variant="danger" onClick={confirm}>Delete</Button>
        </div>
      </Dialog.Content>
    </Dialog.Portal>
  </Dialog.Root>;
}
