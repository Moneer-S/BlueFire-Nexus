import { ReactFlowProvider } from "@xyflow/react";
import type { Scenario } from "../types";
import type { CompositionContext } from "../lib/composition";
import { GraphWorkspace } from "../pages/Builder";

export function CompositionGraph({ scenario, snapshot }: { scenario: Scenario; snapshot: CompositionContext["snapshot"] }) {
  return <div className="composition-graph"><ReactFlowProvider><GraphWorkspace
    behaviors={snapshot.methods.map(method => method.behavior)} actions={snapshot.methods.map(method => method.action)}
    review={{ scenario, setScenario: () => {}, dirty: false, readOnly: true, validated: true, statusLabel: "Compiler-validated projection", controls: null, details: null }}
  /></ReactFlowProvider></div>;
}
