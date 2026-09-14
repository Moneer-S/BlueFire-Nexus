import { BaseEdge, type EdgeProps } from "@xyflow/react";
import { routeCurve, type BuilderFlowEdge } from "../lib/graph-routes";

/** Short source-side numbers map to the complete, keyboard-readable Routes list. */
export function BuilderRouteEdge({ id, sourceX, sourceY, targetX, targetY, data, selected, style, markerEnd, interactionWidth }: EdgeProps<BuilderFlowEdge>) {
  return <BaseEdge id={id} path={routeCurve(sourceX, sourceY, targetX, targetY, data?.lane ?? 0)}
    markerEnd={markerEnd} interactionWidth={interactionWidth}
    style={{ ...style, strokeWidth: selected ? 3.5 : 2 }}
    label={`R${data?.number ?? "?"}`} labelX={sourceX} labelY={sourceY + 19}
    labelStyle={{ fill: "var(--text)", fontWeight: 700, fontSize: 10 }}
    labelBgStyle={{ fill: "var(--ink-900)", stroke: String(style?.stroke ?? "var(--line)") }} labelBgPadding={[5, 3]} labelBgBorderRadius={4} />;
}
