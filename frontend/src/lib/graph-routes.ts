import type { Edge } from "@xyflow/react";
import type { Outcome } from "../types";

export type BuilderFlowEdge = Edge<{
  kind: "route" | "artifact";
  outcome?: Outcome;
  artifactType?: string;
  number?: number;
  lane?: number;
  sourceTitle?: string;
  targetTitle?: string;
}>;

/** Presentation only: distinct bends retain every route's original handles and identity. */
export function routeCurve(sourceX: number, sourceY: number, targetX: number, targetY: number, lane: number) {
  const bend = Math.max(42, Math.abs(targetY - sourceY) * .4) + 80 * lane / (lane + 4);
  return `M ${sourceX},${sourceY} C ${sourceX},${sourceY + bend} ${targetX},${targetY - bend} ${targetX},${targetY}`;
}
