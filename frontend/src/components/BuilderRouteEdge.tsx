import { BaseEdge, type EdgeProps } from "@xyflow/react";
import { useMemo } from "react";
import { routePath, type BuilderFlowEdge } from "../lib/graph-routes";

/** Short source-side numbers map to the complete, keyboard-readable Routes list. */
export function BuilderRouteEdge({ id, source, target, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, data, selected, style, markerEnd, interactionWidth }: EdgeProps<BuilderFlowEdge>) {
  const payload = data?.artifactLabel?.length && data.artifactLabel.length > 22 ? `${data.artifactLabel.slice(0, 19)}...` : data?.artifactLabel;
  const route = useMemo(() => routePath({ source: { x: sourceX, y: sourceY }, target: { x: targetX, y: targetY }, sourceId: source, targetId: target, sourceSide: sourcePosition, targetSide: targetPosition, obstacles: data?.obstacles, lane: data?.lane, labelWidth: Math.max(30, (payload?.length ?? 0) * 6.5 + 14) }), [source, target, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, data?.obstacles, data?.lane, payload]);
  const labelPosition = data?.kind === "artifact" ? route.payloadLabel : route.label;
  return <g data-route-obstructed={route.obstructed || undefined}>
    {data?.kind === "artifact" ? <title>{data.artifactLabel}: {data.artifactType ?? "Input dependency"}</title> : null}
    {route.obstructed ? <title>Saved positions overlap this connection. Auto-layout can separate the cards.</title> : null}
    <BaseEdge id={id} path={route.path}
    markerEnd={markerEnd} interactionWidth={interactionWidth}
    style={{ ...style, strokeWidth: selected ? 3.5 : data?.kind === "artifact" ? 1.5 : 2, strokeLinejoin: "round" }}
    label={data?.kind === "artifact" ? labelPosition ? payload : undefined : `R${data?.number ?? "?"}`} labelX={labelPosition?.x} labelY={labelPosition?.y}
    labelStyle={{ fill: "var(--text)", fontWeight: 700, fontSize: 10 }}
    labelBgStyle={{ fill: "var(--ink-900)", stroke: String(style?.stroke ?? "var(--line)") }} labelBgPadding={[5, 3]} labelBgBorderRadius={4} />
  </g>;
}
