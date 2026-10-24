import { BaseEdge, type EdgeProps } from "@xyflow/react";
import { useMemo } from "react";
import { routePath, type BuilderFlowEdge } from "../lib/graph-routes";

/** Conditions explain the connection; numbered identities remain in route inspection. */
export function BuilderRouteEdge({ id, source, target, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, data, selected, style, markerEnd, interactionWidth }: EdgeProps<BuilderFlowEdge>) {
  const payload = data?.artifactLabel?.length && data.artifactLabel.length > 22 ? `${data.artifactLabel.slice(0, 19)}...` : data?.artifactLabel;
  const outcome = data?.outcome ? { success: "On success", partial: "Partly complete", blocked: "When blocked", failed: "On failure" }[data.outcome] : "Connection";
  const shortOutcome = data?.outcome ? { success: "Success", partial: "Partial", blocked: "Blocked", failed: "Failed" }[data.outcome] : "Connection";
  const label = data?.kind === "artifact" ? payload : selected ? `R${data?.number ?? "?"} · ${shortOutcome}` : data?.outcome !== "success" ? shortOutcome : undefined;
  const labelWidth = Math.max(30, (label?.length ?? 0) * 6.5 + 14);
  const route = useMemo(() => routePath({ source: { x: sourceX, y: sourceY }, target: { x: targetX, y: targetY }, sourceId: source, targetId: target, sourceSide: sourcePosition, targetSide: targetPosition, obstacles: data?.obstacles, lane: data?.lane, labelWidth }), [source, target, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, data?.obstacles, data?.lane, labelWidth]);
  // Conditional ports are vertically separated. Keep their labels beside those
  // ports instead of stacking them on the return segment shared by a join.
  const sourceLabel = data?.kind === "route" && data.outcome !== "success" && sourcePosition === "right"
    ? { x: sourceX + 8 + labelWidth / 2, y: sourceY } : undefined;
  const sourceLabelClear = sourceLabel && !(data?.obstacles ?? []).some(rect => sourceLabel.x + labelWidth / 2 > rect.x - 4 && sourceLabel.x - labelWidth / 2 < rect.x + rect.width + 4 && sourceLabel.y + 10 > rect.y - 4 && sourceLabel.y - 10 < rect.y + rect.height + 4);
  const labelPosition = sourceLabelClear ? sourceLabel : route.payloadLabel;
  return <g data-route-obstructed={route.obstructed || undefined} data-route-kind={data?.kind} data-route-outcome={data?.outcome}>
    {data?.kind === "route" ? <title>{`Route ${data.number}: ${outcome}`}</title> : null}
    {data?.kind === "artifact" ? <title>{data.artifactLabel}: {data.artifactType ?? "Input dependency"}</title> : null}
    {route.obstructed ? <title>Saved positions overlap this connection. Auto-layout can separate the cards.</title> : null}
    <BaseEdge id={id} path={route.path}
    markerEnd={markerEnd} interactionWidth={interactionWidth}
    style={{ ...style, strokeWidth: selected ? 3.5 : data?.kind === "artifact" ? 1.5 : 2, strokeLinejoin: "round" }}
    label={labelPosition ? label : undefined} labelX={labelPosition?.x} labelY={labelPosition?.y}
    labelStyle={{ fill: "var(--text)", fontWeight: 600, fontSize: 10.5 }}
    labelBgStyle={{ fill: "var(--ink-900)", stroke: selected ? String(style?.stroke ?? "var(--line)") : "var(--line)" }} labelBgPadding={[6, 4]} labelBgBorderRadius={4} />
  </g>;
}
