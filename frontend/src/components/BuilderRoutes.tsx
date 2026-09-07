import { X } from "lucide-react";
import { branchLabels } from "../lib/graph-view";
import type { BuilderFlowEdge } from "../lib/graph-routes";
import { Button, IconButton } from "./Primitives";

export function BuilderRoutes({ routes, total, selected, readOnly, select, inspect, remove, close }: {
  routes: BuilderFlowEdge[]; total: number; selected?: BuilderFlowEdge; readOnly: boolean;
  select: (id: string) => void; inspect: (source: string) => void; remove: (id: string) => void; close: () => void;
}) {
  return <aside className="builder-routes" aria-label="Route inspection">
    <header><div><h2>Routes</h2><p>{routes.length} of {total} shown · numbers match the canvas</p></div><IconButton label="Close route list" onClick={close}><X/></IconButton></header>
    <p className="route-help">Select a route to follow its path. Use ↑ and ↓ to compare routes.</p>
    <ol aria-label="Visible routes">{routes.map((edge) => <li key={edge.id}><button type="button" data-route={edge.id} aria-pressed={selected?.id === edge.id}
      onFocus={() => select(edge.id)} onClick={() => select(edge.id)} onKeyDown={(event) => {
        const buttons = Array.from(event.currentTarget.closest("ol")!.querySelectorAll<HTMLButtonElement>("button[data-route]"));
        const index = buttons.indexOf(event.currentTarget);
        const next = event.key === "ArrowDown" ? Math.min(index + 1, buttons.length - 1) : event.key === "ArrowUp" ? Math.max(0, index - 1) : event.key === "Home" ? 0 : event.key === "End" ? buttons.length - 1 : undefined;
        if (next !== undefined) { event.preventDefault(); event.stopPropagation(); buttons[next]?.focus(); }
        if (event.key === "Delete" && !readOnly) { event.preventDefault(); event.stopPropagation(); remove(edge.id); }
      }}><span className="route-number">R{edge.data?.number}</span><span><strong>{edge.data?.sourceTitle}</strong><span>{branchLabels[edge.data!.outcome!]} → {edge.data?.targetTitle}</span><small>{edge.source} → {edge.target}</small></span></button></li>)}</ol>
    <footer>{selected ? <><p role="status"><strong>R{selected.data?.number} · {branchLabels[selected.data!.outcome!]}</strong><span>{selected.data?.sourceTitle} → {selected.data?.targetTitle}</span></p><Button size="small" variant="secondary" onClick={() => inspect(selected.source)}>Inspect source step</Button><Button size="small" variant="ghost" disabled={readOnly} onClick={() => remove(selected.id)}>Delete route</Button>{readOnly ? <small>This view is read-only.</small> : <small>Change this branch in the source step's details. Deletion requires confirmation and can be undone.</small>}</> : <p>Select a numbered route on the canvas or in this list.</p>}</footer>
  </aside>;
}
