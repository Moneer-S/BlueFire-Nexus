import { useQuery } from "@tanstack/react-query";
import { ArrowRight, Cloud, FileLock2, Network, RefreshCw, Send } from "lucide-react";
import { useRef } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { DEMO_MODE } from "../lib/api";
import { displayTitle } from "../lib/display-title";
import { loadSavedWork, workFamilies, type WorkFamily } from "../lib/saved-defensive-work";
import { Badge, Button, ErrorState, LoadingState, sentence } from "./Primitives";
import "./SavedDefensiveWork.css";

const icons = { handoff: Send, file: FileLock2, domain: Network, cloud: Cloud };

export function SavedDefensiveWork() {
  const [params, setParams] = useSearchParams();
  const selected = workFamilies.find(item => item.id === params.get("work")) ?? workFamilies[0];
  const tabs = useRef<Array<HTMLButtonElement | null>>([]);
  const history = useQuery({ queryKey: ["overview-saved-work", selected.id], queryFn: () => loadSavedWork(selected.id), retry: false, enabled: !DEMO_MODE });
  const select = (family: WorkFamily) => setParams(previous => { const next = new URLSearchParams(previous); next.set("work", family); return next; }, { replace: true });
  return <section className="work-section saved-defensive-work" aria-labelledby="saved-defensive-heading">
    <header className="work-section-heading"><h2 id="saved-defensive-heading">Saved defensive work</h2><Button variant="ghost" size="small" aria-label={`Refresh ${selected.label.toLowerCase()} history`} disabled={DEMO_MODE || history.isFetching} onClick={() => { void history.refetch(); }}><RefreshCw aria-hidden="true" />Refresh</Button></header>
    <div className="saved-work-tabs" role="tablist" aria-label="Defensive workflows">{workFamilies.map((family, index) => {
      const Icon = icons[family.id];
      return <button key={family.id} ref={element => { tabs.current[index] = element; }} id={`saved-work-${family.id}`} role="tab" aria-selected={selected.id === family.id} aria-controls={`saved-work-panel-${family.id}`} tabIndex={selected.id === family.id ? 0 : -1} onClick={() => select(family.id)} onKeyDown={event => {
        const next = event.key === "Home" ? 0 : event.key === "End" ? workFamilies.length - 1 : event.key === "ArrowRight" ? (index + 1) % workFamilies.length : event.key === "ArrowLeft" ? (index + workFamilies.length - 1) % workFamilies.length : null;
        if (next !== null) {
          const target = workFamilies[next];
          if (target) { event.preventDefault(); select(target.id); tabs.current[next]?.focus(); }
        }
      }}><Icon aria-hidden="true" />{family.label}</button>;
    })}</div>
    <div role="tabpanel" id={`saved-work-panel-${selected.id}`} aria-labelledby={`saved-work-${selected.id}`}>
      {DEMO_MODE ? <p className="workspace-note">Saved defensive work is available in the installed workspace.</p> : <>
        {history.isError ? <><ErrorState title={`${selected.label} history unavailable`} error={history.error} retry={() => { void history.refetch(); }} />{history.data ? <p className="workspace-note">Previously loaded records. Their current state could not be checked.</p> : null}</> : null}
        {history.isPending ? <LoadingState label={`Loading ${selected.label.toLowerCase()} history`} /> : history.data?.rows.length ? <ul className="saved-work-list">{history.data.rows.map(row => <li key={row.id}>
          <Link to={row.href}><span><strong>{displayTitle(row.title)}</strong><small>{row.detail}</small></span><ArrowRight aria-hidden="true" /></Link>
          <span className="saved-work-state"><span>Recorded state</span><Badge tone={row.attention ? "warning" : "neutral"}>{sentence(row.state)}</Badge></span>
        </li>)}</ul> : history.isSuccess && !history.data.more ? <p className="workspace-note">No saved {selected.label.toLowerCase()} work.</p> : null}
        {history.data?.more ? <p className="workspace-note">More saved records are available in this workflow.</p> : null}
      </>}
      <Link className="saved-work-open" to={selected.href}>Open {selected.label.toLowerCase()} workspace <ArrowRight aria-hidden="true" /></Link>
    </div>
  </section>;
}
