import { useQuery } from "@tanstack/react-query";
import { ArrowRight, RefreshCw, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";
import { activeWorkHref, loadActiveWork, type ActiveWorkReference } from "../lib/active-defensive-work";
import { displayTitle } from "../lib/display-title";
import { rememberActiveDefensiveWork } from "../state/activeDefensiveWork";
import { Button, ErrorState, LoadingState, sentence } from "./Primitives";
import "./ActiveWorkResume.css";

export function ActiveWorkResume({ reference }: { reference: ActiveWorkReference }) {
  const work = useQuery({ queryKey: ["active-defensive-work", reference.family, reference.id], queryFn: () => loadActiveWork(reference), retry: false, staleTime: 0, refetchOnMount: "always" });
  const value = work.data;
  return <section className="active-work active-objective" aria-labelledby="active-objective-heading">
    <div className="active-work-content">
      <div className="active-work-heading"><span className="active-work-symbol"><ShieldCheck aria-hidden="true" /></span><div><h2 id="active-objective-heading">Active objective</h2><h3>{value ? displayTitle(value.title) : "Saved defensive work"}</h3></div></div>
      {work.isPending ? <LoadingState label="Opening saved work" /> : work.isError ? <ErrorState title="Saved work could not be checked" error={work.error} retry={() => { void work.refetch(); }} /> : null}
      {value ? <>
        <p className="active-work-purpose">{value.objective}</p>
        {work.isError ? <p className="workspace-note">Previously loaded evidence. Its current state could not be checked.</p> : null}
        {work.isFetching ? <p className="workspace-note" role="status">Checking the current saved state…</p> : null}
        <dl className="active-objective-context"><div><dt>Environment</dt><dd>{value.environment}</dd></div><div><dt>Current stage</dt><dd>{value.phase}</dd></div></dl>
        <div className="active-objective-change"><span>Defensive change</span><p>{value.change}</p></div>
      </> : null}
      <div className="active-work-actions"><Link className="button button-primary" to={value?.href ?? activeWorkHref(reference)}>Continue objective<ArrowRight aria-hidden="true" /></Link><Button variant="secondary" onClick={() => rememberActiveDefensiveWork(undefined)}>Show working draft</Button></div>
      {value ? <div className="active-objective-state"><span>Recorded state: {sentence(value.recordedState)}</span><Button variant="ghost" size="small" aria-label="Refresh active objective" disabled={work.isFetching} onClick={() => { void work.refetch(); }}><RefreshCw aria-hidden="true" />Refresh</Button></div> : null}
    </div>
    <div className="active-work-plan active-objective-evidence"><header><h3>Current evidence</h3></header>
      {value ? <><dl>{value.results.map((result, index) => <div key={`${result.label}-${index}`}><dt>{result.label}</dt><dd data-tone={result.tone}>{result.value}</dd></div>)}</dl>{value.links.length ? <nav aria-label="Objective records">{value.links.map(link => <Link key={`${link.href}-${link.label}`} to={link.href}>{link.label}<ArrowRight aria-hidden="true" /></Link>)}</nav> : null}</> : <p>Evidence will appear after the saved record is loaded.</p>}
    </div>
  </section>;
}
