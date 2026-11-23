import * as Dialog from "@radix-ui/react-dialog";
import { useQuery } from "@tanstack/react-query";
import { ArrowUpRight, Search, X } from "lucide-react";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { displayTitle } from "../lib/display-title";
import { runLabel } from "../lib/runPresentation";
import type { Scenario } from "../types";

export function WorkspaceSearch({ destinations, scenarios, current }: {
  destinations: Array<{ to: string; label: string }>;
  scenarios: Scenario[];
  current: string;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const runs = useQuery({ queryKey: ["runs"], queryFn: api.runs, enabled: open, staleTime: 15_000 });
  useEffect(() => {
    const handleKey = (event: KeyboardEvent) => {
      if (event.defaultPrevented || (!open && (current === "Build" || document.querySelector(".workbench-builder, [role='dialog']")))) return;
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault(); event.stopPropagation(); setOpen(value => !value);
      }
    };
    document.addEventListener("keydown", handleKey);
    return () => document.removeEventListener("keydown", handleKey);
  }, [current, open]);
  const term = query.trim().toLocaleLowerCase();
  const groups = [
    { title: "Workspace", items: destinations.map(item => ({ title: item.label, detail: "Workspace", href: item.to })) },
    { title: "Experiments", items: scenarios.map(item => ({ title: displayTitle(item.title), detail: `${item.steps.length} steps`, href: `/scenarios?selected=${encodeURIComponent(item.id)}` })) },
    { title: "Runs", items: (runs.data?.runs ?? []).map(item => ({ title: runLabel(item), detail: item.mode === "simulate" ? "Simulation" : "Execution", href: `/runs/${encodeURIComponent(item.run_id)}` })) },
  ].map(group => ({ ...group, items: group.items.filter(item => `${item.title} ${item.detail}`.toLocaleLowerCase().includes(term)).slice(0, 8) }));
  return <Dialog.Root open={open} onOpenChange={setOpen}>
    <Dialog.Trigger className="workspace-search-trigger" aria-label="Search experiments, runs, and tools"><Search aria-hidden="true"/><span>Search experiments, runs, and tools</span><span className="workspace-search-location">{current}</span></Dialog.Trigger>
    <Dialog.Portal><Dialog.Overlay className="dialog-overlay"/><Dialog.Content className="dialog-content workspace-search-dialog">
      <Dialog.Title className="sr-only">Search workspace</Dialog.Title>
      <Dialog.Description className="sr-only">Find saved experiments, recorded runs, and workspace tools.</Dialog.Description>
      <div className="workspace-search-input"><Search aria-hidden="true"/><input autoFocus aria-label="Search experiments, runs, and tools" value={query} onChange={event => setQuery(event.target.value)} placeholder="Search experiments, runs, and tools"/><Dialog.Close className="icon-button" aria-label="Close search"><X aria-hidden="true"/></Dialog.Close></div>
      <div className="workspace-search-results">
        {groups.map(group => group.items.length ? <section key={group.title} aria-label={group.title}><h2>{group.title}</h2><ul>{group.items.map(item => <li key={item.href}><Link to={item.href} onClick={() => setOpen(false)}><span><strong>{item.title}</strong><small>{item.detail}</small></span><ArrowUpRight aria-hidden="true"/></Link></li>)}</ul></section> : null)}
        {!groups.some(group => group.items.length) ? <p>No matches in the available workspace records.</p> : null}
        {runs.isError ? <p role="status">Run history could not be refreshed. Other results remain available.</p> : null}
        {runs.isFetching ? <p role="status">Checking run history...</p> : null}
      </div>
    </Dialog.Content></Dialog.Portal>
  </Dialog.Root>;
}
