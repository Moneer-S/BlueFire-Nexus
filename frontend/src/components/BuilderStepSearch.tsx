import * as Dialog from "@radix-ui/react-dialog";
import * as Tooltip from "@radix-ui/react-tooltip";
import { Search, X } from "lucide-react";
import { useMemo, useState } from "react";
import { displayTitle } from "../lib/display-title";
import type { Behavior, ScenarioStep } from "../types";

export function BuilderStepSearch({ steps, behaviors, onSelect }: {
  steps: ScenarioStep[];
  behaviors: Map<string, Behavior>;
  onSelect: (stepId: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const term = query.trim().toLocaleLowerCase();
  const results = useMemo(() => {
    if (!term) return [];
    const rows = steps.map((step, index) => ({
      step,
      index,
      title: displayTitle(behaviors.get(step.behavior_id)?.title ?? "Unavailable step"),
      purpose: behaviors.get(step.behavior_id)?.purpose ?? "",
    }));
    const titleCounts = new Map<string, number>();
    rows.forEach(row => titleCounts.set(row.title, (titleCounts.get(row.title) ?? 0) + 1));
    return rows.flatMap(row => {
      const titleMatch = row.title.toLocaleLowerCase().includes(term);
      const purposeMatch = row.purpose.toLocaleLowerCase().includes(term);
      const metadataMatch = titleMatch || purposeMatch;
      const exactIdMatch = row.step.id.toLocaleLowerCase() === term;
      return metadataMatch || exactIdMatch
        ? [{ ...row, metadataMatch, duplicateTitle: (titleCounts.get(row.title) ?? 0) > 1 }]
        : [];
    }).sort((left, right) => Number(right.metadataMatch) - Number(left.metadataMatch) || left.index - right.index);
  }, [behaviors, steps, term]);

  const choose = (stepId: string) => {
    setOpen(false);
    setQuery("");
    onSelect(stepId);
  };

  return <Dialog.Root open={open} onOpenChange={setOpen}>
    <Tooltip.Root>
      <Tooltip.Trigger asChild><Dialog.Trigger className="icon-button" aria-label="Find step"><Search aria-hidden="true" /></Dialog.Trigger></Tooltip.Trigger>
      <Tooltip.Portal><Tooltip.Content className="tooltip" sideOffset={8}>Find step<Tooltip.Arrow className="tooltip-arrow" /></Tooltip.Content></Tooltip.Portal>
    </Tooltip.Root>
    <Dialog.Portal>
      <Dialog.Overlay className="dialog-overlay" />
      <Dialog.Content className="dialog-content workspace-search-dialog builder-step-search-dialog">
        <Dialog.Title className="sr-only">Find a step in this experiment</Dialog.Title>
        <Dialog.Description className="sr-only">Search step titles and purposes, or enter an exact step ID.</Dialog.Description>
        <div className="workspace-search-input">
          <Search aria-hidden="true" />
          <input autoFocus aria-label="Find a step" value={query} onChange={event => setQuery(event.target.value)} placeholder="Search step title, purpose, or exact ID" />
          <Dialog.Close className="icon-button" aria-label="Close search"><X aria-hidden="true" /></Dialog.Close>
        </div>
        <div className="workspace-search-results builder-step-search-results" aria-live="polite">
          {!term ? <p>{steps.length} {steps.length === 1 ? "step" : "steps"} in this experiment.</p> : results.length ? <ul>
            {results.map(({ step, index, title, purpose, duplicateTitle, metadataMatch }) => <li key={step.id}>
              <button type="button" onClick={() => choose(step.id)}>
                <span><strong>{title}</strong>{purpose ? <small>{purpose}</small> : null}<code>{duplicateTitle ? `Step ${index + 1} · ` : ""}{step.id}</code></span>
                {!metadataMatch ? <small>Exact step ID</small> : null}
              </button>
            </li>)}
          </ul> : <p>No matching steps.</p>}
        </div>
      </Dialog.Content>
    </Dialog.Portal>
  </Dialog.Root>;
}
