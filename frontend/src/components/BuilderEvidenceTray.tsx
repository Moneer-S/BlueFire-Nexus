import { Activity, ArrowRight, ChevronDown, FileText, Info } from "lucide-react";
import { useId, useRef, useState, type KeyboardEvent } from "react";
import { Link } from "react-router-dom";
import { displayTitle } from "../lib/display-title";
import { inputLabel, inputTypeLabel } from "../lib/graph-view";
import type { Behavior, ScenarioStep } from "../types";
import { Badge } from "./Primitives";
import "./BuilderEvidenceTray.css";

type EvidenceChoice = { key: string; label: string; detail?: string; outputIndex?: number; kind: "output" | "observations" | "limitations" };

function EvidenceSections({ behavior }: { behavior: Behavior }) {
  const id = useId();
  const choices: EvidenceChoice[] = [
    ...behavior.outputs.map((output, index) => ({ key: `output-${index}`, label: inputLabel(output.name),
      detail: inputLabel(inputTypeLabel(output.type)), outputIndex: index, kind: "output" as const })),
    { key: "observations", label: "Expected observations", kind: "observations" },
    { key: "limitations", label: "Method limitations", kind: "limitations" },
  ];
  const [selectedKey, setSelectedKey] = useState(choices[0]!.key);
  const selected = choices.find(choice => choice.key === selectedKey) ?? choices[0]!;
  const output = selected.kind === "output" ? behavior.outputs[selected.outputIndex!] : undefined;
  const tabs = useRef<HTMLDivElement>(null);
  const selectWithKeyboard = (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
    const next = event.key === "ArrowDown" ? (index + 1) % choices.length
      : event.key === "ArrowUp" ? (index - 1 + choices.length) % choices.length
        : event.key === "Home" ? 0 : event.key === "End" ? choices.length - 1 : undefined;
    if (next === undefined) return;
    event.preventDefault();
    event.stopPropagation();
    setSelectedKey(choices[next]!.key);
    tabs.current?.querySelectorAll<HTMLButtonElement>('[role="tab"]')[next]?.focus();
  };
  return <div className="builder-evidence-content">
    <div className="builder-evidence-list">
      <span className="builder-evidence-list-label">Expected outputs · {behavior.outputs.length}</span>
      {!behavior.outputs.length ? <p className="builder-evidence-no-outputs">No output artifacts declared.</p> : null}
      <div className="builder-evidence-tabs" ref={tabs} role="tablist" aria-label="Expected step evidence" aria-orientation="vertical">
      {choices.map((choice, index) => <button key={choice.key} type="button" role="tab"
        id={`${id}-tab-${choice.key}`} aria-controls={`${id}-panel`}
        aria-selected={selected.key === choice.key} tabIndex={selected.key === choice.key ? 0 : -1}
        className={choice.kind === "output" ? undefined : "builder-evidence-support-tab"}
        onClick={() => setSelectedKey(choice.key)} onKeyDown={event => selectWithKeyboard(event, index)}>
        {choice.kind === "output" ? <FileText aria-hidden="true" /> : choice.kind === "observations" ? <Activity aria-hidden="true" /> : <Info aria-hidden="true" />}
        <span><strong>{choice.label}</strong>{choice.detail ? <small>{choice.detail}</small> : null}</span>
      </button>)}
      </div>
    </div>
    <div className="builder-evidence-detail" role="tabpanel" id={`${id}-panel`}
      aria-labelledby={`${id}-tab-${selected.key}`} tabIndex={0}>
      {output ? <>
        <p className="builder-evidence-eyebrow">Expected output</p>
        <h3>{inputLabel(output.name)}</h3>
        <p>{output.description?.trim() || `This method declares ${inputTypeLabel(output.type)} as an output.`}</p>
        <dl className="builder-evidence-facts"><div><dt>Content</dt><dd>{inputLabel(inputTypeLabel(output.type))}</dd></div>
          <div><dt>Items</dt><dd>{output.multiple ? "Multiple items" : "Single item"}</dd></div></dl>
        <details className="builder-evidence-contract-reference"><summary>Contract reference</summary><dl>
          <div><dt>Output name</dt><dd><code>{output.name}</code></dd></div>
          <div><dt>Contract type</dt><dd><code>{output.type}</code></dd></div>
        </dl></details>
      </> : selected.kind === "observations" ? <>
        <p className="builder-evidence-eyebrow">Expected observations</p><h3>What to look for</h3>
        {behavior.telemetry.length ? <ul>{behavior.telemetry.map((item, index) => <li key={`${index}-${item}`}>{inputLabel(inputTypeLabel(item))}</li>)}</ul>
          : <p>This method declares no observation types.</p>}
        {behavior.detection_hints.length ? <><h4>Detection value</h4><ul>{behavior.detection_hints.map((hint, index) => <li key={index}>{hint}</li>)}</ul></> : <p>No detection guidance is declared.</p>}
      </> : <>
        <p className="builder-evidence-eyebrow">Method limitations</p><h3>How to interpret this evidence</h3>
        {behavior.limitations.length ? <ul>{behavior.limitations.map((limitation, index) => <li key={index}>{limitation}</li>)}</ul>
          : <p>No method-specific evidence limitations are declared.</p>}
      </>}
    </div>
  </div>;
}

/** Selected method declarations only; this tray has no run or observed-evidence binding. */
export function BuilderEvidenceTray({ step, ordinal, behavior }: { step?: ScenarioStep; ordinal?: number; behavior?: Behavior }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  const title = behavior ? displayTitle(behavior.title) : step ? "Method unavailable" : "Select a step";
  return <section className="builder-evidence-tray" data-open={open} aria-label="Step evidence">
    <header className="builder-evidence-header"><button type="button" aria-expanded={open} aria-controls={`${id}-content`} onClick={() => setOpen(value => !value)}>
      <FileText aria-hidden="true" /><strong>Step evidence</strong><span className="builder-evidence-selection">{step && ordinal ? `Step ${ordinal} · ` : ""}{title}</span>
      <Badge tone="info">Expected</Badge><ChevronDown className="builder-evidence-chevron" aria-hidden="true" />
    </button></header>
    <div id={`${id}-content`} className="builder-evidence-expanded" hidden={!open}>
      <div className="builder-evidence-scope"><p>From the method definition. Open a run to inspect recorded evidence.</p>
        <Link to="/runs">Open run results<ArrowRight aria-hidden="true" /></Link></div>
      {step && behavior ? <EvidenceSections key={`${step.id}:${behavior.id}`} behavior={behavior} />
        : <div className="builder-evidence-empty"><FileText aria-hidden="true" /><div><strong>{step ? "This method is unavailable" : "Select a step to inspect its evidence"}</strong>
          <p>{step ? "Its expected outputs and observation guidance are unavailable. Choose an available method in step details."
            : "Choose a card on the canvas or a row in Steps. Its declared outputs and observation guidance will appear here."}</p></div></div>}
    </div>
  </section>;
}
