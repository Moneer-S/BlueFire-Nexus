import { FileSearch } from "lucide-react";
import { resolveRunStepEvidence } from "../lib/run-step-evidence";
import type { CatalogResponse, RunRecord, RunStep } from "../types";
import { EvidenceRecords } from "./EvidenceRecords";

export function RunStepEvidence({ run, step, name, catalog }: { run: RunRecord; step: RunStep; name: string; catalog: CatalogResponse }) {
  const { records, unresolvedIds, distinctReferenceCount } = resolveRunStepEvidence(run, step);
  if (!distinctReferenceCount) return <span className="run-step-no-evidence">No linked evidence</span>;
  return <details className="run-step-evidence-preview">
    <summary><FileSearch aria-hidden="true"/><span>Inspect evidence</span><span className="run-step-evidence-count">{distinctReferenceCount} linked {distinctReferenceCount === 1 ? "record" : "records"}</span></summary>
    <div className="run-step-evidence-body" role="group" aria-label={`Evidence for ${name}`}>
      {unresolvedIds.length ? <p className="run-step-evidence-unavailable">{unresolvedIds.length} linked {unresolvedIds.length === 1 ? "record is" : "records are"} unavailable or cannot be attributed to this step. Check the recorded references in Step details.</p> : null}
      {records.length ? <EvidenceRecords records={records} catalog={catalog} run={run}/> : null}
    </div>
  </details>;
}
