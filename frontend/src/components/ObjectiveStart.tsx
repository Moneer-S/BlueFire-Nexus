import { useQuery } from "@tanstack/react-query";
import { ArrowRight, RefreshCw } from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Badge, Button, DataList, Field } from "./Primitives";
import { checkedFileAccessList, checkedFileAccessStatus, fileAccessApi, type FileAccessStatus } from "../lib/file-access";
import { objectiveById, objectiveHref, objectives } from "../lib/objectives";
import "./ObjectiveStart.css";

export function ObjectiveStart() {
  const [params, setParams] = useSearchParams();
  const [now, setNow] = useState(Date.now());
  const requested = params.get("goal");
  const selected = objectiveById(requested);
  const fileAccessSelected = selected?.id === "file-access";
  const status = useQuery({
    queryKey: ["file-access-status"],
    queryFn: async () => checkedFileAccessStatus(await fileAccessApi.status()),
    enabled: fileAccessSelected,
    retry: false,
  });
  const controls = useQuery({
    queryKey: ["file-access-list"],
    queryFn: async () => checkedFileAccessList(await fileAccessApi.list()),
    enabled: fileAccessSelected,
    retry: false,
  });
  const setupExpiry = status.data
    ? "setup" in status.data ? status.data.setup?.expires_at_ms : status.data.enrollment?.expires_at_ms
    : undefined;
  useEffect(() => {
    if (setupExpiry === undefined) return;
    const remaining = setupExpiry - Date.now();
    if (remaining <= 0) {
      if (now < setupExpiry) setNow(Date.now());
      return;
    }
    const timer = window.setTimeout(() => setNow(Date.now()), Math.min(remaining, 2_147_483_647));
    return () => window.clearTimeout(timer);
  }, [setupExpiry, now]);
  const choose = (value: string) => setParams((previous) => {
    const next = new URLSearchParams(previous);
    if (value) next.set("goal", value);
    else next.delete("goal");
    return next;
  }, { replace: true });

  return <section className="objective-start" aria-labelledby="objective-start-title">
    <div className="objective-start-choice">
      <h2 id="objective-start-title">Choose an objective</h2>
      <Field label="Objective">
        <select value={selected?.id ?? ""} onChange={(event) => choose(event.target.value)}>
          <option value="">Select a question</option>
          {objectives.map((objective) => <option key={objective.id} value={objective.id}>{objective.label}</option>)}
        </select>
      </Field>
      {requested && !selected ? <p role="alert">This objective is unavailable. Select a supported question.</p> : null}
      {selected ? <Link className="button button-primary button-medium" to={objectiveHref(selected, params)}>Review environment <ArrowRight aria-hidden="true" /></Link> : <Button variant="primary" disabled>Review environment <ArrowRight aria-hidden="true" /></Button>}
    </div>
    {selected ? <div className="objective-start-scope" aria-live="polite">
      <h3>{selected.question}</h3>
      <DataList items={[
        { label: "Required environment", value: selected.environment },
        { label: "Planned test data", value: selected.data },
        { label: "Proposed change", value: selected.change },
        ...(fileAccessSelected ? [
          { label: "Workspace setup", value: fileAccessSetupState(status.isFetching, status.error, status.data, now) },
          { label: "Saved controls", value: fileAccessControlState(controls.isPending, controls.error, controls.data) },
          { label: "Effective access", value: <Badge tone="warning">Not tested</Badge> },
        ] : [{ label: "Workspace setup", value: <Badge tone="warning">Not checked here</Badge> }]),
      ]} />
      {fileAccessSelected && (status.error || controls.error) ? <div className="objective-start-refresh">
        <span>Some file-access setup details could not be loaded.</span>
        <Button variant="ghost" size="small" disabled={status.isFetching || controls.isFetching} onClick={() => { void status.refetch(); void controls.refetch(); }}><RefreshCw />Retry</Button>
      </div> : null}
    </div> : null}
  </section>;
}

function fileAccessSetupState(
  fetching: boolean,
  error: unknown,
  status: FileAccessStatus | undefined,
  now: number,
) {
  if (fetching) return <Badge>Checking</Badge>;
  if (error) return <Badge tone="warning">Unavailable</Badge>;
  if (!status) return <Badge tone="warning">Not checked</Badge>;
  if ("setup" in status && status.setup) {
    if (status.setup.expires_at_ms <= now) return <Badge tone="warning">Setup receipt expired</Badge>;
    return <Badge tone="info">{status.available ? "Paired setup available" : "Setup receipt found"}</Badge>;
  }
  if (status.enrollment && status.enrollment.expires_at_ms <= now) return <Badge tone="warning">Workspace enrollment expired</Badge>;
  return status.available
    ? <Badge tone="info">Workspace recognized</Badge>
    : <Badge tone="warning">No current workspace</Badge>;
}

function fileAccessControlState(
  pending: boolean,
  error: unknown,
  value: ReturnType<typeof checkedFileAccessList> | undefined,
) {
  if (pending) return <Badge>Loading</Badge>;
  if (error) return <Badge tone="warning">Unavailable</Badge>;
  if (!value) return <Badge tone="warning">Not checked</Badge>;
  const count = value.controls.length;
  return <span>{count} saved {count === 1 ? "control" : "controls"}</span>;
}
