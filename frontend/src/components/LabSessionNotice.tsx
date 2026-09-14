import { useEffect, useState } from "react";
import type { CatalogResponse } from "../types";
import "./LabSessionNotice.css";

export function LabSessionNotice({ providers }: { providers: CatalogResponse["ai"]["providers"] }) {
  const deadlines = (providers ?? []).map((provider) => provider.health?.lab_session_expires_at_ms)
    .filter((value): value is number => typeof value === "number" && Number.isSafeInteger(value) && value > 0);
  const deadline = deadlines.length ? Math.min(...deadlines) : undefined;
  return deadline === undefined ? null : <TimedLabSession key={deadline} deadline={deadline} />;
}

function TimedLabSession({ deadline }: { deadline: number }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 15_000);
    return () => window.clearInterval(timer);
  }, []);
  const remaining = deadline - now;
  const minutes = Math.max(1, Math.ceil(remaining / 60_000));
  const expired = remaining <= 0;
  const urgent = remaining <= 120_000;
  const title = expired ? "Lab session time limit reached" : `Lab session ends in about ${minutes} ${minutes === 1 ? "minute" : "minutes"}`;
  const guidance = expired
    ? "Restart the lab from the terminal that opened it, then reopen this page. Review saved jobs and any interrupted cleanup before resuming. Work does not restart automatically."
    : "The temporary provider enrollment ends this isolated session at its time limit. Saved run records remain in the lab. Finish or stop active work before then; starting a fresh session requires the lab terminal.";
  return <aside className={`lab-session-notice ${urgent ? "urgent" : ""}`} aria-label="Lab session time limit">
    {urgent ? <><strong role="status">{title}</strong><p>{guidance}</p></> : <details><summary>{title}</summary><p>{guidance}</p></details>}
    <span className="lab-session-clock">{new Date(deadline).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}</span>
  </aside>;
}
