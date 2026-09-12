import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { api, DEMO_MODE } from "../lib/api";
import { runnerDiagnosticsPath, runnerLifecycleFailure } from "../lib/runner-diagnostics";
import { isExecuteRunnerReady } from "./ExecuteOnboarding";
import { Button, Callout, ErrorState, sentence } from "./Primitives";
import type { PreflightReport } from "../types";
import { RunnerUpgradeReview } from "./RunnerUpgradeReview";

export function RunnerInventoryRecovery({ profileId, problems }: { profileId?: string; problems?: PreflightReport["findings"] }) {
  if (!profileId || !problems?.some((problem) => (typeof problem === "string" ? problem : problem.message)?.startsWith("Runner inventory is missing enabled action(s):"))) return null;
  return <Callout tone="warning" title="The enrolled runner is missing a required method"><p>Keep this experiment unstarted. In Local runner, stop it safely and review the verified upgrade and retained history. Resolve any reported blocker before applying it.</p><Link to={runnerDiagnosticsPath(profileId)}>Review runner update for this profile</Link></Callout>;
}

/** Native runner setup only; experiment preflight and approval remain separate. */
export function ExecuteRunnerReadiness({ profileId }: { profileId?: string }) {
  const client = useQueryClient();
  const [upgradeBusy, setUpgradeBusy] = useState(false);
  const action = useMutation({
    mutationFn: ({ kind, profileId: requestedProfile }: { kind: "bootstrap" | "start" | "stop"; profileId: string }) => {
      if (!requestedProfile || DEMO_MODE) throw new Error("Choose an Execute profile in the installed local service first.");
      return kind === "bootstrap" ? api.bootstrapRunner(requestedProfile) : kind === "stop" ? api.stopRunner(requestedProfile) : api.startRunner(requestedProfile);
    },
    onSettled: () => client.invalidateQueries({ queryKey: ["runner-lifecycle"] }),
  });
  const runner = useQuery({ queryKey: ["runner-lifecycle", profileId ?? null], queryFn: () => api.runnerStatus(profileId), enabled: Boolean(profileId), retry: false, refetchInterval: action.isPending || upgradeBusy ? false : 5000 });
  const matchingProfile = Boolean(profileId) && runner.data?.profile_id === profileId;
  const ready = matchingProfile && !runner.error && isExecuteRunnerReady(runner.data);
  const canAct = !DEMO_MODE && Boolean(profileId) && !runner.isFetching && !runner.isPending && !runner.error && !action.isPending && !upgradeBusy;
  const canStop = matchingProfile && (runner.data?.state === "ready" || runner.data?.state === "stale" || (runner.data?.state === "unavailable" && runner.data.process === "authenticated"));
  const next = runner.data?.state === "unbootstrapped" ? "bootstrap" : matchingProfile && runner.data?.state === "stopped" && runner.data.enrollment === "active" ? "start" : undefined;
  return <section className="execute-runner-readiness" aria-label="Execute runner readiness">
    <div><h2>Local runner</h2><p role="status">{action.isPending ? action.variables.profileId !== profileId ? "Finishing runner setup for the previous profile…" : action.variables.kind === "bootstrap" ? "Preparing runner…" : action.variables.kind === "stop" ? "Stopping runner safely…" : "Starting runner…" : !profileId ? "Choose an Execute profile" : runner.isPending ? "Checking runner…" : ready ? "Runner authenticated" : runner.error ? "Runner status unavailable" : matchingProfile && runner.data?.upgrade_recovery_required ? "Runner update needs completion" : runner.data?.state === "ready" ? "Runner needs attention" : sentence(runner.data?.state ?? "unavailable")}</p></div>
    <p>{DEMO_MODE ? "Open the installed local service to prepare a runner." : ready ? "The runner connection is authenticated. Preflight still checks whether its actual methods support this experiment, profile and scope." : "Prepare and start the local runner for this profile before reviewing an Execute experiment. Starting the runner does not start the experiment or approve its actions."}</p>
    {!profileId ? <p>Choose an Execute profile below to prepare its runner.</p> : null}
    <div className="execute-runner-actions">
      {!ready && next ? <Button variant="primary" disabled={!canAct} onClick={() => profileId && action.mutate({ kind: next, profileId })}>{next === "bootstrap" ? "Prepare runner" : "Start runner"}</Button> : null}
      <Button variant="ghost" disabled={!profileId || runner.isFetching || action.isPending || upgradeBusy} onClick={() => { void runner.refetch(); }}>Check runner status</Button>
      {profileId ? <Link to={runnerDiagnosticsPath(profileId)}>Open runner diagnostics</Link> : null}
    </div>
    {profileId ? <details><summary>Preflight reports a missing runner method?</summary><p>An application update can leave the previously enrolled runner in place. Stop it safely, then review the candidate and retained history below. Applying an upgrade does not start the runner or the experiment.</p>{canStop ? <Button variant="secondary" disabled={!canAct} onClick={() => action.mutate({ kind: "stop", profileId })}>Stop runner safely</Button> : null}</details> : null}
    <RunnerUpgradeReview profileId={profileId} status={runner.data} disabled={action.isPending || runner.isPending || runner.isFetching || Boolean(runner.error)} onBusy={setUpgradeBusy}/>
    {runner.error ? <ErrorState title="Runner check failed" error={runner.error} /> : null}
    {action.error && action.variables?.profileId === profileId ? <><ErrorState title="Runner setup needs attention" error={action.error}/>{runnerLifecycleFailure(action.error).map((detail, index) => <p key={index}>{detail}</p>)}</> : null}
  </section>;
}
