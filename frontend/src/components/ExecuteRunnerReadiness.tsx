import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, DEMO_MODE } from "../lib/api";
import { isExecuteRunnerReady } from "./ExecuteOnboarding";
import { Button, ErrorState, sentence } from "./Primitives";

/** Native runner setup only; experiment preflight and approval remain separate. */
export function ExecuteRunnerReadiness({ profileId }: { profileId?: string }) {
  const client = useQueryClient();
  const action = useMutation({
    mutationFn: (kind: "bootstrap" | "start") => {
      if (!profileId || DEMO_MODE) throw new Error("Choose an Execute profile in the installed local service first.");
      return kind === "bootstrap" ? api.bootstrapRunner(profileId) : api.startRunner(profileId);
    },
    onSuccess: (status) => client.setQueryData(["runner-lifecycle"], status),
    onSettled: () => { void client.invalidateQueries({ queryKey: ["runner-lifecycle"] }); },
  });
  const runner = useQuery({ queryKey: ["runner-lifecycle"], queryFn: api.runnerStatus, retry: false, refetchInterval: action.isPending ? false : 5000 });
  const ready = !runner.error && isExecuteRunnerReady(runner.data);
  const canAct = !DEMO_MODE && Boolean(profileId) && !runner.isPending && !runner.error && !action.isPending;
  const next = runner.data?.state === "unbootstrapped" ? "bootstrap" : runner.data?.state === "stopped" && runner.data.enrollment === "active" ? "start" : undefined;
  return <section className="execute-runner-readiness" aria-label="Execute runner readiness">
    <div><h2>Local runner</h2><p role="status">{action.isPending ? action.variables === "bootstrap" ? "Preparing runner…" : "Starting runner…" : runner.isPending ? "Checking runner…" : ready ? "Ready for preflight" : runner.error ? "Runner status unavailable" : runner.data?.state === "ready" ? "Runner needs attention" : sentence(runner.data?.state ?? "unavailable")}</p></div>
    <p>{DEMO_MODE ? "Open the installed local service to prepare a runner." : ready ? "The runner is authenticated. Ask the Assistant to prepare this experiment; preflight will check the selected profile, scope, and actions." : "Prepare and start the local runner before asking the Assistant to prepare this Execute run. Starting the runner does not start the experiment or approve its actions."}</p>
    {!profileId ? <p>Choose an Execute profile below to prepare its runner.</p> : null}
    <div className="execute-runner-actions">
      {!ready && next ? <Button variant="primary" disabled={!canAct} onClick={() => action.mutate(next)}>{next === "bootstrap" ? "Prepare runner" : "Start runner"}</Button> : null}
      <Button variant="ghost" disabled={runner.isFetching || action.isPending} onClick={() => { void runner.refetch(); }}>Check runner status</Button>
      {!ready && !next && !runner.isPending ? <Link to="/runners">Open runner diagnostics</Link> : null}
    </div>
    {runner.error ? <ErrorState title="Runner check failed" error={runner.error} /> : null}
    {action.error ? <ErrorState title="Runner setup needs attention" error={action.error} /> : null}
  </section>;
}
