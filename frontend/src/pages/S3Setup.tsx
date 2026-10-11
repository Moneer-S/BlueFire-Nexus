import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, FileCheck2, RefreshCw } from "lucide-react";
import { Link, useSearchParams } from "react-router-dom";
import { ExecuteRunnerReadiness } from "../components/ExecuteRunnerReadiness";
import { Badge, Button, Callout, DataList, ErrorState, Field, LoadingState } from "../components/Primitives";
import { s3SetupApi, type S3ConfigurationState, type S3SetupEnvironment } from "../lib/s3-setup";
import { S3SetupDraft } from "./S3SetupDraft";

const configuration: Record<S3ConfigurationState, { title: string; detail: string }> = {
  unsupported_host: { title: "Owned Linux host required", detail: "This connection does not meet the supported S3 host requirements." },
  method_unavailable: { title: "S3 method unavailable", detail: "The enrolled runner does not provide the required S3 method. Its update needs review." },
  missing: { title: "S3 configuration missing", detail: "No protected S3 configuration is installed for this enrollment. Owner-local setup is required." },
  incomplete: { title: "Setup recovery required", detail: "An interrupted local publication is retained. Complete its exact owner-local recovery before another check." },
  invalid: { title: "Local setup needs review", detail: "The protected configuration could not be verified consistently. No local repair was attempted." },
  profile_missing: { title: "Profile not connected to S3", detail: "The installed configuration does not bind an environment to this profile." },
  profile_changed: { title: "Installed profile is out of date", detail: "The local configuration does not match this profile or its enrolled host. Review and update owner-local setup before execution." },
  configured: { title: "Local checks recorded", detail: "AWS identity, effective permissions and defensive outcomes have not been tested." },
};
const accessName = { absent: "Not imported", current: "Locally current", expired: "Expired" };

function SetupEnvironment({ value }: { value: S3SetupEnvironment }) {
  return <article className="s3-setup-environment"><h3>{value.environment_id}</h3><DataList items={[
    { label: "Protected runtime", value: value.runtime_state === "verified" ? "Verified locally" : "Unavailable or changed" },
    { label: "Temporary access reference", value: accessName[value.access_reference_state] },
    { label: "Authorized time window", value: value.scope_state === "current" ? "Current" : "Not current" },
    { label: "Generated test objects", value: value.fixture_generation === 2 ? "Enrolled" : "Not enrolled" },
    { label: "AWS access", value: "Not checked" },
  ]} /></article>;
}

export function S3Setup({ onClose }: { onClose: () => void }) {
  const [params, setParams] = useSearchParams();
  const cache = useQueryClient();
  const profiles = useQuery({ queryKey: ["s3-setup-profiles"], queryFn: s3SetupApi.profiles, retry: false });
  const selectedId = params.get("setup_profile") ?? (profiles.data?.profiles.length === 1 ? profiles.data.profiles[0]?.profile_id ?? "" : "");
  const selected = profiles.data?.profiles.find(row => row.profile_id === selectedId);
  const check = useMutation({ mutationFn: s3SetupApi.check, onSuccess: () => { void cache.invalidateQueries({ queryKey: ["s3-environments"] }); } });
  const current = selected && !profiles.error && check.data?.profile_id === selected.profile_id && check.data.profile_digest === selected.profile_digest ? check.data : null;
  const matchingRequest = check.variables?.profile_id === selected?.profile_id && check.variables?.profile_digest === selected?.profile_digest;
  const choose = (profileId: string) => { check.reset(); const next = new URLSearchParams(params); next.set("setup_profile", profileId); setParams(next); };
  return <section className="s3-band s3-setup" aria-label="S3 connection setup">
    <div className="s3-setup-heading"><h2>S3 connection</h2><Button variant="ghost" onClick={onClose}><ArrowLeft />Back to workspace</Button></div>
    <div className="s3-setup-columns"><div>
      {profiles.isPending ? <LoadingState label="Opening saved S3 profiles" /> : profiles.error ? <ErrorState title="S3 profiles unavailable" error={profiles.error} /> : <>
        <Field label="Linux S3 profile"><select value={selectedId} onChange={event => choose(event.target.value)} disabled={check.isPending}><option value="">Select a saved profile</option>{profiles.data?.profiles.map(row => <option key={row.profile_id} value={row.profile_id}>{row.profile_id}</option>)}</select></Field>
        {!profiles.data?.profiles.length ? <Callout tone="warning" title="No active Linux S3 profile"><Link to="/runner-profiles">Open runner profiles</Link></Callout> : !selected ? <p>The previous profile is no longer available. Choose a current saved profile.</p> : null}
        {profiles.data?.truncated ? <p>The first 64 eligible profiles are shown.</p> : null}
      </>}
      <div className="s3-actions"><Button variant="primary" disabled={!selected || Boolean(profiles.error) || profiles.isFetching || check.isPending} onClick={() => selected && check.mutate(selected)}><FileCheck2 />{check.isPending ? "Checking connection" : "Check connection"}</Button><Button disabled={profiles.isFetching || check.isPending} onClick={() => { check.reset(); void profiles.refetch(); }}><RefreshCw />Refresh profiles</Button></div>
      {check.error && matchingRequest ? <ErrorState title="Connection check not confirmed" error={check.error} /> : null}
      {current ? <div className="s3-setup-result" aria-live="polite"><Badge tone={current.host_state === "authenticated" ? "info" : "warning"}>{current.host_state === "authenticated" ? "Authenticated connection" : "Runner unavailable"}</Badge>{current.setup ? <><h3>{configuration[current.setup.configuration_state].title}</h3><p>{configuration[current.setup.configuration_state].detail}</p>{current.setup.environments.map(row => <SetupEnvironment key={row.environment_id} value={row} />)}</> : <p>The selected runner could not provide a consistent setup check.</p>}</div> : <p role="status">No current S3 connection check.</p>}
    </div><div><ExecuteRunnerReadiness profileId={selected?.profile_id} /><section className="s3-band"><h3>Owner-local prerequisites</h3><DataList items={[
      { label: "Runtime", value: "Protected Linux installation" },
      { label: "Cloud scope", value: "Existing account, bucket and scoped roles" },
      { label: "Temporary credentials", value: "Imported locally, never in this browser" },
    ]} /></section></div></div>
    <S3SetupDraft profileId={selectedId} selected={profiles.error || profiles.isFetching ? undefined : selected} />
  </section>;
}
