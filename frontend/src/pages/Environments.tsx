import { useQuery } from "@tanstack/react-query";
import { ArrowRight, Cloud, FileLock2, Network, RefreshCw, Server, Workflow } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { PageHeader, Badge, Button, ErrorState, LoadingState, sentence, formatDate } from "../components/Primitives";
import { api, DEMO_MODE } from "../lib/api";
import { adSmbApi, checkedAdEnvironments, checkedAdList } from "../lib/ad-smb";
import { checkedFileAccessList, checkedFileAccessStatus, fileAccessApi } from "../lib/file-access";
import { providerChoiceLabel } from "../lib/provider-presentation";
import { checkedEnvironments, s3Api } from "../lib/s3-access";
import "./Environments.css";

const staleTime = 30_000;

function StateBadge({ tone, children }: { tone: "success" | "warning" | "info" | "neutral"; children: string }) {
  return <Badge tone={tone}>{children}</Badge>;
}

function QueryState({ pending, error, label, retry }: { pending: boolean; error: unknown; label: string; retry: () => void }) {
  if (pending) return <LoadingState label={label} />;
  if (error) return <ErrorState title={`${label} unavailable`} error={error} retry={retry} />;
  return null;
}

function BandHeader({ id, title, icon: Icon, status, action }: { id: string; title: string; icon: typeof Cloud; status?: ReactNode; action?: ReactNode }) {
  return <header className="environment-band-header"><span className="environment-band-icon"><Icon aria-hidden="true" /></span><h2 id={id}>{title}</h2>{status}{action}</header>;
}

function BandLinks({ to, linkLabel, secondaryLink }: { to: string; linkLabel: string; secondaryLink?: { to: string; label: string } }) {
  return <footer className="environment-band-links"><Link to={to}>{linkLabel}<ArrowRight aria-hidden="true" /></Link>{secondaryLink ? <Link to={secondaryLink.to}>{secondaryLink.label}<ArrowRight aria-hidden="true" /></Link> : null}</footer>;
}

export function EnvironmentsPage() {
  const [now, setNow] = useState(Date.now());
  const s3 = useQuery({ queryKey: ["s3-environments"], queryFn: async () => checkedEnvironments(await s3Api.environments()), retry: false, staleTime });
  const fileStatus = useQuery({ queryKey: ["file-access-status"], queryFn: async () => checkedFileAccessStatus(await fileAccessApi.status()), retry: false, staleTime });
  const fileControls = useQuery({ queryKey: ["file-access-list"], queryFn: async () => checkedFileAccessList(await fileAccessApi.list()), retry: false, staleTime });
  const adEnvironments = useQuery({ queryKey: ["ad-smb-environments"], queryFn: async () => checkedAdEnvironments(await adSmbApi.environments()), retry: false, staleTime });
  const adWorkflows = useQuery({ queryKey: ["ad-smb-workflows"], queryFn: async () => checkedAdList(await adSmbApi.list()), retry: false, staleTime });
  const catalog = useQuery({ queryKey: ["catalog"], queryFn: api.catalog, retry: false, staleTime });
  const profiles = useQuery({ queryKey: ["resources", "runner-profiles"], queryFn: () => api.resources("runner-profiles"), retry: false, staleTime });
  const runners = useQuery({ queryKey: ["resources", "runners"], queryFn: () => api.resources("runners"), retry: false, staleTime });
  const providers = useQuery({ queryKey: ["resources", "model-providers"], queryFn: () => api.resources("model-providers"), retry: false, staleTime });
  const authorizations = useQuery({ queryKey: ["ai-authorizations"], queryFn: api.aiAuthorizations, retry: false, staleTime });

  const fileSetup = fileStatus.data?.setup;
  const expiryTimes = [
    fileSetup?.expires_at_ms,
    fileStatus.data?.enrollment?.expires_at_ms,
    ...(s3.data?.environments.map(row => Date.parse(row.environment.scope.expires_at)) ?? []),
    ...(adEnvironments.data?.environments.map(row => Date.parse(row.environment.expiresAt)) ?? []),
    ...(catalog.data?.ai.providers?.map(provider => provider.health?.lab_session_expires_at_ms) ?? []),
    ...(authorizations.data?.authorizations.filter(item => item.status === "active").map(item => item.expires_at_ms) ?? []),
  ].filter((expiry): expiry is number => typeof expiry === "number" && Number.isFinite(expiry));
  const nextExpiry = expiryTimes.filter(expiry => expiry > now).sort((a, b) => a - b)[0];
  useEffect(() => {
    if (nextExpiry === undefined) return;
    let active = true;
    let timer = 0;
    const refresh = () => {
      if (!active) return;
      const current = Date.now();
      setNow(current);
      const remaining = nextExpiry - current;
      if (remaining > 0) timer = window.setTimeout(refresh, Math.min(remaining, 2_147_483_647));
    };
    timer = window.setTimeout(refresh, Math.max(0, Math.min(nextExpiry - Date.now(), 2_147_483_647)));
    return () => { active = false; window.clearTimeout(timer); };
  }, [nextExpiry]);

  const fileCurrent = fileSetup ? fileSetup.expires_at_ms > now : Boolean(fileStatus.data?.available && fileStatus.data?.enrollment && fileStatus.data.enrollment.expires_at_ms > now);
  const fileExpired = Boolean(fileSetup && fileSetup.expires_at_ms <= now || fileStatus.data?.enrollment && fileStatus.data.enrollment.expires_at_ms <= now);
  const fileReadiness = fileStatus.isError ? undefined : !fileStatus.data ? undefined
    : !fileCurrent ? { label: fileExpired ? "Expired" : fileSetup || fileStatus.data.enrollment ? "Unavailable" : "No setup", tone: "warning" as const }
      : fileStatus.data.available ? { label: "Available for review", tone: "info" as const }
        : fileSetup ? { label: "Setup saved", tone: "warning" as const }
          : { label: "Unavailable", tone: "warning" as const };
  const currentAuthorizations = authorizations.isError ? undefined : authorizations.data?.authorizations.filter(item => item.status === "active" && item.expires_at_ms > now).length;
  const nativeCurrentlyAvailable = Boolean(adEnvironments.data?.nativeAvailable && adEnvironments.data.environments.some(row => row.available && row.environment.provenance === "runner_reported" && Date.parse(row.environment.expiresAt) > now));
  const readinessQueries = [s3, fileStatus, fileControls, adEnvironments, adWorkflows, catalog, profiles, runners, providers, authorizations];
  const refreshing = readinessQueries.some(query => query.isFetching);
  const refresh = () => { readinessQueries.forEach(query => { void query.refetch(); }); };

  return <div className="page environments-page">
    <PageHeader title="Environments" description="Manage the access, runners, and models your experiments use." actions={<Button disabled={refreshing} onClick={refresh}><RefreshCw aria-hidden="true" />{refreshing ? "Checking status" : "Refresh status"}</Button>} />

    <div className="environment-section-heading"><div><h2>Environment access</h2><p>Open a workspace to review its setup, saved work, and next allowed operation.</p></div><Link to="/getting-started">Setup guide<ArrowRight aria-hidden="true" /></Link></div>
    <div className="environment-overview">
    <section className={`environment-band${s3.data && !s3.data.environments.length ? " environment-band-empty" : ""}`} aria-labelledby="cloud-access-heading">
      <BandHeader id="cloud-access-heading" title="Cloud access" icon={Cloud} status={s3.data && !s3.data.environments.length ? <StateBadge tone={s3.isError ? "warning" : "neutral"}>{s3.isError ? "Last reported" : "Not enrolled"}</StateBadge> : null} />
      <QueryState pending={s3.isPending} error={s3.error} label="S3 enrollment" retry={() => { void s3.refetch(); }} />
      {s3.data ? s3.data.environments.length ? <div className="environment-rows">{s3.data.environments.map(row => <article className="environment-row" key={row.environment.environment_id}>
        <div><strong>{row.environment.display_name}</strong><small>{row.environment.scope.bucket} · {row.environment.scope.region}</small></div>
        <p>{s3.isError ? "Last reported environment; current status could not be refreshed." : row.problem ?? (Date.parse(row.environment.scope.expires_at) <= now ? "The enrolled environment scope has expired." : row.available ? "Enrolled environment is available for review." : "Enrolled environment is currently unavailable.")}</p>
        <StateBadge tone={s3.isError || !row.available || Date.parse(row.environment.scope.expires_at) <= now ? "warning" : "info"}>{s3.isError ? "Last reported" : Date.parse(row.environment.scope.expires_at) <= now ? "Expired" : row.available ? "Ready for review" : "Unavailable"}</StateBadge>
      </article>)}</div> : <p className="environment-empty environment-empty-compact">{s3.data.problem ?? (s3.isError ? "No enrolled S3 environments were last reported." : "No enrolled S3 environments are reported.")}</p> : null}
      {s3.data?.problem && s3.data.environments.length ? <p className="environment-note">{s3.data.problem}</p> : null}
      <BandLinks to="/s3-access" linkLabel="Open S3 access" />
    </section>

    <section className={`environment-band${fileControls.data && !fileControls.data.controls.length ? " environment-band-empty" : ""}`} aria-labelledby="file-access-heading">
      <BandHeader id="file-access-heading" title="File access" icon={FileLock2} status={fileStatus.isError && fileStatus.data ? <StateBadge tone="warning">Last reported</StateBadge> : fileReadiness ? <StateBadge tone={fileReadiness.tone}>{fileReadiness.label}</StateBadge> : null} />
      <QueryState pending={fileStatus.isPending} error={fileStatus.error} label="File-access setup" retry={() => { void fileStatus.refetch(); }} />
      {fileStatus.data ? <div className="environment-rows"><article className="environment-row environment-file-status">
        {fileSetup || fileStatus.data.enrollment || fileStatus.data.platform === "macos" ? <div><strong>{fileStatus.data.platform === "macos" ? "macOS workspace" : fileSetup ? "Protected Windows setup" : "Prepared file-access session"}</strong><small>{fileSetup ? `Setup expires ${formatDate(new Date(fileSetup.expires_at_ms).toISOString())}` : fileStatus.data.enrollment ? `Enrollment expires ${formatDate(new Date(fileStatus.data.enrollment.expires_at_ms).toISOString())}` : "No current enrollment"}</small></div> : null}
        <p>{fileStatus.isError ? "Last reported setup; current status could not be refreshed." : !fileCurrent ? fileExpired ? "Saved setup has expired." : fileSetup || fileStatus.data.enrollment ? fileStatus.data.problem?.message ?? "Saved setup is unavailable for file operations." : "No setup is available for this workspace." : fileStatus.data.available ? "Available for reviewed file operations." : fileStatus.data.problem?.message ?? "Setup is saved, but file operations are unavailable."}</p>
      </article><article className="environment-row environment-row-history">
        <p>{fileControls.error ? "History unavailable; see the notice below." : fileControls.isPending ? "Loading saved-control history." : `${fileControls.data?.controls.length} saved ${fileControls.data?.controls.length === 1 ? "control" : "controls"}.`}</p>
        <StateBadge tone={fileControls.error ? "warning" : fileControls.isPending ? "neutral" : "info"}>{fileControls.error ? "Unavailable" : fileControls.isPending ? "Loading" : "History"}</StateBadge>
      </article></div> : null}
      {fileControls.error ? <ErrorState title="Saved file-access history unavailable" error={fileControls.error} retry={() => { void fileControls.refetch(); }} /> : null}
      <BandLinks to="/file-access" linkLabel="Open file access" />
    </section>

    <section className={`environment-band${adEnvironments.data && !adEnvironments.data.environments.length && adWorkflows.data && !adWorkflows.data.length ? " environment-band-empty" : ""}`} aria-labelledby="directory-access-heading">
      <BandHeader id="directory-access-heading" title="Directory access" icon={Network} status={adEnvironments.data && !adEnvironments.data.environments.length ? <StateBadge tone={adEnvironments.isError ? "warning" : "neutral"}>{adEnvironments.isError ? "Last reported" : "Not enrolled"}</StateBadge> : null} />
      <QueryState pending={adEnvironments.isPending} error={adEnvironments.error} label="AD environment readiness" retry={() => { void adEnvironments.refetch(); }} />
      {adEnvironments.data ? <>
        <div className="environment-rows">{adEnvironments.data.environments.map(row => <article className="environment-row" key={row.environment.id}>
          <div><strong>{row.environment.domain} · {row.environment.share}</strong><small>{sentence(row.environment.provenance)} environment · expires {formatDate(row.environment.expiresAt)}</small></div>
          <p>{adEnvironments.isError ? "Last reported environment; current status could not be refreshed." : row.readiness.problem ? (row.readiness.problem === "native_admission_unavailable" ? "Native admission is unavailable." : sentence(row.readiness.problem)) : row.available && Date.parse(row.environment.expiresAt) > now ? "Member and client channels are ready for review." : Date.parse(row.environment.expiresAt) <= now ? "The enrolled environment scope has expired." : "Environment is not ready for review."}</p>
          <StateBadge tone={adEnvironments.isError || !row.available || Date.parse(row.environment.expiresAt) <= now ? "warning" : "info"}>{adEnvironments.isError ? "Last reported" : Date.parse(row.environment.expiresAt) <= now ? "Expired" : row.available ? "Ready for review" : "Unavailable"}</StateBadge>
        </article>)}{!adEnvironments.data.environments.length ? <p className="environment-empty environment-empty-compact">{adEnvironments.isError ? "No enrolled AD environments were last reported. Native availability could not be refreshed." : `No enrolled AD environments are reported. Native execution: ${nativeCurrentlyAvailable ? "reported available for an enrolled environment" : "not reported available"}.`}</p> : null}</div>
        {adEnvironments.data.environments.length ? <p className="environment-note">Native execution: {adEnvironments.isError ? "last reported status could not be refreshed" : nativeCurrentlyAvailable ? "reported available for an enrolled environment" : "not reported available"}. Environment review readiness and workflow dispatch are separate.</p> : null}
      </> : null}
      <QueryState pending={adWorkflows.isPending} error={adWorkflows.error} label="AD workflow history" retry={() => { void adWorkflows.refetch(); }} />
      {adWorkflows.data ? <p className="environment-note environment-history-note">{adWorkflows.isError ? "Last reported" : "Saved"} workflows: {adWorkflows.data.length}; pending operations: {adWorkflows.data.filter(row => row.pending !== null).length}.</p> : null}
      <BandLinks to="/ad-smb" linkLabel="Open AD share access" />
    </section>

    </div>
    <div className="environment-section-heading environment-configuration-heading"><div><h2>Workspace connections</h2><p>Configured records and current access are shown separately.</p></div></div>
    <div className="environment-configurations">
    <section className="environment-band" aria-labelledby="execution-heading">
      <BandHeader id="execution-heading" title="Execution configuration" icon={Server} />
      <div className="environment-rows">
        <article className="environment-row"><div><strong>Runner profiles</strong><small>Rules and limits for reviewed runs</small></div>
          <p>{catalog.isError || profiles.isError ? catalog.data || profiles.data ? "Some profile information could not be refreshed." : "Profile information could not be loaded." : catalog.data && profiles.data ? "Review available profiles and saved configurations." : "Profile information is loading."}</p>
          <StateBadge tone={catalog.isError || profiles.isError ? "warning" : "info"}>{catalog.isError || profiles.isError ? catalog.data || profiles.data ? "Partial status" : "Unavailable" : catalog.data && profiles.data ? "Reported" : "Loading"}</StateBadge>
          {catalog.data && profiles.data ? <details className="environment-inventory-details"><summary>Inventory details</summary><span>{catalog.data.runner_profiles.length} catalog profiles · {profiles.data.resources.filter(item => item.status === "active").length} active saved profiles · {profiles.data.resources.length} saved profile records.</span></details> : null}
        </article>
        <article className="environment-row"><div><strong>Runner records</strong><small>Saved runners; connectivity is checked when used</small></div>
          <p>{runners.isError ? runners.data ? "Saved runner information could not be refreshed." : "Runner information could not be loaded." : runners.data ? "Saved records; connection is checked when a runner is used." : "Runner information is loading."}</p>
          <StateBadge tone={runners.isError ? "warning" : "neutral"}>{runners.isError ? runners.data ? "Last reported" : "Unavailable" : runners.data ? "Saved" : "Loading"}</StateBadge>
          {runners.data ? <details className="environment-inventory-details"><summary>Inventory details</summary><span>{runners.data.resources.length} saved {runners.data.resources.length === 1 ? "runner record" : "runner records"}; authentication has not been checked here.</span></details> : null}
        </article>
      </div>
      {(catalog.isPending || catalog.isError) && <QueryState pending={catalog.isPending} error={catalog.error} label="Execution catalog" retry={() => { void catalog.refetch(); }} />}
      {(profiles.isPending || profiles.isError) && <QueryState pending={profiles.isPending} error={profiles.error} label="Saved runner profiles" retry={() => { void profiles.refetch(); }} />}
      {runners.isPending || runners.isError ? <QueryState pending={runners.isPending} error={runners.error} label="Runner records" retry={() => { void runners.refetch(); }} /> : null}
      <BandLinks to="/runner-profiles" linkLabel="Open runner profiles" secondaryLink={{ to: "/runners", label: "Open Runners" }} />
    </section>

    <section className="environment-band environment-model-access" aria-labelledby="model-access-heading">
      <BandHeader id="model-access-heading" title="Model access" icon={Workflow} action={<Link className="environment-header-action" to="/settings#model-connection" aria-label="Open model connection settings">Connection settings<ArrowRight aria-hidden="true" /></Link>} />
      {catalog.isPending || catalog.isError ? <QueryState pending={catalog.isPending} error={catalog.error} label="Provider health" retry={() => { void catalog.refetch(); }} /> : null}
      {!catalog.isError && catalog.data?.ai.providers?.length ? <div className="environment-provider-list" aria-label="Provider readiness">{catalog.data.ai.providers.map(provider => {
        const health = provider.health?.state;
        const sessionExpired = provider.health?.lab_session_expires_at_ms !== undefined && provider.health.lab_session_expires_at_ms <= now;
        const tone = sessionExpired || health === "degraded" || health === "unavailable" ? "warning" : health === "ready" ? "success" : "neutral";
        return <div className="environment-provider-row" key={provider.provider_id}>
          <div className="environment-provider-identity"><strong>{providerChoiceLabel(provider, catalog.data?.ai.providers ?? [])}</strong><details><summary>Provider reference</summary><code>{provider.provider_id}</code></details></div>
          <StateBadge tone={tone}>{sessionExpired ? "Session expired" : health ? sentence(health) : "Health not reported"}</StateBadge>
          {!sessionExpired && health !== "ready" && provider.health?.message ? <p className="environment-provider-problem">{provider.health.message}</p> : null}
        </div>;
      })}</div> : catalog.isSuccess ? <p className="environment-note">{catalog.data.ai.providers ? "No providers are configured in the catalog." : "Provider health is not reported by this catalog."}</p> : null}
      <dl className="environment-model-facts" aria-label="Model authorization and saved inventory">
        <div><dt>Model usage authorization</dt><dd>
          <StateBadge tone={authorizations.isError ? "warning" : currentAuthorizations ? "info" : "neutral"}>{authorizations.isError ? authorizations.data ? "Last reported" : "Unavailable" : currentAuthorizations ? "Authorized" : authorizations.data ? "None current" : "Loading"}</StateBadge>
          <span>{authorizations.isError ? authorizations.data ? "Last reported authorization; current status could not be refreshed." : "Authorization status unavailable." : currentAuthorizations === undefined ? "Authorization status is loading." : `${currentAuthorizations} current authorizations reported.`}</span>
        </dd></div>
        <div><dt>Saved provider configurations</dt><dd>
          <StateBadge tone={catalog.isError || providers.isError ? "warning" : catalog.data && providers.data ? "info" : "neutral"}>{catalog.isError || providers.isError ? catalog.data || providers.data ? "Partial status" : "Unavailable" : catalog.data && providers.data ? "Inventory" : "Loading"}</StateBadge>
          <span>{catalog.isError || providers.isError ? catalog.data || providers.data ? "Some provider information could not be refreshed." : "Provider information could not be loaded." : catalog.data && providers.data ? "Saved configurations and provider health are reported separately." : "Provider information is loading."}</span>
          {catalog.data && providers.data ? <details className="environment-inventory-details"><summary>Inventory details</summary><span>{catalog.data.ai.providers?.length ?? "Not reported"} catalog providers · {providers.data.resources.filter(item => item.status === "active").length} active saved configurations · {providers.data.resources.length} saved configurations.</span></details> : null}
        </dd></div>
      </dl>
      {(providers.isPending || providers.isError) && <QueryState pending={providers.isPending} error={providers.error} label="Saved provider configurations" retry={() => { void providers.refetch(); }} />}
      {authorizations.isPending || authorizations.isError ? <QueryState pending={authorizations.isPending} error={authorizations.error} label="Model usage authorization" retry={() => { void authorizations.refetch(); }} /> : null}
    </section>

    </div>
    {DEMO_MODE ? <p className="environment-demo-note" role="status">Demo workspace · setup and access are not connected to enrolled environments.</p> : null}
  </div>;
}

