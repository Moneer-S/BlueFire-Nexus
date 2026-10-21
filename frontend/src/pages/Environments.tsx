import { useQuery } from "@tanstack/react-query";
import { ArrowRight, Cloud, FileLock2, Network, Server, Workflow } from "lucide-react";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { PageHeader, Badge, ErrorState, LoadingState, sentence, formatDate } from "../components/Primitives";
import { api, DEMO_MODE } from "../lib/api";
import { adSmbApi, checkedAdEnvironments, checkedAdList } from "../lib/ad-smb";
import { checkedFileAccessList, checkedFileAccessStatus, fileAccessApi } from "../lib/file-access";
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

function BandHeader({ id, title, icon: Icon, to, linkLabel, secondaryLink }: { id: string; title: string; icon: typeof Cloud; to: string; linkLabel: string; secondaryLink?: { to: string; label: string } }) {
  return <header className="environment-band-header"><span className="environment-band-icon"><Icon aria-hidden="true" /></span><h2 id={id}>{title}</h2><div className="environment-band-links"><Link to={to}>{linkLabel}<ArrowRight aria-hidden="true" /></Link>{secondaryLink ? <Link to={secondaryLink.to}>{secondaryLink.label}<ArrowRight aria-hidden="true" /></Link> : null}</div></header>;
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
    const timer = window.setTimeout(() => setNow(Date.now()), Math.min(nextExpiry - Date.now(), 2_147_483_647));
    return () => window.clearTimeout(timer);
  }, [nextExpiry]);

  const fileCurrent = fileSetup ? fileSetup.expires_at_ms > now : Boolean(fileStatus.data?.available && fileStatus.data?.enrollment && fileStatus.data.enrollment.expires_at_ms > now);
  const fileReadiness = fileStatus.isError ? undefined : !fileStatus.data ? undefined
    : !fileCurrent ? { label: "Not current", tone: "warning" as const }
      : fileStatus.data.available ? { label: "Available for review", tone: "info" as const }
        : fileSetup ? { label: "Protected setup only", tone: "warning" as const }
          : { label: "Unavailable", tone: "warning" as const };
  const currentAuthorizations = authorizations.isError ? undefined : authorizations.data?.authorizations.filter(item => item.status === "active" && item.expires_at_ms > now).length;
  const nativeCurrentlyAvailable = Boolean(adEnvironments.data?.nativeAvailable && adEnvironments.data.environments.some(row => row.available && row.environment.provenance === "runner_reported" && Date.parse(row.environment.expiresAt) > now));

  return <div className="page environments-page">
    <PageHeader eyebrow="Workspace configuration" title="Environments" description="Review saved environment setup and current access readiness. Open each workspace for its full setup and operation history." />

    <section className="environment-band" aria-labelledby="cloud-access-heading">
      <BandHeader id="cloud-access-heading" title="Cloud access" icon={Cloud} to="/s3-access" linkLabel="Open S3 access" />
      <QueryState pending={s3.isPending} error={s3.error} label="S3 enrollment" retry={() => { void s3.refetch(); }} />
      {s3.data ? s3.data.environments.length ? <div className="environment-rows">{s3.data.environments.map(row => <article className="environment-row" key={row.environment.environment_id}>
        <div><strong>{row.environment.display_name}</strong><small>{row.environment.scope.bucket} · {row.environment.scope.region}</small></div>
        <p>{s3.isError ? "Last reported environment; current status could not be refreshed." : row.problem ?? (Date.parse(row.environment.scope.expires_at) <= now ? "The enrolled environment scope has expired." : row.available ? "Enrolled environment is available for review." : "Enrolled environment is currently unavailable.")}</p>
        <StateBadge tone={s3.isError || !row.available || Date.parse(row.environment.scope.expires_at) <= now ? "warning" : "info"}>{s3.isError ? "Last reported" : Date.parse(row.environment.scope.expires_at) <= now ? "Expired" : row.available ? "Ready for review" : "Unavailable"}</StateBadge>
      </article>)}</div> : <p className="environment-empty">No enrolled S3 environments are reported.</p> : null}
      {s3.data?.problem ? <p className="environment-note">{s3.data.problem}</p> : null}
    </section>

    <section className="environment-band" aria-labelledby="file-access-heading">
      <BandHeader id="file-access-heading" title="File access" icon={FileLock2} to="/file-access" linkLabel="Open file access" />
      <QueryState pending={fileStatus.isPending} error={fileStatus.error} label="File-access setup" retry={() => { void fileStatus.refetch(); }} />
      {fileStatus.data ? <div className="environment-rows"><article className="environment-row">
        <div><strong>{fileStatus.data.platform === "macos" ? "macOS workspace" : fileSetup ? "Protected Windows setup" : "Prepared file-access session"}</strong><small>{fileSetup ? `Setup expires ${formatDate(new Date(fileSetup.expires_at_ms).toISOString())}` : fileStatus.data.enrollment ? `Enrollment expires ${formatDate(new Date(fileStatus.data.enrollment.expires_at_ms).toISOString())}` : "No current enrollment"}</small></div>
        <p>{fileStatus.isError ? "Last reported setup; current status could not be refreshed." : !fileCurrent ? fileSetup ? "Protected setup is recorded but expired." : "No current task-access setup is available." : fileStatus.data.available ? "Current setup is available for reviewed operations." : fileStatus.data.problem?.message ?? "Protected setup is recorded; task access is unavailable."}</p>
        {fileStatus.isError ? <StateBadge tone="warning">Last reported</StateBadge> : fileReadiness ? <StateBadge tone={fileReadiness.tone}>{fileReadiness.label}</StateBadge> : <StateBadge tone="neutral">Status unknown</StateBadge>}
      </article><article className="environment-row">
        <div><strong>Saved controls</strong><small>File-access work history</small></div>
        <p>{fileControls.error ? "History unavailable; see the notice below." : fileControls.isPending ? "Loading saved-control history." : `${fileControls.data?.controls.length} saved ${fileControls.data?.controls.length === 1 ? "control" : "controls"}.`}</p>
        <StateBadge tone={fileControls.error ? "warning" : fileControls.isPending ? "neutral" : "info"}>{fileControls.error ? "Unavailable" : fileControls.isPending ? "Loading" : "History"}</StateBadge>
      </article></div> : null}
      {fileControls.error ? <ErrorState title="Saved file-access history unavailable" error={fileControls.error} retry={() => { void fileControls.refetch(); }} /> : null}
    </section>

    <section className="environment-band" aria-labelledby="directory-access-heading">
      <BandHeader id="directory-access-heading" title="Directory access" icon={Network} to="/ad-smb" linkLabel="Open AD share access" />
      <QueryState pending={adEnvironments.isPending} error={adEnvironments.error} label="AD environment readiness" retry={() => { void adEnvironments.refetch(); }} />
      {adEnvironments.data ? <>
        <div className="environment-rows">{adEnvironments.data.environments.map(row => <article className="environment-row" key={row.environment.id}>
          <div><strong>{row.environment.domain} · {row.environment.share}</strong><small>{sentence(row.environment.provenance)} environment · expires {formatDate(row.environment.expiresAt)}</small></div>
          <p>{adEnvironments.isError ? "Last reported environment; current status could not be refreshed." : row.readiness.problem ? (row.readiness.problem === "native_admission_unavailable" ? "Native admission is unavailable." : sentence(row.readiness.problem)) : row.available && Date.parse(row.environment.expiresAt) > now ? "Member and client channels are ready for review." : Date.parse(row.environment.expiresAt) <= now ? "The enrolled environment scope has expired." : "Environment is not ready for review."}</p>
          <StateBadge tone={adEnvironments.isError || !row.available || Date.parse(row.environment.expiresAt) <= now ? "warning" : "info"}>{adEnvironments.isError ? "Last reported" : Date.parse(row.environment.expiresAt) <= now ? "Expired" : row.available ? "Ready for review" : "Unavailable"}</StateBadge>
        </article>)}{!adEnvironments.data.environments.length ? <p className="environment-empty">No enrolled AD environments are reported.</p> : null}</div>
        <p className="environment-note">Native execution: {adEnvironments.isError ? "last reported status could not be refreshed" : nativeCurrentlyAvailable ? "reported available for an enrolled environment" : "not reported available"}. Environment review readiness and workflow dispatch are separate.</p>
      </> : null}
      <QueryState pending={adWorkflows.isPending} error={adWorkflows.error} label="AD workflow history" retry={() => { void adWorkflows.refetch(); }} />
      {adWorkflows.data ? <p className="environment-note">{adWorkflows.isError ? "Last reported" : "Saved"} workflows: {adWorkflows.data.length}; pending operations: {adWorkflows.data.filter(row => row.pending !== null).length}. Workflow history is reported separately from environment readiness.</p> : null}
    </section>

    <section className="environment-band" aria-labelledby="execution-heading">
      <BandHeader id="execution-heading" title="Execution configuration" icon={Server} to="/runner-profiles" linkLabel="Open runner profiles" secondaryLink={{ to: "/runners", label: "Open Runners" }} />
      <div className="environment-rows">
        <article className="environment-row"><div><strong>Runner profiles</strong><small>Catalog and saved profile lifecycle</small></div>
          <p>{catalog.isError || profiles.isError ? catalog.data || profiles.data ? "Last reported inventory; one or more sources could not be refreshed." : "Profile inventory could not be loaded." : catalog.data && profiles.data ? `${catalog.data.runner_profiles.length} catalog profiles · ${profiles.data.resources.filter(item => item.status === "active").length} active saved profiles · ${profiles.data.resources.length} saved profile records.` : "Profile inventory is loading."}</p>
          <StateBadge tone={catalog.isError || profiles.isError ? "warning" : "info"}>{catalog.isError || profiles.isError ? catalog.data || profiles.data ? "Partial status" : "Unavailable" : catalog.data && profiles.data ? "Inventory" : "Loading"}</StateBadge>
        </article>
        <article className="environment-row"><div><strong>Runner records</strong><small>Saved references do not establish connectivity</small></div>
          <p>{runners.isError ? runners.data ? "Last reported inventory; current records could not be refreshed." : "Runner-record inventory could not be loaded." : runners.data ? `${runners.data.resources.length} saved ${runners.data.resources.length === 1 ? "record" : "records"}; runner authentication has not been checked here.` : "Runner-record inventory is loading."}</p>
          <StateBadge tone={runners.isError ? "warning" : "neutral"}>{runners.isError ? runners.data ? "Last reported" : "Unavailable" : runners.data ? "Inventory only" : "Loading"}</StateBadge>
        </article>
      </div>
      {(catalog.isPending || catalog.isError) && <QueryState pending={catalog.isPending} error={catalog.error} label="Execution catalog" retry={() => { void catalog.refetch(); }} />}
      {(profiles.isPending || profiles.isError) && <QueryState pending={profiles.isPending} error={profiles.error} label="Saved runner profiles" retry={() => { void profiles.refetch(); }} />}
      {runners.isPending || runners.isError ? <QueryState pending={runners.isPending} error={runners.error} label="Runner records" retry={() => { void runners.refetch(); }} /> : null}
    </section>

    <section className="environment-band" aria-labelledby="model-access-heading">
      <BandHeader id="model-access-heading" title="Model access" icon={Workflow} to="/settings#model-connection" linkLabel="Open model connection settings" />
      <div className="environment-rows">
        <article className="environment-row"><div><strong>Configured providers</strong><small>Catalog readiness and saved activation are separate</small></div>
          <p>{catalog.isError || providers.isError ? catalog.data || providers.data ? "Last reported inventory; one or more sources could not be refreshed." : "Provider inventory could not be loaded." : catalog.data && providers.data ? `${catalog.data.ai.providers?.length ?? "Not reported"} catalog providers · ${providers.data.resources.filter(item => item.status === "active").length} active saved configurations · ${providers.data.resources.length} saved configurations.` : "Provider inventory is loading."}</p>
          <StateBadge tone={catalog.isError || providers.isError ? "warning" : catalog.data && providers.data ? "info" : "neutral"}>{catalog.isError || providers.isError ? catalog.data || providers.data ? "Partial status" : "Unavailable" : catalog.data && providers.data ? "Inventory" : "Loading"}</StateBadge>
        </article>
        <article className="environment-row"><div><strong>Model usage authorization</strong><small>Authorization does not test provider connectivity</small></div>
          <p>{authorizations.isError ? authorizations.data ? "Last reported authorization; current status could not be refreshed." : "Authorization status unavailable." : currentAuthorizations === undefined ? "Authorization status is loading." : `${currentAuthorizations} current authorizations reported.`}</p>
          <StateBadge tone={authorizations.isError ? "warning" : currentAuthorizations ? "info" : "neutral"}>{authorizations.isError ? authorizations.data ? "Last reported" : "Unavailable" : currentAuthorizations ? "Authorized" : authorizations.data ? "None current" : "Loading"}</StateBadge>
        </article>
      </div>
      {(providers.isPending || providers.isError) && <QueryState pending={providers.isPending} error={providers.error} label="Saved provider configurations" retry={() => { void providers.refetch(); }} />}
      {authorizations.isPending || authorizations.isError ? <QueryState pending={authorizations.isPending} error={authorizations.error} label="Model usage authorization" retry={() => { void authorizations.refetch(); }} /> : null}
      {!catalog.isError && catalog.data?.ai.providers?.length ? <div className="environment-provider-list" aria-label="Provider readiness">{catalog.data.ai.providers.map(provider => {
        const health = provider.health?.state;
        const sessionExpired = provider.health?.lab_session_expires_at_ms !== undefined && provider.health.lab_session_expires_at_ms <= now;
        const tone = sessionExpired || health === "degraded" || health === "unavailable" ? "warning" : health === "ready" ? "success" : "neutral";
        return <div className="environment-provider-row" key={provider.provider_id}><strong>{provider.provider_id}</strong><span>{provider.model}</span><StateBadge tone={tone}>{sessionExpired ? "Session expired" : health ? sentence(health) : "Health not reported"}</StateBadge></div>;
      })}</div> : null}
    </section>

    {DEMO_MODE ? <p className="environment-demo-note" role="status">Demo workspace · setup and access are not connected to enrolled environments.</p> : null}
  </div>;
}

