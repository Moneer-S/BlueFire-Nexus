import * as Dialog from "@radix-ui/react-dialog";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArchiveX,
  Box,
  CheckCircle2,
  FileKey2,
  FileUp,
  KeyRound,
  PackageCheck,
  Power,
  RefreshCw,
  ShieldAlert,
  Trash2,
  X,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { api } from "../lib/api";
import type {
  ActionPackageActivationEvent,
  ActionPackageCatalog,
  ActionPackageInstallation,
  ActionPackagePublisherTrust,
  RunnerProfile,
} from "../types";
import {
  Badge,
  Button,
  Callout,
  DataList,
  EmptyState,
  ErrorState,
  Field,
  LoadingState,
  PageHeader,
  Panel,
  PanelHeader,
  Stat,
  formatDate,
  sentence,
} from "../components/Primitives";

type PackageOperation = "activate" | "deactivate" | "remove";
const MAX_SIGNED_ENVELOPE_BYTES = 1_048_576;

type LifecycleVariables = {
  action: PackageOperation;
  package: ActionPackageInstallation;
  actor: string;
  reason: string;
  runnerProfileId?: string;
  catalog: ActionPackageCatalog;
};

type TrustVariables = {
  action: "suspend" | "revoke";
  publisher: ActionPackagePublisherTrust;
  actor: string;
  reason: string;
};

function statusTone(status: string) {
  if (status === "active" || status === "trusted") return "success" as const;
  if (status === "installed") return "info" as const;
  if (status === "suspended" || status === "superseded") return "warning" as const;
  if (status === "revoked" || status === "removed") return "danger" as const;
  return "neutral" as const;
}

function stringValue(value: unknown, fallback = "Not recorded") {
  return typeof value === "string" && value ? value : fallback;
}

function packageActionLabel(item: ActionPackageInstallation) {
  return item.active_version && item.active_version !== item.version
    ? `Upgrade to ${item.version}`
    : `Activate ${item.version}`;
}

function identityLabel(item: ActionPackageInstallation) {
  return `${item.package_id}@${item.version}`;
}

export function ActionPackagesPage() {
  const queryClient = useQueryClient();
  const inventoryQuery = useQuery({ queryKey: ["action-packages"], queryFn: api.actionPackages });
  const catalogQuery = useQuery({ queryKey: ["catalog"], queryFn: api.catalog });
  const [notice, setNotice] = useState<string>();

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ["action-packages"] });
    void queryClient.invalidateQueries({ queryKey: ["catalog"] });
  };

  const installMutation = useMutation({
    mutationFn: ({ envelope, installedBy }: { envelope: Record<string, unknown>; installedBy: string }) => api.installActionPackage(envelope, installedBy),
    onSuccess: ({ package: item }) => {
      setNotice(`${identityLabel(item)} passed signature and immutable-package verification. Activation is still required.`);
      refresh();
    },
  });
  const enrollmentMutation = useMutation({
    mutationFn: api.trustActionPackagePublisher,
    onSuccess: ({ publisher }) => {
      setNotice(`${publisher.publisher_id}/${publisher.key_id} is enrolled in local publisher trust.`);
      refresh();
    },
  });
  const lifecycleMutation = useMutation({
    mutationFn: async (variables: LifecycleVariables) => {
      const { package: item, actor, reason, catalog } = variables;
      if (variables.action === "activate") {
        return api.activateActionPackage(item.package_id, item.version, variables.runnerProfileId ?? "", actor, reason);
      }
      const identity = {
        package_digest: item.package_digest,
        expected_catalog_generation: catalog.generation,
        expected_catalog_digest: catalog.catalog_digest,
      };
      return variables.action === "deactivate"
        ? api.deactivateActionPackage(item.package_id, item.version, identity, actor, reason)
        : api.removeActionPackage(item.package_id, item.version, identity, actor, reason);
    },
    onSuccess: (_result, variables) => {
      const verb = variables.action === "activate"
        ? variables.package.active_version ? "upgraded" : "activated"
        : variables.action === "deactivate" ? "deactivated" : "removed";
      setNotice(`${identityLabel(variables.package)} was ${verb}; the catalog inventory has been refreshed.`);
      refresh();
    },
  });
  const trustMutation = useMutation({
    mutationFn: (variables: TrustVariables) => api.transitionActionPackagePublisher(
      variables.publisher.publisher_id,
      variables.publisher.key_id,
      variables.action,
      variables.actor,
      variables.reason,
    ),
    onSuccess: (_result, variables) => {
      setNotice(`${variables.publisher.publisher_id}/${variables.publisher.key_id} trust is now ${variables.action === "suspend" ? "suspended" : "revoked"}. Any active packages signed by that key were deactivated.`);
      refresh();
    },
  });

  if (inventoryQuery.isPending) return <LoadingState label="Loading signed action packages" />;
  if (inventoryQuery.isError) return <ErrorState title="Action package inventory unavailable" error={inventoryQuery.error} retry={() => inventoryQuery.refetch()} />;

  const inventory = inventoryQuery.data;
  const executeProfiles = (catalogQuery.data?.runner_profiles ?? []).filter((profile) => profile.mode === "execute");
  const activeCount = inventory.catalog.packages.length;
  const trustedCount = inventory.publishers.filter((item) => item.trust_state === "trusted").length;
  const mutationError = installMutation.error ?? enrollmentMutation.error ?? lifecycleMutation.error ?? trustMutation.error;

  return <div className="page action-packages-page">
    <PageHeader
      eyebrow="Signed extension control"
      title="Action packages"
      description="Install immutable signed versions, bind them to an authenticated runner inventory, and manage the exact catalog generation operators approve."
      actions={<>
        <PublisherEnrollmentDialog pending={enrollmentMutation.isPending} onEnroll={(enrollment) => enrollmentMutation.mutateAsync(enrollment).then(() => undefined)} />
        <PackageImportDialog pending={installMutation.isPending} onInstall={(envelope, installedBy) => installMutation.mutateAsync({ envelope, installedBy }).then(() => undefined)} />
      </>}
    />

    {notice ? <Callout tone="success" title="Action package inventory updated"><span aria-live="polite">{notice}</span></Callout> : null}
    {mutationError ? <Callout tone="danger" title="Lifecycle action refused">{mutationError instanceof Error ? mutationError.message : "The local control plane refused the action."}</Callout> : null}
    {catalogQuery.isError ? <Callout tone="warning" title="Runner profiles unavailable">Installed package state remains visible, but activation is disabled until Execute profiles can be loaded.</Callout> : null}

    <div className="stat-grid package-stat-grid">
      <Stat label="Active generation" value={inventory.catalog.generation} detail="Append-only catalog sequence" tone="info" />
      <Stat label="Active packages" value={activeCount} detail={`${inventory.packages.length} installed heads`} tone={activeCount ? "success" : "info"} />
      <Stat label="Trusted publishers" value={trustedCount} detail={`${inventory.publishers.length} enrolled keys`} tone={trustedCount ? "success" : "warning"} />
      <Stat label="Lifecycle events" value={inventory.activation_events.length} detail="Immutable activation history" tone="info" />
    </div>

    <Callout tone="warning" title="Signed packages select reviewed native behavior; they do not load executable code">
      BlueFire verifies the signature, immutable digests, compatibility, publisher trust, and exact alias-to-opcode binding. Activation can only select already compiled and reviewed runner opcodes; package bytes, scripts, and entry points are never executed.
    </Callout>

    <Panel className="catalog-authority-panel">
      <PanelHeader eyebrow="Current authorization boundary" title={`Catalog generation ${inventory.catalog.generation}`} detail="Every deactivation and removal is compare-and-swapped against this exact identity." actions={<Badge tone="success" dot>Audited snapshot</Badge>} />
      <div className="catalog-authority-body">
        <DataList items={[
          { label: "Catalog digest", value: <code>{inventory.catalog.catalog_digest}</code> },
          { label: "Authority digest", value: inventory.catalog.authority_digest ? <code>{inventory.catalog.authority_digest}</code> : "Not exposed" },
          { label: "Execution boundary", value: <Badge tone="warning">{sentence(inventory.execution_boundary ?? "signed-reviewed-opcodes-only")}</Badge> },
        ]} />
      </div>
    </Panel>

    <Panel>
      <PanelHeader eyebrow="Installed heads" title="Verified package inventory" detail="Each card is the highest installed immutable SemVer for one package ID. An older active version remains identified until an explicit upgrade." actions={<Button size="small" variant="ghost" onClick={() => inventoryQuery.refetch()} disabled={inventoryQuery.isFetching}><RefreshCw className={inventoryQuery.isFetching ? "spin" : ""} />Refresh</Button>} />
      {inventory.packages.length ? <div className="package-grid">
        {inventory.packages.map((item) => <PackageCard
          key={`${item.package_id}:${item.version}:${item.package_digest}`}
          item={item}
          catalog={inventory.catalog}
          profiles={executeProfiles}
          busy={lifecycleMutation.isPending}
          onOperation={(variables) => lifecycleMutation.mutateAsync(variables).then(() => undefined)}
        />)}
      </div> : <EmptyState icon={<Box />} title="No signed packages installed" description="Enroll a publisher key, then import a signed JSON envelope. Installation never activates runner behavior automatically." />}
    </Panel>

    <div className="package-lower-grid">
      <PublisherPanel
        publishers={inventory.publishers}
        catalog={inventory.catalog}
        busy={trustMutation.isPending}
        onTransition={(variables) => trustMutation.mutateAsync(variables).then(() => undefined)}
      />
      <ActivationHistory events={inventory.activation_events} />
    </div>
  </div>;
}

function PackageCard({ item, catalog, profiles, busy, onOperation }: {
  item: ActionPackageInstallation;
  catalog: ActionPackageCatalog;
  profiles: RunnerProfile[];
  busy: boolean;
  onOperation: (variables: LifecycleVariables) => Promise<void>;
}) {
  const canActivate = !item.active && item.status !== "removed" && item.trust.state === "trusted";
  return <article className="package-card">
    <header>
      <span className={`registry-icon ${item.active ? "tier-safe" : item.status === "removed" ? "tier-restricted" : "tier-controlled"}`}><PackageCheck aria-hidden="true" /></span>
      <div>
        <p className="eyebrow">{item.publisher_id}</p>
        <h3>{item.package_id}</h3>
        <span className="package-version">Version {item.version}</span>
      </div>
      <div className="row-badges"><Badge tone={statusTone(item.status)}>{sentence(item.status)}</Badge><Badge tone={statusTone(item.trust.state)}>{sentence(item.trust.state)} signer</Badge></div>
    </header>
    {item.active_version && item.active_version !== item.version ? <Callout tone="warning" title={`Upgrade available from ${item.active_version}`}>The older version remains active until this exact installed head passes runner inventory verification.</Callout> : null}
    <DataList items={[
      { label: "Immutable digest", value: <code>{item.package_digest}</code> },
      { label: "Content digest", value: <code>{item.content_digest}</code> },
      { label: "Signing key", value: <span><code>{item.key_id}</code><small className="block-detail">{item.signer_fingerprint}</small></span> },
      { label: "Platforms", value: item.manifest.platforms.join(", ") || "None" },
      { label: "Capabilities", value: item.manifest.capabilities.join(", ") || "None" },
      { label: "Safety tiers", value: item.manifest.safety_tiers.map((tier) => <Badge key={tier} tone={tier === "restricted" ? "danger" : tier === "controlled" ? "warning" : "success"}>{tier}</Badge>) },
      { label: "License", value: <span>{item.manifest.license.spdx_id}<small className="block-detail">{item.manifest.license.notice}</small></span> },
      { label: "Installed", value: `${formatDate(item.installed_at)} by ${item.installed_by}` },
      { label: "Active identity", value: item.active ? <span>Generation {item.active_generation}<small className="block-detail">{item.active_version}</small></span> : item.active_version ? `Version ${item.active_version} remains active` : "Not active" },
    ]} />
    <div className="package-chip-row">
      <Badge tone="neutral">{item.manifest.behavior_ids.length} behaviors</Badge>
      <Badge tone="neutral">{item.manifest.action_ids.length} actions</Badge>
    </div>
    <footer>
      {canActivate ? <PackageOperationDialog item={item} operation="activate" catalog={catalog} profiles={profiles} pending={busy} onConfirm={onOperation} disabled={!profiles.length} /> : null}
      {item.active ? <PackageOperationDialog item={item} operation="deactivate" catalog={catalog} profiles={profiles} pending={busy} onConfirm={onOperation} /> : null}
      {item.status !== "removed" ? <PackageOperationDialog item={item} operation="remove" catalog={catalog} profiles={profiles} pending={busy} onConfirm={onOperation} /> : null}
      {!canActivate && !item.active && item.status !== "removed" ? <span className="package-action-note"><ShieldAlert aria-hidden="true" />Activation requires a currently trusted signer.</span> : null}
    </footer>
  </article>;
}

function PackageOperationDialog({ item, operation, catalog, profiles, pending, onConfirm, disabled = false }: {
  item: ActionPackageInstallation;
  operation: PackageOperation;
  catalog: ActionPackageCatalog;
  profiles: RunnerProfile[];
  pending: boolean;
  onConfirm: (variables: LifecycleVariables) => Promise<void>;
  disabled?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [actor, setActor] = useState("");
  const [reason, setReason] = useState("");
  const [profileId, setProfileId] = useState(profiles[0]?.id ?? "");
  const [confirmed, setConfirmed] = useState(false);
  const [typedIdentity, setTypedIdentity] = useState("");
  const [localError, setLocalError] = useState<string>();
  useEffect(() => {
    if (!profileId && profiles[0]) setProfileId(profiles[0].id);
  }, [profileId, profiles]);
  const label = operation === "activate" ? packageActionLabel(item) : operation === "deactivate" ? `Deactivate ${item.version}` : `Remove ${item.version}`;
  const irreversible = operation === "remove";
  const valid = actor.trim() && reason.trim() && confirmed && (operation !== "activate" || profileId) && (!irreversible || typedIdentity === identityLabel(item));
  return <Dialog.Root open={open} onOpenChange={(next) => { setOpen(next); if (next) { setConfirmed(false); setTypedIdentity(""); setLocalError(undefined); } }}>
    <Dialog.Trigger asChild><Button size="small" variant={operation === "remove" ? "danger" : operation === "activate" ? "primary" : "secondary"} disabled={disabled || pending}>{operation === "activate" ? <Power /> : operation === "deactivate" ? <ArchiveX /> : <Trash2 />}{label}</Button></Dialog.Trigger>
    <Dialog.Portal>
      <Dialog.Overlay className="dialog-overlay" />
      <Dialog.Content className="dialog-content package-confirm-dialog">
        <div><Dialog.Title>{label}</Dialog.Title><Dialog.Description>{operation === "activate" ? "Verify this immutable package against one authenticated Execute runner profile, then publish a new catalog generation." : operation === "deactivate" ? "Remove this package from the active catalog without deleting its immutable installed bytes." : "Tombstone this installed version while retaining the immutable bytes required for historical audit."}</Dialog.Description></div>
        <Dialog.Close asChild><button className="dialog-close" aria-label="Close dialog"><X /></button></Dialog.Close>
        <form className="dialog-form" onSubmit={async (event) => {
          event.preventDefault();
          setLocalError(undefined);
          try {
            await onConfirm({ action: operation, package: item, actor: actor.trim(), reason: reason.trim(), runnerProfileId: operation === "activate" ? profileId : undefined, catalog });
            setOpen(false);
          } catch (error) {
            setLocalError(error instanceof Error ? error.message : "The lifecycle action was refused.");
          }
        }}>
          <div className="exact-identity-box" aria-label="Exact lifecycle identity">
            <strong>{identityLabel(item)}</strong>
            <span>Package digest</span><code>{item.package_digest}</code>
            <span>Catalog generation</span><code>{catalog.generation}</code>
            <span>Catalog digest</span><code>{catalog.catalog_digest}</code>
          </div>
          {operation === "activate" ? <Field label="Authenticated Execute runner profile" hint="Activation verifies the package against this runner's current platform, version, identity, and reviewed opcode inventory."><select aria-label="Authenticated Execute runner profile" value={profileId} onChange={(event) => setProfileId(event.target.value)} required disabled={!profiles.length}><option value="" disabled>Select an Execute profile</option>{profiles.map((profile) => <option value={profile.id} key={profile.id}>{profile.id} · {profile.platforms.join(", ")}</option>)}</select></Field> : null}
          <Field label="Operator"><input value={actor} onChange={(event) => setActor(event.target.value)} required autoComplete="off" /></Field>
          <Field label="Reason"><textarea rows={3} value={reason} onChange={(event) => setReason(event.target.value)} required placeholder="Why is this exact lifecycle transition required?" /></Field>
          {irreversible ? <Field label={`Type ${identityLabel(item)} to confirm`} hint="Removal cannot restore the installed head; historical audit bytes remain retained."><input value={typedIdentity} onChange={(event) => setTypedIdentity(event.target.value)} autoComplete="off" required /></Field> : null}
          <label className="check-row package-confirm-check"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /><span>I confirm this exact package version and catalog snapshot. A stale catalog identity must be refused without effects.</span></label>
          {localError ? <Callout tone="danger" title="Action refused">{localError}</Callout> : null}
          <div className="dialog-actions"><Dialog.Close asChild><Button type="button" variant="ghost">Cancel</Button></Dialog.Close><Button type="submit" variant={irreversible ? "danger" : "primary"} disabled={!valid || pending}>{pending ? "Verifying…" : operation === "activate" ? "Verify & publish generation" : operation === "deactivate" ? "Confirm deactivation" : "Confirm immutable removal"}</Button></div>
        </form>
      </Dialog.Content>
    </Dialog.Portal>
  </Dialog.Root>;
}

function PackageImportDialog({ pending, onInstall }: { pending: boolean; onInstall: (envelope: Record<string, unknown>, installedBy: string) => Promise<void> }) {
  const [open, setOpen] = useState(false);
  const [envelope, setEnvelope] = useState<Record<string, unknown>>();
  const [fileName, setFileName] = useState("");
  const [installedBy, setInstalledBy] = useState("");
  const [parseError, setParseError] = useState<string>();
  const [submitError, setSubmitError] = useState<string>();
  const manifest = envelope?.manifest && typeof envelope.manifest === "object" && !Array.isArray(envelope.manifest) ? envelope.manifest as Record<string, unknown> : undefined;
  const readFile = async (file?: File) => {
    setEnvelope(undefined); setFileName(file?.name ?? ""); setParseError(undefined); setSubmitError(undefined);
    if (!file) return;
    try {
      if (file.size > MAX_SIGNED_ENVELOPE_BYTES) {
        throw new Error("The signed envelope exceeds the 1 MiB browser/API limit.");
      }
      const parsed = JSON.parse(await file.text()) as unknown;
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("The file root must be a signed envelope object.");
      const record = parsed as Record<string, unknown>;
      if (!record.manifest || !record.integrity || !record.signature) throw new Error("The envelope must contain manifest, integrity, and signature records.");
      setEnvelope(record);
    } catch (error) {
      setParseError(error instanceof Error ? error.message : "The selected file is not valid JSON.");
    }
  };
  return <Dialog.Root open={open} onOpenChange={setOpen}>
    <Dialog.Trigger asChild><Button variant="primary"><FileUp />Import signed package</Button></Dialog.Trigger>
    <Dialog.Portal><Dialog.Overlay className="dialog-overlay" /><Dialog.Content className="dialog-content">
      <div><Dialog.Title>Import signed package</Dialog.Title><Dialog.Description>Select a JSON envelope from disk. BlueFire independently verifies the enrolled publisher key, Ed25519 signature, canonical bytes, manifest, and immutable digest before installation.</Dialog.Description></div>
      <Dialog.Close asChild><button className="dialog-close" aria-label="Close dialog"><X /></button></Dialog.Close>
      <form className="dialog-form" onSubmit={async (event) => {
        event.preventDefault(); if (!envelope) return; setSubmitError(undefined);
        try { await onInstall(envelope, installedBy.trim()); setOpen(false); }
        catch (error) { setSubmitError(error instanceof Error ? error.message : "The signed package was refused."); }
      }}>
        <Field label="Signed envelope file" hint="JSON only. Package content is never executed in the browser or loaded as native code."><input aria-label="Signed envelope file" type="file" accept="application/json,.json" onChange={(event) => void readFile(event.target.files?.[0])} /></Field>
        {parseError ? <Callout tone="danger" title="Envelope could not be read">{parseError}</Callout> : null}
        {envelope ? <Callout tone="success" title="Envelope ready for independent verification"><span className="import-preview"><strong>{stringValue(manifest?.package_id, fileName)}</strong><span>Version {stringValue(manifest?.version)}</span><span>Publisher {stringValue((manifest?.provenance as Record<string, unknown> | undefined)?.publisher_id)}</span><span>The file has only been parsed for this preview; signature and compatibility are verified by the control plane on import.</span></span></Callout> : null}
        <Field label="Installed by"><input value={installedBy} onChange={(event) => setInstalledBy(event.target.value)} required autoComplete="off" placeholder="Operator identity" /></Field>
        {submitError ? <Callout tone="danger" title="Installation refused">{submitError}</Callout> : null}
        <div className="dialog-actions"><Dialog.Close asChild><Button type="button" variant="ghost">Cancel</Button></Dialog.Close><Button type="submit" variant="primary" disabled={!envelope || !installedBy.trim() || pending}>{pending ? "Verifying signature…" : "Verify & install inactive"}</Button></div>
      </form>
    </Dialog.Content></Dialog.Portal>
  </Dialog.Root>;
}

function PublisherEnrollmentDialog({ pending, onEnroll }: { pending: boolean; onEnroll: (enrollment: { publisher_id: string; key_id: string; public_key: string; provenance: Record<string, unknown>; trusted_by: string }) => Promise<void> }) {
  const [open, setOpen] = useState(false);
  const [publisherId, setPublisherId] = useState(""); const [keyId, setKeyId] = useState(""); const [publicKey, setPublicKey] = useState("");
  const [source, setSource] = useState(""); const [reference, setReference] = useState(""); const [revision, setRevision] = useState(""); const [trustedBy, setTrustedBy] = useState(""); const [error, setError] = useState<string>();
  return <Dialog.Root open={open} onOpenChange={setOpen}>
    <Dialog.Trigger asChild><Button><KeyRound />Enroll publisher key</Button></Dialog.Trigger>
    <Dialog.Portal><Dialog.Overlay className="dialog-overlay" /><Dialog.Content className="dialog-content publisher-dialog">
      <div><Dialog.Title>Enroll publisher key</Dialog.Title><Dialog.Description>Create one immutable local publisher/key binding with operator-reviewed provenance. Trusting a key does not install or activate a package.</Dialog.Description></div>
      <Dialog.Close asChild><button className="dialog-close" aria-label="Close dialog"><X /></button></Dialog.Close>
      <form className="dialog-form" onSubmit={async (event) => {
        event.preventDefault(); setError(undefined);
        try { await onEnroll({ publisher_id: publisherId.trim(), key_id: keyId.trim(), public_key: publicKey.trim(), provenance: { source: source.trim(), reference: reference.trim(), revision: revision.trim() }, trusted_by: trustedBy.trim() }); setOpen(false); }
        catch (caught) { setError(caught instanceof Error ? caught.message : "Publisher trust enrollment was refused."); }
      }}>
        <div className="two-column"><Field label="Publisher ID"><input value={publisherId} onChange={(event) => setPublisherId(event.target.value)} required autoComplete="off" /></Field><Field label="Key ID"><input value={keyId} onChange={(event) => setKeyId(event.target.value)} required autoComplete="off" /></Field></div>
        <Field label="Ed25519 public key" hint="Use the canonical public-key encoding supplied through your reviewed publisher channel."><textarea rows={3} value={publicKey} onChange={(event) => setPublicKey(event.target.value)} required spellCheck={false} /></Field>
        <fieldset className="provenance-fields"><legend>Reviewed provenance</legend><Field label="Source"><input value={source} onChange={(event) => setSource(event.target.value)} required /></Field><Field label="Immutable reference"><input value={reference} onChange={(event) => setReference(event.target.value)} required /></Field><Field label="Revision"><input value={revision} onChange={(event) => setRevision(event.target.value)} required /></Field></fieldset>
        <Field label="Trusted by"><input value={trustedBy} onChange={(event) => setTrustedBy(event.target.value)} required autoComplete="off" placeholder="Operator identity" /></Field>
        <Callout tone="warning" title="Trust is local and exact">The publisher ID, key ID, public key, and provenance are immutable after enrollment. Suspension deactivates dependent packages; revocation is permanent.</Callout>
        {error ? <Callout tone="danger" title="Enrollment refused">{error}</Callout> : null}
        <div className="dialog-actions"><Dialog.Close asChild><Button type="button" variant="ghost">Cancel</Button></Dialog.Close><Button type="submit" variant="primary" disabled={pending}>{pending ? "Enrolling…" : "Enroll exact key"}</Button></div>
      </form>
    </Dialog.Content></Dialog.Portal>
  </Dialog.Root>;
}

function PublisherPanel({ publishers, catalog, busy, onTransition }: { publishers: ActionPackagePublisherTrust[]; catalog: ActionPackageCatalog; busy: boolean; onTransition: (variables: TrustVariables) => Promise<void> }) {
  return <Panel className="publisher-panel"><PanelHeader eyebrow="Local trust roots" title="Publisher keys" detail="Trust is an explicit operator decision bound to one Ed25519 key and its reviewed provenance." actions={<Badge tone={publishers.some((item) => item.trust_state === "trusted") ? "success" : "warning"}>{publishers.filter((item) => item.trust_state === "trusted").length} trusted</Badge>} />
    {publishers.length ? <div className="publisher-list">{publishers.map((publisher) => <article key={`${publisher.publisher_id}:${publisher.key_id}`}>
      <header><span className="registry-icon"><FileKey2 /></span><div><strong>{publisher.publisher_id}</strong><code>{publisher.key_id}</code></div><Badge tone={statusTone(publisher.trust_state)}>{sentence(publisher.trust_state)}</Badge></header>
      <DataList items={[
        { label: "Fingerprint", value: <code>{publisher.key_fingerprint}</code> },
        { label: "Trusted by", value: `${publisher.trusted_by} · ${formatDate(publisher.trusted_at)}` },
        { label: "Provenance", value: <span>{stringValue(publisher.provenance.source)}<small className="block-detail">{stringValue(publisher.provenance.reference)} · {stringValue(publisher.provenance.revision)}</small></span> },
      ]} />
      {publisher.trust_state !== "revoked" ? <footer>{publisher.trust_state === "trusted" ? <PublisherTransitionDialog publisher={publisher} action="suspend" catalog={catalog} pending={busy} onConfirm={onTransition} /> : null}<PublisherTransitionDialog publisher={publisher} action="revoke" catalog={catalog} pending={busy} onConfirm={onTransition} /></footer> : <p className="package-action-note"><ShieldAlert />This key is permanently revoked.</p>}
    </article>)}</div> : <EmptyState icon={<KeyRound />} title="No publisher keys enrolled" description="Enroll a reviewed publisher key before importing its signed package envelopes." />}
  </Panel>;
}

function PublisherTransitionDialog({ publisher, action, catalog, pending, onConfirm }: { publisher: ActionPackagePublisherTrust; action: "suspend" | "revoke"; catalog: ActionPackageCatalog; pending: boolean; onConfirm: (variables: TrustVariables) => Promise<void> }) {
  const [open, setOpen] = useState(false); const [actor, setActor] = useState(""); const [reason, setReason] = useState(""); const [confirmed, setConfirmed] = useState(false); const [error, setError] = useState<string>();
  return <Dialog.Root open={open} onOpenChange={(next) => { setOpen(next); if (next) { setConfirmed(false); setError(undefined); } }}>
    <Dialog.Trigger asChild><Button size="small" variant={action === "revoke" ? "danger" : "secondary"}>{action === "revoke" ? <ShieldAlert /> : <ArchiveX />}{sentence(action)} trust</Button></Dialog.Trigger>
    <Dialog.Portal><Dialog.Overlay className="dialog-overlay" /><Dialog.Content className="dialog-content">
      <div><Dialog.Title>{sentence(action)} publisher trust</Dialog.Title><Dialog.Description>{action === "revoke" ? "Revocation is permanent and deactivates every package signed by this exact key." : "Suspension deactivates every package signed by this exact key until a separately supported recovery workflow is completed."}</Dialog.Description></div>
      <Dialog.Close asChild><button className="dialog-close" aria-label="Close dialog"><X /></button></Dialog.Close>
      <form className="dialog-form" onSubmit={async (event) => { event.preventDefault(); setError(undefined); try { await onConfirm({ action, publisher, actor: actor.trim(), reason: reason.trim() }); setOpen(false); } catch (caught) { setError(caught instanceof Error ? caught.message : "The trust transition was refused."); } }}>
        <div className="exact-identity-box"><strong>{publisher.publisher_id}/{publisher.key_id}</strong><span>Key fingerprint</span><code>{publisher.key_fingerprint}</code><span>Current catalog</span><code>Generation {catalog.generation} · {catalog.catalog_digest}</code></div>
        <Field label="Operator"><input value={actor} onChange={(event) => setActor(event.target.value)} required autoComplete="off" /></Field><Field label="Reason"><textarea rows={3} value={reason} onChange={(event) => setReason(event.target.value)} required /></Field>
        <label className="check-row package-confirm-check"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /><span>I understand dependent active packages are deactivated and the catalog generation changes.</span></label>
        {error ? <Callout tone="danger" title="Trust transition refused">{error}</Callout> : null}
        <div className="dialog-actions"><Dialog.Close asChild><Button type="button" variant="ghost">Cancel</Button></Dialog.Close><Button type="submit" variant={action === "revoke" ? "danger" : "primary"} disabled={!actor.trim() || !reason.trim() || !confirmed || pending}>{pending ? "Applying…" : `Confirm ${action}`}</Button></div>
      </form>
    </Dialog.Content></Dialog.Portal>
  </Dialog.Root>;
}

function ActivationHistory({ events }: { events: ActionPackageActivationEvent[] }) {
  const ordered = useMemo(() => [...events].sort((left, right) => right.generation - left.generation).slice(0, 12), [events]);
  return <Panel className="activation-history-panel"><PanelHeader eyebrow="Append-only audit" title="Catalog history" detail="Recent activation and deactivation generations, in newest-first order." actions={<Badge tone="info">{events.length} events</Badge>} />
    {ordered.length ? <ol className="package-event-list">{ordered.map((event) => <li key={`${event.generation}:${stringValue(event.event_id, stringValue(event.package_id))}`}><span className="event-generation">G{event.generation}</span><div><strong>{sentence(stringValue(event.event_type, "catalog change"))}</strong><code>{stringValue(event.package_id)}</code><p>{stringValue(event.reason)}</p><small>{stringValue(event.actor)} · {formatDate(typeof event.created_at === "string" ? event.created_at : undefined)}</small></div><Badge tone={event.event_type === "activated" ? "success" : "warning"}>{sentence(stringValue(event.cause, "operator"))}</Badge></li>)}</ol> : <EmptyState icon={<CheckCircle2 />} title="No catalog transitions yet" description="Installed packages remain inactive until an operator publishes the first verified generation." />}
  </Panel>;
}
