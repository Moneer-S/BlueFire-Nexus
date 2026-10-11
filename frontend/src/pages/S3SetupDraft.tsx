import * as Dialog from "@radix-ui/react-dialog";
import { useMutation } from "@tanstack/react-query";
import { Download, FileCheck2, FolderOpen, Save } from "lucide-react";
import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { Badge, Button, DataList, ErrorState, Field } from "../components/Primitives";
import { downloadArtifact } from "../lib/download";
import { MAX_S3_DRAFT_BYTES, s3SetupApi, savedDraftProfileId, type S3SavedSetupDraft, type S3SetupProfile } from "../lib/s3-setup";

export function S3SetupDraft({ selected, profileId = selected?.profile_id ?? "" }: { selected?: S3SetupProfile; profileId?: string }) {
  const [source, setSource] = useState("");
  const [inputError, setInputError] = useState<Error>();
  const [downloadError, setDownloadError] = useState<Error>();
  const inputGeneration = useRef(0);
  const operationId = useRef(0);
  const selectionKey = JSON.stringify([profileId, selected?.profile_digest ?? null]);
  const selectionRef = useRef(selectionKey);
  const [saved, setSaved] = useState<Record<string, S3SavedSetupDraft | null>>({});
  const [operation, setOperation] = useState<{ key: string; kind: "load" | "save" }>();
  const [storageError, setStorageError] = useState<Error>();
  const [storageNotice, setStorageNotice] = useState<string>();
  const [replacement, setReplacement] = useState<{ key: string; generation: number; draft: S3SavedSetupDraft } | null>(null);
  const openButton = useRef<HTMLButtonElement>(null);
  const cancelButton = useRef<HTMLButtonElement>(null);
  const busy = operation?.key === selectionKey;
  useLayoutEffect(() => {
    if (selectionRef.current !== selectionKey) {
      selectionRef.current = selectionKey;
      inputGeneration.current += 1;
      setReplacement(null);
      setStorageError(undefined);
      setStorageNotice(undefined);
    }
  }, [selectionKey]);
  useEffect(() => () => { inputGeneration.current += 1; operationId.current += 1; }, []);
  const review = useMutation({ mutationFn: s3SetupApi.reviewDraft });
  const matches = selected && review.variables?.profile_id === selected.profile_id && review.variables.profile_digest === selected.profile_digest && review.variables.configuration_json === source;
  const current = matches && !review.isPending && !review.error ? review.data : undefined;
  const edit = (text: string) => { inputGeneration.current += 1; setSource(text); setInputError(undefined); setDownloadError(undefined); setStorageError(undefined); setStorageNotice(undefined); setReplacement(null); review.reset(); };
  const acceptSaved = (draft: S3SavedSetupDraft) => {
    edit(draft.configuration_json);
    setSaved(previous => ({ ...previous, [draft.profile_id]: draft }));
  };
  const openSaved = async () => {
    if (!savedDraftProfileId(profileId) || busy) return;
    const id = ++operationId.current, generation = ++inputGeneration.current, key = selectionKey;
    setOperation({ key, kind: "load" }); setStorageError(undefined); setStorageNotice(undefined); setReplacement(null);
    try {
      const response = await s3SetupApi.savedDraft(profileId);
      if (id !== operationId.current || generation !== inputGeneration.current || key !== selectionRef.current) return;
      if (!response.draft) { setSaved(previous => ({ ...previous, [profileId]: null })); setStorageNotice("No saved configuration draft for this profile."); }
      else if (source && source !== response.draft.configuration_json) setReplacement({ key, generation, draft: response.draft });
      else acceptSaved(response.draft);
    } catch (error) {
      if (id === operationId.current && generation === inputGeneration.current && key === selectionRef.current) setStorageError(error instanceof Error ? error : new Error("The saved draft could not be opened. Current inputs are unchanged."));
    } finally { if (id === operationId.current) setOperation(undefined); }
  };
  const save = async () => {
    if (!current || !selected || selected.profile_id !== profileId || busy || replacement) return;
    const id = ++operationId.current, key = selectionKey;
    setOperation({ key, kind: "save" }); setStorageError(undefined); setStorageNotice(undefined);
    try {
      const response = await s3SetupApi.saveDraft({ ...selected, configuration_json: source, expected_digest: saved[profileId]?.digest ?? null });
      if (id !== operationId.current || key !== selectionRef.current) return;
      if (!response.draft) throw new Error("The saved draft was not confirmed. Current inputs are unchanged.");
      // Retain the accepted revision for the next compare-and-save, never replace newer text.
      setSaved(previous => ({ ...previous, [profileId]: response.draft }));
    } catch (error) {
      if (id === operationId.current && key === selectionRef.current) setStorageError(error instanceof Error ? error : new Error("The draft could not be saved. Current inputs are unchanged."));
    } finally { if (id === operationId.current) setOperation(undefined); }
  };
  const retained = saved[profileId];
  const unchangedSource = retained?.configuration_json === source;
  const unchanged = unchangedSource && retained?.profile_digest === selected?.profile_digest;
  const replacing = replacement?.key === selectionKey && replacement.generation === inputGeneration.current;
  const importFile = async (file?: File) => {
    const generation = ++inputGeneration.current;
    if (!file) return;
    try {
      if (file.size > MAX_S3_DRAFT_BYTES) throw new Error("The nonsecret configuration exceeds 128 KiB. The current draft is unchanged.");
      const text = await file.text();
      if (generation === inputGeneration.current) edit(text);
    } catch (error) {
      if (generation === inputGeneration.current) setInputError(error instanceof Error ? error : new Error("The configuration file could not be read. The current draft is unchanged."));
    }
  };
  const download = () => {
    if (!current) return;
    try { downloadArtifact(new Blob([source], { type: "application/json;charset=utf-8" }), "bluefire-s3-configuration.json"); setDownloadError(undefined); }
    catch { setDownloadError(new Error("The configuration could not be downloaded. Its draft is unchanged.")); }
  };
  return <section className="s3-band s3-setup-draft" aria-label="S3 configuration draft">
    <div className="s3-setup-heading"><h3>Configuration draft</h3><Badge tone="neutral">Not installed or authorized</Badge></div>
    <Field label="Non-secret configuration file"><input type="file" accept="application/json,.json" onChange={event => { void importFile(event.target.files?.[0]); event.target.value = ""; }} /></Field>
    <details><summary>Configuration JSON</summary><Field label="Non-secret configuration JSON"><textarea rows={12} spellCheck={false} value={source} maxLength={MAX_S3_DRAFT_BYTES} onChange={event => edit(event.target.value)} /></Field></details>
    <div className="s3-actions"><Button disabled={!selected || !source.trim() || review.isPending} onClick={() => selected && review.mutate({ ...selected, configuration_json: source })}><FileCheck2 />{review.isPending ? "Reviewing draft" : "Review configuration"}</Button><Button disabled={!current} onClick={download}><Download />Export configuration</Button><Button disabled={!current || selected?.profile_id !== profileId || busy || Boolean(replacement) || unchanged} onClick={() => { void save(); }}><Save />{busy && operation.kind === "save" ? "Saving draft" : "Save draft"}</Button><button ref={openButton} className="button button-secondary button-medium" disabled={!savedDraftProfileId(profileId) || busy} onClick={() => { void openSaved(); }}><FolderOpen />{busy && operation.kind === "load" ? "Opening draft" : "Open saved draft"}</button></div>
    {retained ? <p role="status">{unchangedSource ? "Draft saved" : "Current inputs differ from the saved draft"}{retained.profile_digest !== selected?.profile_digest ? ". Saved for a different or unavailable profile version." : "."}</p> : null}
    {storageNotice ? <p role="status">{storageNotice}</p> : null}
    {storageError ? <ErrorState title="Saved draft not confirmed" error={storageError} /> : null}
    {inputError ? <ErrorState title="Configuration input unavailable" error={inputError} /> : null}
    {matches && review.error ? <ErrorState title="Configuration review refused" error={review.error} /> : null}
    {downloadError ? <ErrorState title="Export unavailable" error={downloadError} /> : null}
    {current ? <div className="s3-setup-result" aria-live="polite"><h3>Structure checked</h3><p>Host installation, ownership, temporary access and AWS permissions remain unverified. Owner-local review is still required before installation.</p>{current.environments.map(row => <article key={row.environment_id} className="s3-setup-environment"><h3>{row.display_name}</h3><DataList items={[
      { label: "Environment", value: row.environment_id }, { label: "AWS account", value: row.account_id }, { label: "Region", value: row.region }, { label: "Bucket", value: row.bucket }, { label: "Scope expiry", value: row.expires_at }, { label: "Generated test objects", value: row.fixture_generation === 2 ? "Explicit v2 draft" : "Not included" },
    ]} /></article>)}<details><summary>Reviewed document identity</summary><code>{current.configuration_digest}</code></details></div> : <p role="status">No current configuration review for this profile and draft.</p>}
    <Dialog.Root open={Boolean(replacing)} onOpenChange={open => { if (!open) setReplacement(null); }}><Dialog.Portal><Dialog.Overlay className="dialog-overlay" /><Dialog.Content className="dialog-content" onOpenAutoFocus={event => { event.preventDefault(); cancelButton.current?.focus(); }} onCloseAutoFocus={event => { event.preventDefault(); openButton.current?.focus(); }} onEscapeKeyDown={event => event.stopPropagation()}><Dialog.Title>Replace current configuration?</Dialog.Title><Dialog.Description>Unsaved inputs will be replaced by the saved draft for {profileId}. No installation or authorization will be restored.</Dialog.Description><div className="dialog-actions"><button ref={cancelButton} className="button button-secondary button-medium" onClick={() => setReplacement(null)}>Cancel</button><Button onClick={() => { if (replacing && replacement) acceptSaved(replacement.draft); }}>Open saved version</Button></div></Dialog.Content></Dialog.Portal></Dialog.Root>
  </section>;
}
