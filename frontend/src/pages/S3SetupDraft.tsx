import { useMutation } from "@tanstack/react-query";
import { Download, FileCheck2 } from "lucide-react";
import { useRef, useState } from "react";
import { Badge, Button, DataList, ErrorState, Field } from "../components/Primitives";
import { downloadArtifact } from "../lib/download";
import { MAX_S3_DRAFT_BYTES, s3SetupApi, type S3SetupProfile } from "../lib/s3-setup";

export function S3SetupDraft({ selected }: { selected?: S3SetupProfile }) {
  const [source, setSource] = useState("");
  const [inputError, setInputError] = useState<Error>();
  const [downloadError, setDownloadError] = useState<Error>();
  const inputGeneration = useRef(0);
  const review = useMutation({ mutationFn: s3SetupApi.reviewDraft });
  const matches = selected && review.variables?.profile_id === selected.profile_id && review.variables.profile_digest === selected.profile_digest && review.variables.configuration_json === source;
  const current = matches && !review.isPending && !review.error ? review.data : undefined;
  const edit = (text: string) => { inputGeneration.current += 1; setSource(text); setInputError(undefined); setDownloadError(undefined); review.reset(); };
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
    <div className="s3-actions"><Button disabled={!selected || !source.trim() || review.isPending} onClick={() => selected && review.mutate({ ...selected, configuration_json: source })}><FileCheck2 />{review.isPending ? "Reviewing draft" : "Review configuration"}</Button><Button disabled={!current} onClick={download}><Download />Export configuration</Button></div>
    {inputError ? <ErrorState title="Configuration input unavailable" error={inputError} /> : null}
    {matches && review.error ? <ErrorState title="Configuration review refused" error={review.error} /> : null}
    {downloadError ? <ErrorState title="Export unavailable" error={downloadError} /> : null}
    {current ? <div className="s3-setup-result" aria-live="polite"><h3>Structure checked</h3><p>Host installation, ownership, temporary access and AWS permissions remain unverified. Owner-local review is still required before installation.</p>{current.environments.map(row => <article key={row.environment_id} className="s3-setup-environment"><h3>{row.display_name}</h3><DataList items={[
      { label: "Environment", value: row.environment_id }, { label: "AWS account", value: row.account_id }, { label: "Region", value: row.region }, { label: "Bucket", value: row.bucket }, { label: "Scope expiry", value: row.expires_at }, { label: "Generated test objects", value: row.fixture_generation === 2 ? "Explicit v2 draft" : "Not included" },
    ]} /></article>)}<details><summary>Reviewed document identity</summary><code>{current.configuration_digest}</code></details></div> : <p role="status">No current configuration review for this profile and draft.</p>}
  </section>;
}
