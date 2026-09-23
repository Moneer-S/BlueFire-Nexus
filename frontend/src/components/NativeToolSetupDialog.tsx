import * as Dialog from "@radix-ui/react-dialog";
import { useEffect, useRef, useState } from "react";
import { api } from "../lib/api";
import type { NativeToolCandidateInspection, NativeToolInstallation, RunnerProfile } from "../types";
import { Badge, Button, Callout, DataList, Field } from "./Primitives";

const ACTION_ID = "sandbox.permission.chmod.v1";

export function NativeToolSetupDialog({ profile, onSave, triggerLabel = "Set up GNU chmod" }: { profile: RunnerProfile; onSave: (profile: RunnerProfile) => Promise<unknown>; triggerLabel?: string }) {
  const [open, setOpen] = useState(false);
  const [location, setLocation] = useState("/usr/bin/chmod");
  const [version, setVersion] = useState("");
  const [candidate, setCandidate] = useState<NativeToolCandidateInspection>();
  const [error, setError] = useState<string>();
  const [inspecting, setInspecting] = useState(false);
  const [saving, setSaving] = useState(false);
  const requestRef = useRef(0);
  useEffect(() => { requestRef.current += 1; setCandidate(undefined); setError(undefined); setInspecting(false); }, [profile]);
  const inspect = async () => {
    const requestId = ++requestRef.current;
    setInspecting(true); setError(undefined); setCandidate(undefined);
    try {
      const result = await api.inspectNativeToolCandidate(profile.id, location.trim(), version.trim());
      if (requestId === requestRef.current) setCandidate(result);
    } catch (caught) {
      if (requestId === requestRef.current) setError(caught instanceof Error ? caught.message : "The protected tool could not be inspected.");
    } finally { if (requestId === requestRef.current) setInspecting(false); }
  };
  const save = async () => {
    if (!candidate?.installation || candidate.status !== "ready") return;
    setSaving(true); setError(undefined);
    try {
      const current = (profile.native_tool_installations ?? []).filter((item) => item.adapter_id !== ACTION_ID);
      await onSave({ ...profile, native_tool_installations: [...current, candidate.installation] });
      setOpen(false); setCandidate(undefined);
    } catch (caught) { setError(caught instanceof Error ? caught.message : "The tool binding could not be saved."); }
    finally { setSaving(false); }
  };
  const edit = (setter: (value: string) => void) => (value: string) => { requestRef.current += 1; setInspecting(false); setCandidate(undefined); setError(undefined); setter(value); };
  return <Dialog.Root open={open} onOpenChange={(next) => { setOpen(next); if (!next) { requestRef.current += 1; setInspecting(false); setCandidate(undefined); setError(undefined); } }}>
    <Dialog.Trigger asChild><Button size="small" variant="secondary" aria-label={triggerLabel}>Set up GNU chmod</Button></Dialog.Trigger>
    <Dialog.Portal><Dialog.Overlay className="dialog-overlay"/><Dialog.Content className="dialog-content">
      <Dialog.Title>Set up GNU chmod</Dialog.Title>
      <Dialog.Description>Match a protected Linux installation to a reviewed GNU chmod build, then attach its identity to this draft profile. Inspection does not execute chmod or activate the profile.</Dialog.Description>
      <p>Profile: <code>{profile.id}</code></p>
      <p>Supported build: Ubuntu Noble, amd64, coreutils <code>9.4-3ubuntu6.1</code>. Other builds need a reviewed BlueFire update.</p>
      <Field label="Installation location" hint="The reviewed executable path on the Linux runner."><input aria-label="Installation location" value={location} onChange={(event) => edit(setLocation)(event.target.value)} autoComplete="off" spellCheck={false}/></Field>
      <Field label="Declared GNU version" hint="Enter the exact supported package version. Both the version and executable fingerprint must match BlueFire’s reviewed build list; BlueFire does not run --version."><input aria-label="Declared GNU version" value={version} onChange={(event) => edit(setVersion)(event.target.value)} autoComplete="off"/></Field>
      {candidate?.status === "ready" && candidate.installation ? <section role="status" aria-label="Reviewed GNU build verified"><p><strong>Reviewed GNU build verified</strong></p><p><Badge tone="success">Ready to save</Badge> The executable matches a reviewed package build and passed the ownership checks.</p><details><summary>Technical verification details</summary><DataList items={[{ label: "Platform", value: candidate.platform }, { label: "Architecture", value: candidate.architecture }, { label: "Version", value: candidate.installation.tool_version }, { label: "Size", value: `${candidate.installation.size_bytes} bytes` }, { label: "Content fingerprint", value: <code>{candidate.installation.content_sha256}</code> }]} /></details></section> : null}
      {candidate?.status === "unavailable" ? <Callout tone="warning" title="Installation unavailable">{({ inspection_unavailable: "The protected tool could not be verified on this runner.", unsafe_installation: "The installation is not protected by the reviewed ownership checks.", digest_mismatch: "The executable did not match the reviewed content identity.", unsupported_binary: "The path is not a supported Linux executable.", unrecognized_tool_build: "This executable and package version do not match a reviewed GNU chmod build. Check the declared version and supported build list; a different build requires a reviewed BlueFire update." } as Record<string, string>)[candidate.code] ?? "The protected tool could not be verified."} No binding was saved.<details><summary>Technical detail</summary><code>{candidate.code}</code></details></Callout> : null}
      {error ? <p role="alert">{error}</p> : null}
      <div className="dialog-actions"><Dialog.Close asChild><Button type="button" variant="ghost">Cancel</Button></Dialog.Close><Button type="button" variant="secondary" onClick={() => void inspect()} disabled={inspecting || saving || !location.trim() || !version.trim()}>{inspecting ? "Inspecting…" : "Inspect installation"}</Button><Button type="button" onClick={() => void save()} disabled={inspecting || saving || candidate?.status !== "ready" || !candidate.installation}>Save tool binding</Button></div>
    </Dialog.Content></Dialog.Portal>
  </Dialog.Root>;
}

export type { NativeToolInstallation };
