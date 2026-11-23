import * as Dialog from "@radix-ui/react-dialog";
import { useEffect, useRef, useState } from "react";
import { api } from "../lib/api";
import { NATIVE_TOOL_SETUP, type NativeToolActionId } from "../lib/native-tool-setup";
import { profileLabel } from "../lib/run-review-labels";
import type { NativeToolCandidateInspection, NativeToolInstallation, RunnerProfile } from "../types";
import { Badge, Button, Callout, DataList, Field } from "./Primitives";

export function NativeToolSetupDialog({ profile, onSave, actionId = "sandbox.permission.chmod.v1", triggerLabel }: { profile: RunnerProfile; onSave: (profile: RunnerProfile) => Promise<unknown>; actionId?: NativeToolActionId; triggerLabel?: string }) {
  const tool = NATIVE_TOOL_SETUP[actionId];
  const eligible = profile.mode === "execute" && profile.platforms.length === 1 && profile.platforms[0] === "linux" && profile.enabled_actions.includes(actionId) && !profile.blocked_actions.includes(actionId);
  const [open, setOpen] = useState(false);
  const [location, setLocation] = useState<string>(tool.location);
  const [version, setVersion] = useState("");
  const [candidate, setCandidate] = useState<NativeToolCandidateInspection>();
  const [error, setError] = useState<string>();
  const [inspecting, setInspecting] = useState(false);
  const [saving, setSaving] = useState(false);
  const requestRef = useRef(0);
  useEffect(() => { requestRef.current += 1; setCandidate(undefined); setError(undefined); setInspecting(false); return () => { requestRef.current += 1; }; }, [profile, actionId]);
  useEffect(() => { setLocation(tool.location); setVersion(""); }, [tool]);
  const inspect = async () => {
    if (!eligible || saving) return;
    const requestId = ++requestRef.current;
    setInspecting(true); setError(undefined); setCandidate(undefined);
    try {
      const result = await api.inspectNativeToolCandidate(profile.id, location.trim(), version.trim(), actionId);
      if (requestId !== requestRef.current) return;
      if (result.status === "ready" && result.installation && (
        result.installation.adapter_id !== actionId || result.installation.tool_id !== tool.toolId
        || result.installation.installation_location !== location.trim() || result.installation.tool_version !== version.trim()
        || result.platform !== "linux" || result.installation.platform !== "linux"
        || result.architecture !== "x86_64" || result.installation.architecture !== "x86_64"
      )) throw new Error("The inspected installation did not match the selected tool and declared settings. Inspect it again before saving.");
      setCandidate(result);
    } catch (caught) {
      if (requestId === requestRef.current) setError(caught instanceof Error ? caught.message : "The protected tool could not be inspected.");
    } finally { if (requestId === requestRef.current) setInspecting(false); }
  };
  const save = async () => {
    if (!eligible || inspecting || saving || !candidate?.installation || candidate.status !== "ready") return;
    setSaving(true); setError(undefined);
    try {
      const current = (profile.native_tool_installations ?? []).filter((item) => item.adapter_id !== actionId);
      await onSave({ ...profile, native_tool_installations: [...current, candidate.installation] });
      setOpen(false); setCandidate(undefined);
    } catch (caught) { setError(caught instanceof Error ? caught.message : "The tool binding could not be saved."); }
    finally { setSaving(false); }
  };
  const edit = (setter: (value: string) => void) => (value: string) => { requestRef.current += 1; setInspecting(false); setCandidate(undefined); setError(undefined); setter(value); };
  return <Dialog.Root open={open} onOpenChange={(next) => { if (saving) return; setOpen(next); if (!next) { requestRef.current += 1; setInspecting(false); setCandidate(undefined); setError(undefined); } }}>
    <Dialog.Trigger asChild><Button size="small" variant="secondary" aria-label={triggerLabel ?? `Set up ${tool.name}`} disabled={!eligible}>Set up {tool.name}</Button></Dialog.Trigger>
    <Dialog.Portal><Dialog.Overlay className="dialog-overlay"/><Dialog.Content className="dialog-content">
      <Dialog.Title>Set up {tool.name}</Dialog.Title>
      <Dialog.Description>Match a protected Linux installation to a reviewed {tool.name} build, then attach its identity to this draft profile. Inspection does not execute {tool.command} or activate the profile.</Dialog.Description>
      <p>Profile: {profileLabel(profile.id)} <small><code>{profile.id}</code></small></p>
      <p>Supported packages: Ubuntu Noble, Linux amd64, {tool.packageName} <code>{tool.packageVersions.join(" or ")}</code>. Other builds need a reviewed BlueFire update.</p>
      <Field label="Installation location" hint="The reviewed executable path on the Linux runner."><input aria-label="Installation location" value={location} onChange={(event) => edit(setLocation)(event.target.value)} disabled={saving} autoComplete="off" spellCheck={false}/></Field>
      <Field label="Declared GNU version" hint="Enter the exact supported package version. Both the version and executable fingerprint must match BlueFire’s reviewed build list; BlueFire does not run --version."><input aria-label="Declared GNU version" value={version} onChange={(event) => edit(setVersion)(event.target.value)} disabled={saving} autoComplete="off"/></Field>
      {candidate?.status === "ready" && candidate.installation ? <section role="status" aria-label="Reviewed GNU build verified"><p><strong>Reviewed GNU build verified</strong></p><p><Badge tone="success">Ready to save</Badge> The executable matches a reviewed package build and passed the ownership checks.</p><details><summary>Technical verification details</summary><DataList items={[{ label: "Method", value: <code>{actionId}</code> }, { label: "Tool", value: <code>{candidate.installation.tool_id}</code> }, { label: "Location", value: <code>{candidate.installation.installation_location}</code> }, { label: "Platform", value: candidate.platform }, { label: "Architecture", value: candidate.architecture }, { label: "Version", value: candidate.installation.tool_version }, { label: "Size", value: `${candidate.installation.size_bytes} bytes` }, { label: "Content fingerprint", value: <code>{candidate.installation.content_sha256}</code> }]} /></details></section> : null}
      {candidate?.status === "unavailable" ? <Callout tone="warning" title="Installation unavailable">{({ inspection_unavailable: "The protected tool could not be verified on this runner.", unsafe_installation: "The installation is not protected by the reviewed ownership checks.", digest_mismatch: "The executable did not match the reviewed content identity.", unsupported_binary: "The path is not a supported Linux executable.", unrecognized_tool_build: `This executable and package version do not match a reviewed ${tool.name} build. Check the declared version and supported build list; a different build requires a reviewed BlueFire update.` } as Record<string, string>)[candidate.code] ?? "The protected tool could not be verified."} No binding was saved.<details><summary>Technical detail</summary><code>{candidate.code}</code></details></Callout> : null}
      {error ? <p role="alert">{error}</p> : null}
      <div className="dialog-actions"><Dialog.Close asChild><Button type="button" variant="ghost" disabled={saving}>Cancel</Button></Dialog.Close><Button type="button" variant="secondary" onClick={() => void inspect()} disabled={!eligible || inspecting || saving || !location.trim() || !version.trim()}>{inspecting ? "Inspecting…" : "Inspect installation"}</Button><Button type="button" onClick={() => void save()} disabled={!eligible || inspecting || saving || candidate?.status !== "ready" || !candidate.installation}>Save tool binding</Button></div>
    </Dialog.Content></Dialog.Portal>
  </Dialog.Root>;
}

export type { NativeToolInstallation };
