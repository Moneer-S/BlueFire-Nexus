import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { NativeToolSetupDialog } from "../src/components/NativeToolSetupDialog";
import { api } from "../src/lib/api";
import type { NativeToolCandidateInspection, RunnerProfile } from "../src/types";

vi.mock("../src/lib/api", () => ({ api: { inspectNativeToolCandidate: vi.fn() } }));

const profile: RunnerProfile = {
  id: "linux-profile.v1", mode: "execute", environment_type: "local", platforms: ["linux"], scope: ["sandbox.workspace"], network_allowlist: [], capabilities: ["filesystem.read", "filesystem.write", "process.spawn"], safety_tiers: ["controlled"], approval_required: true, enabled_actions: ["sandbox.permission.chmod.v1"], blocked_actions: [], cleanup_policy: "always", budgets: { max_seconds: 60, max_steps: 5, max_bytes: 1024 }, secrets: {},
  native_tool_installations: [{ schema_version: "bluefire.native-tool-installation.v1", adapter_id: "sandbox.other.v1", adapter_version: "1.0.0", adapter_contract_digest: "sha256:" + "a".repeat(64), tool_id: "other.v1", tool_version: "1.0", platform: "linux", architecture: "x86_64", content_sha256: "sha256:" + "b".repeat(64), size_bytes: 12, installation_location: "/usr/bin/other" }],
};

const ready: NativeToolCandidateInspection = { schema_version: "bluefire.native-tool-candidate-inspection.v1", candidate_digest: "sha256:" + "c".repeat(64), status: "ready", code: "verified", platform: "linux", architecture: "x86_64", installation: { schema_version: "bluefire.native-tool-installation.v1", adapter_id: "sandbox.permission.chmod.v1", adapter_version: "1.0.0", adapter_contract_digest: "sha256:" + "d".repeat(64), tool_id: "gnu.coreutils.chmod.v1", tool_version: "9.4-3ubuntu6.1", platform: "linux", architecture: "x86_64", content_sha256: "sha256:" + "e".repeat(64), size_bytes: 1234, installation_location: "/usr/bin/chmod" } };
const gzipAction = "sandbox.collection.atomic-gzip.v1";
// Inspection responses below are component fixtures, not executable provenance proof.
const gzipReady: NativeToolCandidateInspection = { ...ready, installation: { ...ready.installation!, adapter_id: gzipAction, adapter_version: "1.1.0", tool_id: "gnu.gzip.v1", tool_version: "1.12-1ubuntu3.2", installation_location: "/usr/bin/gzip" } };
const bothTools: RunnerProfile = { ...profile, enabled_actions: [...profile.enabled_actions, gzipAction], native_tool_installations: [ready.installation!, { ...gzipReady.installation!, content_sha256: "sha256:" + "0".repeat(64) }] };

function openDialog(onSave = vi.fn()) { render(<NativeToolSetupDialog profile={profile} onSave={onSave} />); return { user: userEvent.setup(), onSave }; }

describe("NativeToolSetupDialog", () => {
  beforeEach(() => { vi.mocked(api.inspectNativeToolCandidate).mockReset(); });
  it("does not inspect a method blocked by the selected profile", () => {
    render(<NativeToolSetupDialog actionId={gzipAction} profile={{ ...bothTools, blocked_actions: [gzipAction] }} onSave={vi.fn()} />);
    expect(screen.getByRole("button", { name: "Set up GNU gzip" })).toBeDisabled();
    expect(api.inspectNativeToolCandidate).not.toHaveBeenCalled();
  });
  it("explains an unrecognized executable without offering a binding", async () => {
    vi.mocked(api.inspectNativeToolCandidate).mockResolvedValueOnce({ ...ready, status: "unavailable", code: "unrecognized_tool_build", installation: null });
    const { user, onSave } = openDialog();
    await user.click(screen.getByRole("button", { name: "Set up GNU chmod" }));
    await user.type(screen.getByLabelText("Declared GNU version"), "9.4-3ubuntu6.1");
    await user.click(screen.getByRole("button", { name: "Inspect installation" }));
    await screen.findByText(/different build requires a reviewed BlueFire update/);
    expect(screen.getByRole("button", { name: "Save tool binding" })).toBeDisabled();
    expect(onSave).not.toHaveBeenCalled();
  });

  it("inspects first and saves only an explicit verified binding", async () => {
    vi.mocked(api.inspectNativeToolCandidate).mockResolvedValueOnce(ready);
    const { user, onSave } = openDialog();
    await user.click(screen.getByRole("button", { name: "Set up GNU chmod" }));
    expect(screen.getByRole("button", { name: "Save tool binding" })).toBeDisabled();
    await user.type(screen.getByLabelText("Declared GNU version"), "9.4-3ubuntu6.1");
    await user.click(screen.getByRole("button", { name: "Inspect installation" }));
    await screen.findByText("Reviewed GNU build verified");
    await user.click(screen.getByRole("button", { name: "Save tool binding" }));
    await waitFor(() => expect(onSave).toHaveBeenCalledWith(expect.objectContaining({ id: profile.id, native_tool_installations: expect.arrayContaining([profile.native_tool_installations![0], ready.installation]) })));
    expect(api.inspectNativeToolCandidate).toHaveBeenCalledWith(profile.id, "/usr/bin/chmod", "9.4-3ubuntu6.1", "sandbox.permission.chmod.v1");
  });

  it("does not offer save for an unavailable candidate and clears readiness on edits", async () => {
    vi.mocked(api.inspectNativeToolCandidate).mockResolvedValueOnce({ ...ready, status: "unavailable", code: "inspection_unavailable", installation: null });
    const { user, onSave } = openDialog();
    await user.click(screen.getByRole("button", { name: "Set up GNU chmod" }));
    await user.type(screen.getByLabelText("Declared GNU version"), "9.4-3ubuntu6.1");
    await user.click(screen.getByRole("button", { name: "Inspect installation" }));
    await screen.findByText(/Installation unavailable/);
    expect(screen.getByRole("button", { name: "Save tool binding" })).toBeDisabled();
    expect(onSave).not.toHaveBeenCalled();
  });

  it("ignores an in-flight response after the operator edits the candidate", async () => {
    let resolve!: (value: NativeToolCandidateInspection) => void;
    vi.mocked(api.inspectNativeToolCandidate).mockReturnValueOnce(new Promise((done) => { resolve = done; }));
    const { user } = openDialog();
    await user.click(screen.getByRole("button", { name: "Set up GNU chmod" }));
    await user.type(screen.getByLabelText("Declared GNU version"), "9.4-3ubuntu6.1");
    await user.click(screen.getByRole("button", { name: "Inspect installation" }));
    await user.clear(screen.getByLabelText("Installation location"));
    await user.type(screen.getByLabelText("Installation location"), "/usr/local/bin/chmod");
    resolve(ready);
    await new Promise((done) => setTimeout(done, 0));
    expect(screen.queryByText("Reviewed GNU build verified")).not.toBeInTheDocument();
  });

  it("can inspect again after invalidating a stale request", async () => {
    let resolve!: (value: NativeToolCandidateInspection) => void;
    vi.mocked(api.inspectNativeToolCandidate)
      .mockReturnValueOnce(new Promise((done) => { resolve = done; }))
      .mockResolvedValueOnce({ ...ready, installation: { ...ready.installation!, installation_location: "/usr/local/bin/chmod" } });
    const { user } = openDialog();
    await user.click(screen.getByRole("button", { name: "Set up GNU chmod" }));
    await user.type(screen.getByLabelText("Declared GNU version"), "9.4-3ubuntu6.1");
    await user.click(screen.getByRole("button", { name: "Inspect installation" }));
    await user.clear(screen.getByLabelText("Installation location"));
    await user.type(screen.getByLabelText("Installation location"), "/usr/local/bin/chmod");
    resolve(ready);
    await user.click(screen.getByRole("button", { name: "Inspect installation" }));
    await screen.findByText("Reviewed GNU build verified");
    expect(api.inspectNativeToolCandidate).toHaveBeenLastCalledWith(profile.id, "/usr/local/bin/chmod", "9.4-3ubuntu6.1", "sandbox.permission.chmod.v1");
  });

  it("clears a verified result when the operator edits the location", async () => {
    vi.mocked(api.inspectNativeToolCandidate).mockResolvedValueOnce(ready);
    const { user } = openDialog();
    await user.click(screen.getByRole("button", { name: "Set up GNU chmod" }));
    await user.type(screen.getByLabelText("Declared GNU version"), "9.4-3ubuntu6.1");
    await user.click(screen.getByRole("button", { name: "Inspect installation" }));
    await screen.findByRole("status", { name: "Reviewed GNU build verified" });
    await user.type(screen.getByLabelText("Installation location"), "-backup");
    expect(screen.queryByRole("status", { name: "Reviewed GNU build verified" })).not.toBeInTheDocument();
  });

  it("invalidates a verified result when the profile changes", async () => {
    vi.mocked(api.inspectNativeToolCandidate).mockResolvedValueOnce(ready);
    const user = userEvent.setup();
    const view = render(<NativeToolSetupDialog profile={profile} onSave={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: "Set up GNU chmod" }));
    await user.type(screen.getByLabelText("Declared GNU version"), "9.4-3ubuntu6.1");
    await user.click(screen.getByRole("button", { name: "Inspect installation" }));
    await screen.findByRole("status", { name: "Reviewed GNU build verified" });
    view.rerender(<NativeToolSetupDialog profile={{ ...profile, id: "other-profile.v1" }} onSave={vi.fn()} />);
    expect(screen.queryByRole("status", { name: "Reviewed GNU build verified" })).not.toBeInTheDocument();
  });

  it("inspects gzip explicitly and replaces only its binding while retaining chmod", async () => {
    vi.mocked(api.inspectNativeToolCandidate).mockResolvedValueOnce(gzipReady);
    const user = userEvent.setup(); const onSave = vi.fn().mockResolvedValue(undefined);
    render(<NativeToolSetupDialog actionId={gzipAction} profile={bothTools} onSave={onSave} />);
    await user.click(screen.getByRole("button", { name: "Set up GNU gzip" }));
    expect(screen.getByLabelText("Installation location")).toHaveValue("/usr/bin/gzip");
    expect(screen.getByText(/Supported packages/)).toHaveTextContent("Linux amd64, gzip 1.12-1ubuntu3.1 or 1.12-1ubuntu3.2");
    expect(screen.queryByRole("combobox")).not.toBeInTheDocument();
    await user.type(screen.getByLabelText("Declared GNU version"), "1.12-1ubuntu3.2");
    await user.click(screen.getByRole("button", { name: "Inspect installation" }));
    await screen.findByRole("status", { name: "Reviewed GNU build verified" });
    expect(onSave).not.toHaveBeenCalled();
    await user.click(screen.getByText("Technical verification details"));
    expect(screen.getByText(gzipReady.installation!.content_sha256)).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Save tool binding" }));
    await waitFor(() => expect(onSave).toHaveBeenCalledExactlyOnceWith({ ...bothTools, native_tool_installations: [ready.installation, gzipReady.installation] }));
    expect(api.inspectNativeToolCandidate).toHaveBeenCalledExactlyOnceWith(bothTools.id, "/usr/bin/gzip", "1.12-1ubuntu3.2", gzipAction);
  });

  it("keeps the saved gzip binding when updating chmod through the default setup", async () => {
    vi.mocked(api.inspectNativeToolCandidate).mockResolvedValueOnce(ready);
    const user = userEvent.setup(); const onSave = vi.fn().mockResolvedValue(undefined);
    render(<NativeToolSetupDialog profile={bothTools} onSave={onSave} />);
    await user.click(screen.getByRole("button", { name: "Set up GNU chmod" }));
    expect(screen.getByLabelText("Installation location")).toHaveValue("/usr/bin/chmod");
    await user.type(screen.getByLabelText("Declared GNU version"), "9.4-3ubuntu6.1");
    await user.click(screen.getByRole("button", { name: "Inspect installation" }));
    await screen.findByRole("status", { name: "Reviewed GNU build verified" });
    await user.click(screen.getByRole("button", { name: "Save tool binding" }));
    await waitFor(() => expect(onSave).toHaveBeenCalledExactlyOnceWith({ ...bothTools, native_tool_installations: [bothTools.native_tool_installations![1], ready.installation] }));
  });

  it.each(["location", "version", "profile"])("ignores a pending gzip inspection after its %s changes", async changed => {
    let finish!: (value: NativeToolCandidateInspection) => void;
    vi.mocked(api.inspectNativeToolCandidate).mockReturnValueOnce(new Promise(resolve => { finish = resolve; }));
    const user = userEvent.setup(); const onSave = vi.fn();
    const view = render(<NativeToolSetupDialog actionId={gzipAction} profile={bothTools} onSave={onSave} />);
    await user.click(screen.getByRole("button", { name: "Set up GNU gzip" }));
    await user.type(screen.getByLabelText("Declared GNU version"), "1.12-1ubuntu3.2");
    await user.click(screen.getByRole("button", { name: "Inspect installation" }));
    if (changed === "profile") view.rerender(<NativeToolSetupDialog actionId={gzipAction} profile={{ ...bothTools, id: "another-profile.v1" }} onSave={onSave} />);
    else await user.type(screen.getByLabelText(changed === "location" ? "Installation location" : "Declared GNU version"), "-changed");
    await act(async () => finish(gzipReady));
    expect(screen.queryByRole("status", { name: "Reviewed GNU build verified" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save tool binding" })).toBeDisabled();
    expect(onSave).not.toHaveBeenCalled();
  });

  it("does not reuse a gzip inspection when the selected setup method changes to chmod", async () => {
    let finish!: (value: NativeToolCandidateInspection) => void;
    vi.mocked(api.inspectNativeToolCandidate).mockReturnValueOnce(new Promise(resolve => { finish = resolve; })).mockResolvedValueOnce(ready);
    const user = userEvent.setup(); const onSave = vi.fn();
    const view = render(<NativeToolSetupDialog actionId={gzipAction} profile={bothTools} onSave={onSave} />);
    await user.click(screen.getByRole("button", { name: "Set up GNU gzip" }));
    await user.type(screen.getByLabelText("Declared GNU version"), "1.12-1ubuntu3.2");
    await user.click(screen.getByRole("button", { name: "Inspect installation" }));
    view.rerender(<NativeToolSetupDialog actionId="sandbox.permission.chmod.v1" profile={bothTools} onSave={onSave} />);
    expect(screen.getByLabelText("Installation location")).toHaveValue("/usr/bin/chmod");
    expect(screen.getByLabelText("Declared GNU version")).toHaveValue("");
    await act(async () => finish(gzipReady));
    expect(screen.getByRole("button", { name: "Save tool binding" })).toBeDisabled();
    await user.type(screen.getByLabelText("Declared GNU version"), "9.4-3ubuntu6.1");
    await user.click(screen.getByRole("button", { name: "Inspect installation" }));
    await screen.findByRole("status", { name: "Reviewed GNU build verified" });
    expect(api.inspectNativeToolCandidate).toHaveBeenLastCalledWith(bothTools.id, "/usr/bin/chmod", "9.4-3ubuntu6.1", "sandbox.permission.chmod.v1");
    expect(onSave).not.toHaveBeenCalled();
  });

  it("refuses an inspection response bound to the other tool", async () => {
    vi.mocked(api.inspectNativeToolCandidate).mockResolvedValueOnce(ready);
    const user = userEvent.setup(); const onSave = vi.fn();
    render(<NativeToolSetupDialog actionId={gzipAction} profile={bothTools} onSave={onSave} />);
    await user.click(screen.getByRole("button", { name: "Set up GNU gzip" }));
    await user.type(screen.getByLabelText("Declared GNU version"), "1.12-1ubuntu3.2");
    await user.click(screen.getByRole("button", { name: "Inspect installation" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("did not match the selected tool");
    expect(screen.getByRole("button", { name: "Save tool binding" })).toBeDisabled();
    expect(onSave).not.toHaveBeenCalled();
  });
});
