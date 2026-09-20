import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { NativeToolSetupDialog } from "../src/components/NativeToolSetupDialog";
import { api } from "../src/lib/api";
import type { NativeToolCandidateInspection, RunnerProfile } from "../src/types";

vi.mock("../src/lib/api", () => ({ api: { inspectNativeToolCandidate: vi.fn() } }));

const profile: RunnerProfile = {
  id: "linux-profile.v1", mode: "execute", environment_type: "local", platforms: ["linux"], scope: ["sandbox.workspace"], network_allowlist: [], capabilities: ["filesystem.read", "filesystem.write", "process.spawn"], safety_tiers: ["controlled"], approval_required: true, enabled_actions: ["sandbox.permission.chmod.v1"], blocked_actions: [], cleanup_policy: "always", budgets: { max_seconds: 60, max_steps: 5, max_bytes: 1024 }, secrets: {},
  native_tool_installations: [{ schema_version: "bluefire.native-tool-installation.v1", adapter_id: "sandbox.other.v1", adapter_version: "1.0.0", adapter_contract_digest: "sha256:" + "a".repeat(64), tool_id: "other.v1", tool_version: "1.0", platform: "linux", architecture: "x86_64", content_sha256: "sha256:" + "b".repeat(64), size_bytes: 12, installation_location: "/usr/bin/other" }],
};

const ready: NativeToolCandidateInspection = { schema_version: "bluefire.native-tool-candidate-inspection.v1", candidate_digest: "sha256:" + "c".repeat(64), status: "ready", code: "verified", platform: "linux", architecture: "x86_64", installation: { schema_version: "bluefire.native-tool-installation.v1", adapter_id: "sandbox.permission.chmod.v1", adapter_version: "1.0.0", adapter_contract_digest: "sha256:" + "d".repeat(64), tool_id: "gnu.coreutils.chmod.v1", tool_version: "9.4", platform: "linux", architecture: "x86_64", content_sha256: "sha256:" + "e".repeat(64), size_bytes: 1234, installation_location: "/usr/bin/chmod" } };

function openDialog(onSave = vi.fn()) { render(<NativeToolSetupDialog profile={profile} onSave={onSave} />); return { user: userEvent.setup(), onSave }; }

describe("NativeToolSetupDialog", () => {
  it("inspects first and saves only an explicit verified binding", async () => {
    vi.mocked(api.inspectNativeToolCandidate).mockResolvedValueOnce(ready);
    const { user, onSave } = openDialog();
    await user.click(screen.getByRole("button", { name: "Set up GNU chmod" }));
    expect(screen.getByRole("button", { name: "Save tool binding" })).toBeDisabled();
    await user.type(screen.getByLabelText("Declared GNU version"), "9.4");
    await user.click(screen.getByRole("button", { name: "Inspect installation" }));
    await screen.findByText("Protected installation verified");
    await user.click(screen.getByRole("button", { name: "Save tool binding" }));
    await waitFor(() => expect(onSave).toHaveBeenCalledWith(expect.objectContaining({ id: profile.id, native_tool_installations: expect.arrayContaining([profile.native_tool_installations![0], ready.installation]) })));
    expect(api.inspectNativeToolCandidate).toHaveBeenCalledWith(profile.id, "/usr/bin/chmod", "9.4");
  });

  it("does not offer save for an unavailable candidate and clears readiness on edits", async () => {
    vi.mocked(api.inspectNativeToolCandidate).mockResolvedValueOnce({ ...ready, status: "unavailable", code: "inspection_unavailable", installation: null });
    const { user, onSave } = openDialog();
    await user.click(screen.getByRole("button", { name: "Set up GNU chmod" }));
    await user.type(screen.getByLabelText("Declared GNU version"), "9.4");
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
    await user.type(screen.getByLabelText("Declared GNU version"), "9.4");
    await user.click(screen.getByRole("button", { name: "Inspect installation" }));
    await user.clear(screen.getByLabelText("Installation location"));
    await user.type(screen.getByLabelText("Installation location"), "/usr/local/bin/chmod");
    resolve(ready);
    await new Promise((done) => setTimeout(done, 0));
    expect(screen.queryByText("Protected installation verified")).not.toBeInTheDocument();
  });

  it("can inspect again after invalidating a stale request", async () => {
    let resolve!: (value: NativeToolCandidateInspection) => void;
    vi.mocked(api.inspectNativeToolCandidate)
      .mockReturnValueOnce(new Promise((done) => { resolve = done; }))
      .mockResolvedValueOnce({ ...ready, installation: { ...ready.installation!, installation_location: "/usr/local/bin/chmod" } });
    const { user } = openDialog();
    await user.click(screen.getByRole("button", { name: "Set up GNU chmod" }));
    await user.type(screen.getByLabelText("Declared GNU version"), "9.4");
    await user.click(screen.getByRole("button", { name: "Inspect installation" }));
    await user.clear(screen.getByLabelText("Installation location"));
    await user.type(screen.getByLabelText("Installation location"), "/usr/local/bin/chmod");
    resolve(ready);
    await user.click(screen.getByRole("button", { name: "Inspect installation" }));
    await screen.findByText("Protected installation verified");
    expect(api.inspectNativeToolCandidate).toHaveBeenLastCalledWith(profile.id, "/usr/local/bin/chmod", "9.4");
  });

  it("clears a verified result when the operator edits the location", async () => {
    vi.mocked(api.inspectNativeToolCandidate).mockResolvedValueOnce(ready);
    const { user } = openDialog();
    await user.click(screen.getByRole("button", { name: "Set up GNU chmod" }));
    await user.type(screen.getByLabelText("Declared GNU version"), "9.4");
    await user.click(screen.getByRole("button", { name: "Inspect installation" }));
    await screen.findByRole("status", { name: "Protected installation verified" });
    await user.type(screen.getByLabelText("Installation location"), "-backup");
    expect(screen.queryByRole("status", { name: "Protected installation verified" })).not.toBeInTheDocument();
  });

  it("invalidates a verified result when the profile changes", async () => {
    vi.mocked(api.inspectNativeToolCandidate).mockResolvedValueOnce(ready);
    const user = userEvent.setup();
    const view = render(<NativeToolSetupDialog profile={profile} onSave={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: "Set up GNU chmod" }));
    await user.type(screen.getByLabelText("Declared GNU version"), "9.4");
    await user.click(screen.getByRole("button", { name: "Inspect installation" }));
    await screen.findByRole("status", { name: "Protected installation verified" });
    view.rerender(<NativeToolSetupDialog profile={{ ...profile, id: "other-profile.v1" }} onSave={vi.fn()} />);
    expect(screen.queryByRole("status", { name: "Protected installation verified" })).not.toBeInTheDocument();
  });
});
