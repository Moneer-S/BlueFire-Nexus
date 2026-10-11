import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Link, MemoryRouter, useLocation } from "react-router-dom";
import { beforeEach, expect, it, vi } from "vitest";
import { S3Setup } from "../src/pages/S3Setup";
import { api } from "../src/lib/api";
import { checkedSetup, checkedSetupProfiles, s3SetupApi, type S3ConfigurationState, type S3SetupCheck, type S3SetupProfile } from "../src/lib/s3-setup";

vi.mock("../src/components/ExecuteRunnerReadiness", () => ({ ExecuteRunnerReadiness: ({ profileId }: { profileId: string }) => <section aria-label="Existing runner controls">{profileId}</section> }));
const hash = `sha256:${"a".repeat(64)}`;
const selected: S3SetupProfile = { profile_id: "s3-primary", profile_digest: hash };
const other = { ...selected, profile_id: "s3-secondary" };
function result(state: S3ConfigurationState = "configured", profile = selected): S3SetupCheck {
  return { schema_version: "bluefire.s3-onboarding-check.v1", ...profile, host_state: "authenticated", context_digest: hash, setup: { schema_version: "bluefire.s3-setup-status.v1", profile_id: profile.profile_id, context_digest: hash, configuration_state: state, revision_digest: ["configured", "profile_missing", "profile_changed"].includes(state) ? hash : null, environments: state === "configured" ? [{ environment_id: "test-environment", runtime_state: "verified", access_reference_state: "current", scope_state: "current", fixture_generation: 1 }] : [] } };
}
function Location() { return <output aria-label="Current location">{useLocation().search}</output>; }
function mount(path = "/s3-access?setup=1") {
  const cache = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const close = vi.fn();
  return { cache, close, user: userEvent.setup(), ...render(<QueryClientProvider client={cache}><MemoryRouter initialEntries={[path]}><S3Setup onClose={close} /><Location /><Link to="/s3-access?setup=1&setup_profile=s3-secondary">Select second through navigation</Link></MemoryRouter></QueryClientProvider>) };
}
beforeEach(() => {
  vi.spyOn(api, "resources").mockResolvedValue({ schema_version: "bluefire.resource-list.v1", kind: "runner-profiles", resources: [] });
  vi.spyOn(s3SetupApi, "profiles").mockResolvedValue({ schema_version: "bluefire.s3-onboarding.v1", profiles: [selected], truncated: false });
  vi.spyOn(s3SetupApi, "check").mockResolvedValue(result());
});

it("recovers an inactive S3 draft after reload without restoring current authority", async () => {
  vi.mocked(s3SetupApi.profiles).mockResolvedValue({ schema_version: "bluefire.s3-onboarding.v1", profiles: [], truncated: false });
  vi.mocked(api.resources).mockResolvedValue({ schema_version: "bluefire.resource-list.v1", kind: "runner-profiles", resources: [{
    kind: "runner-profiles", id: selected.profile_id, status: "inactive", digest: hash,
    created_at: "2026-10-11T00:00:00Z", updated_at: "2026-10-11T00:00:00Z",
    document: { id: selected.profile_id, capabilities: ["cloud.aws.s3.access"] },
  }] });
  const source = '{"synthetic":"retained"}';
  vi.spyOn(s3SetupApi, "savedDraft").mockResolvedValue({ schema_version: "bluefire.s3-saved-setup-draft.v1", draft: { ...selected, configuration_json: source, digest: hash, updated_at: "2026-10-11T00:00:00Z" } });
  const { user } = mount();
  await waitFor(() => expect(screen.getByLabelText("Linux S3 profile")).toHaveValue(selected.profile_id));
  expect(screen.getByRole("option", { name: `${selected.profile_id} (draft recovery only)` })).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Open saved draft" }));
  await waitFor(() => expect(screen.getByLabelText("Non-secret configuration JSON")).toHaveValue(source));
  for (const name of ["Check connection", "Review configuration", "Save draft", "Export configuration"]) expect(screen.getByRole("button", { name })).toBeDisabled();
  expect(screen.getByLabelText("Existing runner controls")).toBeEmptyDOMElement();
  expect(s3SetupApi.check).not.toHaveBeenCalled();
});

it("does not promote recovery metadata into an active profile", async () => {
  vi.mocked(api.resources).mockResolvedValue({ schema_version: "bluefire.resource-list.v1", kind: "runner-profiles", resources: [{
    kind: "runner-profiles", id: other.profile_id, status: "active", digest: hash,
    created_at: "2026-10-11T00:00:00Z", updated_at: "2026-10-11T00:00:00Z",
    document: { id: other.profile_id, enabled_actions: ["owned.aws.s3_access.v1"] },
  }] });
  const { user } = mount();
  await screen.findByRole("option", { name: `${other.profile_id} (draft recovery only)` });
  await user.selectOptions(screen.getByLabelText("Linux S3 profile"), other.profile_id);
  expect(screen.getByRole("button", { name: "Check connection" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Open saved draft" })).toBeEnabled();
  expect(screen.getByLabelText("Existing runner controls")).toBeEmptyDOMElement();
});

it("keeps active setup usable if recovery metadata is unavailable", async () => {
  vi.mocked(api.resources).mockRejectedValue(new Error("Recovery inventory unavailable"));
  mount();
  expect(await screen.findByText("Saved profile recovery choices unavailable")).toBeVisible();
  expect(screen.getByRole("button", { name: "Check connection" })).toBeEnabled();
});

it("requires an explicit check and keeps cloud access unverified", async () => {
  const { user } = mount();
  const button = await screen.findByRole("button", { name: "Check connection" });
  await waitFor(() => expect(button).toBeEnabled());
  expect(s3SetupApi.check).not.toHaveBeenCalled();
  await user.click(button);
  expect(await screen.findByText("Locally current")).toBeVisible();
  expect(screen.getByText("Not checked")).toBeVisible();
  expect(screen.getByText("Not enrolled")).toBeVisible();
  expect(s3SetupApi.check).toHaveBeenCalledWith(selected, expect.anything());
});

it.each([
  ["missing", "S3 configuration missing"], ["incomplete", "Setup recovery required"],
  ["invalid", "Local setup needs review"], ["unsupported_host", "Owned Linux host required"],
  ["method_unavailable", "S3 method unavailable"], ["profile_missing", "Profile not connected to S3"],
  ["profile_changed", "Installed profile is out of date"],
] as const)("shows the precise local setup state %s", async (state, title) => {
  vi.mocked(s3SetupApi.check).mockResolvedValue(result(state));
  const { user } = mount();
  await waitFor(() => expect(screen.getByRole("button", { name: "Check connection" })).toBeEnabled());
  await user.click(screen.getByRole("button", { name: "Check connection" }));
  expect(await screen.findByRole("heading", { name: title })).toBeVisible();
  expect(s3SetupApi.check).toHaveBeenCalledOnce();
});

it("offers profile setup when no eligible profile exists", async () => {
  vi.mocked(s3SetupApi.profiles).mockResolvedValue({ schema_version: "bluefire.s3-onboarding.v1", profiles: [], truncated: false });
  mount();
  expect(await screen.findByRole("link", { name: "Open runner profiles" })).toHaveAttribute("href", "/runner-profiles");
  expect(screen.getByRole("button", { name: "Check connection" })).toBeDisabled();
  expect(s3SetupApi.check).not.toHaveBeenCalled();
});

it("retains the chosen profile in navigation and does not check after reload", async () => {
  vi.mocked(s3SetupApi.profiles).mockResolvedValue({ schema_version: "bluefire.s3-onboarding.v1", profiles: [selected, other], truncated: false });
  const first = mount();
  await first.user.selectOptions(await screen.findByLabelText("Linux S3 profile"), other.profile_id);
  expect(screen.getByLabelText("Current location")).toHaveTextContent("setup_profile=s3-secondary");
  first.unmount();
  mount("/s3-access?setup=1&setup_profile=s3-secondary");
  await waitFor(() => expect(screen.getByLabelText("Linux S3 profile")).toHaveValue(other.profile_id));
  expect(s3SetupApi.check).not.toHaveBeenCalled();
});

it("does not display a late check for a different selected profile", async () => {
  vi.mocked(s3SetupApi.profiles).mockResolvedValue({ schema_version: "bluefire.s3-onboarding.v1", profiles: [selected, other], truncated: false });
  let resolve!: (value: S3SetupCheck) => void;
  vi.mocked(s3SetupApi.check).mockReturnValue(new Promise(done => { resolve = done; }));
  const { user } = mount("/s3-access?setup=1&setup_profile=s3-primary");
  await waitFor(() => expect(screen.getByRole("button", { name: "Check connection" })).toBeEnabled());
  await user.click(screen.getByRole("button", { name: "Check connection" }));
  await user.click(screen.getByRole("link", { name: "Select second through navigation" }));
  resolve(result());
  await waitFor(() => expect(screen.getByRole("button", { name: "Check connection" })).toBeEnabled());
  expect(screen.queryByText("Local checks recorded")).not.toBeInTheDocument();
  expect(screen.getByLabelText("Linux S3 profile")).toHaveValue(other.profile_id);
});

it("preserves selection after failure and removes stale results on profile refresh", async () => {
  const { user } = mount();
  await waitFor(() => expect(screen.getByRole("button", { name: "Check connection" })).toBeEnabled());
  await user.click(screen.getByRole("button", { name: "Check connection" }));
  await screen.findByText("Local checks recorded");
  vi.mocked(s3SetupApi.profiles).mockRejectedValue(new Error("Connection unavailable"));
  await user.click(screen.getByRole("button", { name: "Refresh profiles" }));
  expect(await screen.findByText("S3 profiles unavailable")).toBeVisible();
  expect(screen.queryByText("Local checks recorded")).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Check connection" })).toBeDisabled();
});

it.each(["profile", "digest", "unknown", "state", "reference", "boolean_generation", "duplicate", "unavailable_with_status"])("rejects a widened or inconsistent response: %s", mutation => {
  const value = result();
  if (mutation === "profile") value.profile_id = "other";
  else if (mutation === "digest") value.profile_digest = `sha256:${"b".repeat(64)}`;
  else if (mutation === "unknown") Object.assign(value, { credentials: "not allowed" });
  else if (mutation === "state") value.setup!.configuration_state = "missing";
  else if (mutation === "reference") Object.assign(value.setup!.environments[0]!, { access_reference_state: "aws_verified" });
  else if (mutation === "boolean_generation") Object.assign(value.setup!.environments[0]!, { fixture_generation: true });
  else if (mutation === "duplicate") value.setup!.environments.push(value.setup!.environments[0]!);
  else value.host_state = "unavailable";
  expect(() => checkedSetup(value, selected)).toThrow();
});

it("rejects extra or duplicated profile choices", () => {
  expect(() => checkedSetupProfiles({ schema_version: "bluefire.s3-onboarding.v1", profiles: [selected, selected], truncated: false })).toThrow();
  expect(() => checkedSetupProfiles(Object.assign({ schema_version: "bluefire.s3-onboarding.v1" as const, profiles: [selected], truncated: false }, { private_path: "/private" }))).toThrow();
});

it("accepts a revision-bound stale profile without presenting ready environments", () => {
  const value = result("profile_changed");
  expect(checkedSetup(value, selected)).toEqual(value);
  value.setup!.revision_digest = null;
  expect(() => checkedSetup(value, selected)).toThrow();
});
