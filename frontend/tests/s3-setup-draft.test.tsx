import { webcrypto } from "node:crypto";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import configuration from "../../tests_platform/fixtures/s3_setup_draft_v3.json";
import * as downloads from "../src/lib/download";
import { checkedDraftReview, checkedSavedDraft, draftSourceDigest, MAX_S3_DRAFT_BYTES, s3SetupApi, savedDraftProfileId, type S3SavedSetupDraftResponse, type S3SetupDraftRequest, type S3SetupDraftReview, type S3SetupProfile } from "../src/lib/s3-setup";
import { S3SetupDraft } from "../src/pages/S3SetupDraft";

const hash = `sha256:${"a".repeat(64)}`;
const selected: S3SetupProfile = { profile_id: "s3-test", profile_digest: hash };
const source = `${JSON.stringify(configuration, null, 2)}\n`;
async function result(input: S3SetupDraftRequest): Promise<S3SetupDraftReview> {
  return { schema_version: "bluefire.s3-onboarding-draft-review.v1", profile_id: input.profile_id, profile_digest: input.profile_digest, validation_scope: "structural_only", source_sha256: await draftSourceDigest(input.configuration_json), configuration_digest: hash, environments: configuration.environments.map(row => ({ environment_id: row.environment_id, display_name: row.display_name, account_id: row.scope.account_id, region: row.scope.region, bucket: row.scope.bucket, expires_at: row.scope.expires_at, fixture_generation: 1 })) };
}
function saved(text = source, profile: S3SetupProfile = selected, digest = hash): S3SavedSetupDraftResponse {
  return { schema_version: "bluefire.s3-saved-setup-draft.v1", draft: { profile_id: profile.profile_id, profile_digest: profile.profile_digest, configuration_json: text, digest, updated_at: "2026-10-11T12:00:00Z" } };
}
function mount(profile: S3SetupProfile | undefined = selected, profileId?: string) {
  const cache = new QueryClient({ defaultOptions: { mutations: { retry: false } } });
  const tree = (value?: S3SetupProfile) => <QueryClientProvider client={cache}><S3SetupDraft selected={value} profileId={profileId} /></QueryClientProvider>;
  const view = render(tree(profile));
  return { ...view, user: userEvent.setup(), select: (value?: S3SetupProfile) => view.rerender(tree(value)) };
}
function edit(value = source) { fireEvent.change(screen.getByLabelText("Non-secret configuration JSON"), { target: { value } }); }
beforeEach(() => {
  vi.stubGlobal("crypto", webcrypto);
  vi.spyOn(s3SetupApi, "reviewDraft").mockImplementation(result);
  vi.spyOn(s3SetupApi, "savedDraft").mockResolvedValue({ schema_version: "bluefire.s3-saved-setup-draft.v1", draft: null });
  vi.spyOn(s3SetupApi, "saveDraft").mockImplementation(async input => saved(input.configuration_json, input));
  vi.spyOn(downloads, "downloadArtifact").mockImplementation(() => {});
});
afterEach(() => vi.unstubAllGlobals());

it("reviews only on explicit action and exports the exact reviewed source", async () => {
  const { user } = mount();
  edit();
  expect(s3SetupApi.reviewDraft).not.toHaveBeenCalled();
  expect(screen.getByRole("button", { name: "Export configuration" })).toBeDisabled();
  await user.click(screen.getByRole("button", { name: "Review configuration" }));
  expect(await screen.findByText("Structure checked")).toBeVisible();
  expect(screen.getByText("Not installed or authorized")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Export configuration" }));
  expect(s3SetupApi.reviewDraft).toHaveBeenCalledWith({ ...selected, configuration_json: source }, expect.anything());
  const [blob, name] = vi.mocked(downloads.downloadArtifact).mock.calls[0]!;
  const retained = await new Promise<string>((resolve, reject) => { const reader = new FileReader(); reader.onload = () => resolve(String(reader.result)); reader.onerror = reject; reader.readAsText(blob); });
  expect(retained).toBe(source);
  expect(name).toBe("bluefire-s3-configuration.json");
});

it("keeps the draft after profile failure and refuses export for a changed profile", async () => {
  const { user, select } = mount();
  edit();
  await user.click(screen.getByRole("button", { name: "Review configuration" }));
  await screen.findByText("Structure checked");
  select(undefined);
  expect(screen.getByLabelText("Non-secret configuration JSON")).toHaveValue(source);
  expect(screen.getByRole("button", { name: "Review configuration" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Export configuration" })).toBeDisabled();
  select({ ...selected, profile_digest: `sha256:${"b".repeat(64)}` });
  expect(screen.getByRole("button", { name: "Export configuration" })).toBeDisabled();
  expect(s3SetupApi.reviewDraft).toHaveBeenCalledOnce();
});

it("does not apply a late review to edited source", async () => {
  let resolve!: (value: S3SetupDraftReview) => void;
  vi.mocked(s3SetupApi.reviewDraft).mockReturnValue(new Promise(done => { resolve = done; }));
  const { user } = mount();
  edit();
  await user.click(screen.getByRole("button", { name: "Review configuration" }));
  edit(`${source}\n`);
  resolve(await result({ ...selected, configuration_json: source }));
  await waitFor(() => expect(screen.getByRole("button", { name: "Review configuration" })).toBeEnabled());
  expect(screen.getByRole("button", { name: "Export configuration" })).toBeDisabled();
  expect(screen.queryByText("Structure checked")).not.toBeInTheDocument();
});

it("retains the draft after a refused review", async () => {
  vi.mocked(s3SetupApi.reviewDraft).mockRejectedValue(new Error("Configuration refused"));
  const { user } = mount();
  edit();
  await user.click(screen.getByRole("button", { name: "Review configuration" }));
  expect(await screen.findByText("Configuration review refused")).toBeVisible();
  expect(screen.getByLabelText("Non-secret configuration JSON")).toHaveValue(source);
  expect(screen.getByRole("button", { name: "Export configuration" })).toBeDisabled();
});

it("refuses an oversized file without replacing a retained draft", async () => {
  const { user } = mount();
  edit();
  const file = new File(["x".repeat(MAX_S3_DRAFT_BYTES + 1)], "oversize.json", { type: "application/json" });
  const read = vi.fn();
  Object.defineProperty(file, "text", { value: read });
  await user.upload(screen.getByLabelText("Non-secret configuration file"), file);
  expect(await screen.findByText("Configuration input unavailable")).toBeVisible();
  expect(read).not.toHaveBeenCalled();
  expect(screen.getByLabelText("Non-secret configuration JSON")).toHaveValue(source);
  expect(s3SetupApi.reviewDraft).not.toHaveBeenCalled();
});

it("does not let a late file read replace a newer edit", async () => {
  const { user } = mount();
  let resolve!: (value: string) => void;
  const file = new File([source], "configuration.json", { type: "application/json" });
  Object.defineProperty(file, "text", { value: () => new Promise<string>(done => { resolve = done; }) });
  await user.upload(screen.getByLabelText("Non-secret configuration file"), file);
  edit("newer draft");
  resolve(source);
  await waitFor(() => expect(screen.getByLabelText("Non-secret configuration JSON")).toHaveValue("newer draft"));
  expect(s3SetupApi.reviewDraft).not.toHaveBeenCalled();
});

it.each(["profile", "source", "unknown", "scope", "generation", "duplicate"])("rejects a changed draft response: %s", async mutation => {
  const value = await result({ ...selected, configuration_json: source });
  const digest = value.source_sha256;
  if (mutation === "profile") value.profile_digest = `sha256:${"b".repeat(64)}`;
  else if (mutation === "source") value.source_sha256 = hash;
  else if (mutation === "unknown") Object.assign(value, { credentials: "not accepted" });
  else if (mutation === "scope") Object.assign(value, { validation_scope: "authorized" });
  else if (mutation === "generation") Object.assign(value.environments[0]!, { fixture_generation: true });
  else value.environments.push(value.environments[0]!);
  expect(() => checkedDraftReview(value, selected, digest)).toThrow();
});

it("enforces the encoded byte limit before review", async () => {
  await expect(draftSourceDigest("x".repeat(MAX_S3_DRAFT_BYTES + 1))).rejects.toThrow();
  await expect(draftSourceDigest("\u00e9".repeat(MAX_S3_DRAFT_BYTES))).rejects.toThrow();
});

it("saves only on explicit action after review and uses the accepted revision on the next save", async () => {
  const { user } = mount();
  edit();
  expect(s3SetupApi.savedDraft).not.toHaveBeenCalled();
  expect(s3SetupApi.saveDraft).not.toHaveBeenCalled();
  expect(screen.getByRole("button", { name: "Save draft" })).toBeDisabled();
  await user.click(screen.getByRole("button", { name: "Review configuration" }));
  await screen.findByText("Structure checked");
  await user.click(screen.getByRole("button", { name: "Save draft" }));
  expect(await screen.findByText("Draft saved.")).toBeVisible();
  expect(s3SetupApi.saveDraft).toHaveBeenLastCalledWith({ ...selected, configuration_json: source, expected_digest: null });
  expect(screen.getByRole("button", { name: "Save draft" })).toBeDisabled();
  edit(`${source}\n`);
  await user.click(screen.getByRole("button", { name: "Review configuration" }));
  await screen.findByText("Structure checked");
  await user.click(screen.getByRole("button", { name: "Save draft" }));
  await screen.findByText("Draft saved.");
  expect(s3SetupApi.saveDraft).toHaveBeenLastCalledWith({ ...selected, configuration_json: `${source}\n`, expected_digest: hash });
  expect(screen.getByText("Not installed or authorized")).toBeVisible();
});

it("reopens saved bytes without restoring review or execution authority", async () => {
  vi.mocked(s3SetupApi.savedDraft).mockResolvedValue(saved());
  const { user } = mount();
  await user.click(screen.getByRole("button", { name: "Open saved draft" }));
  await waitFor(() => expect(screen.getByLabelText("Non-secret configuration JSON")).toHaveValue(source));
  expect(s3SetupApi.savedDraft).toHaveBeenCalledWith(selected.profile_id);
  expect(screen.queryByText("Structure checked")).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Export configuration" })).toBeDisabled();
  expect(s3SetupApi.reviewDraft).not.toHaveBeenCalled();
  expect(s3SetupApi.saveDraft).not.toHaveBeenCalled();
});

it("cancels replacement without accepting the fetched revision as an overwrite base", async () => {
  vi.mocked(s3SetupApi.savedDraft).mockResolvedValue(saved(`${source}\n`));
  const { user } = mount();
  edit();
  await user.click(screen.getByRole("button", { name: "Open saved draft" }));
  expect(await screen.findByRole("dialog", { name: "Replace current configuration?" })).toBeVisible();
  expect(screen.getByRole("button", { name: "Cancel" })).toHaveFocus();
  await user.keyboard("{Escape}");
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  expect(screen.getByRole("button", { name: "Open saved draft" })).toHaveFocus();
  expect(screen.getByLabelText("Non-secret configuration JSON")).toHaveValue(source);
  await user.click(screen.getByRole("button", { name: "Review configuration" }));
  await screen.findByText("Structure checked");
  await user.click(screen.getByRole("button", { name: "Save draft" }));
  await screen.findByText("Draft saved.");
  expect(s3SetupApi.saveDraft).toHaveBeenLastCalledWith({ ...selected, configuration_json: source, expected_digest: null });
});

it("replaces inputs only after confirming the exact saved version", async () => {
  vi.mocked(s3SetupApi.savedDraft).mockResolvedValue(saved());
  const { user } = mount();
  edit("unsaved text");
  await user.click(screen.getByRole("button", { name: "Open saved draft" }));
  await screen.findByRole("dialog");
  await user.click(screen.getByRole("button", { name: "Open saved version" }));
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  expect(screen.getByLabelText("Non-secret configuration JSON")).toHaveValue(source);
  expect(screen.getByRole("button", { name: "Export configuration" })).toBeDisabled();
});

it.each(["edit", "profile"])("ignores a late saved draft after a newer %s", async change => {
  let resolve!: (value: S3SavedSetupDraftResponse) => void;
  vi.mocked(s3SetupApi.savedDraft).mockReturnValue(new Promise(done => { resolve = done; }));
  const { user, select } = mount();
  await user.click(screen.getByRole("button", { name: "Open saved draft" }));
  if (change === "edit") edit("newer input");
  else select({ ...selected, profile_digest: `sha256:${"b".repeat(64)}` });
  resolve(saved());
  await waitFor(() => expect(screen.getByRole("button", { name: "Open saved draft" })).toBeEnabled());
  expect(screen.getByLabelText("Non-secret configuration JSON")).toHaveValue(change === "edit" ? "newer input" : "");
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
});

it("does not replace text edited while a save is completing", async () => {
  let resolve!: (value: S3SavedSetupDraftResponse) => void;
  vi.mocked(s3SetupApi.saveDraft).mockReturnValue(new Promise(done => { resolve = done; }));
  const { user } = mount();
  edit();
  await user.click(screen.getByRole("button", { name: "Review configuration" }));
  await screen.findByText("Structure checked");
  await user.click(screen.getByRole("button", { name: "Save draft" }));
  edit(`${source}\n`);
  resolve(saved());
  expect(await screen.findByText("Current inputs differ from the saved draft.")).toBeVisible();
  expect(screen.getByLabelText("Non-secret configuration JSON")).toHaveValue(`${source}\n`);
  expect(screen.getByRole("button", { name: "Save draft" })).toBeDisabled();
});

it("retains source and the old revision after a conflicting save", async () => {
  vi.mocked(s3SetupApi.savedDraft).mockResolvedValue(saved());
  vi.mocked(s3SetupApi.saveDraft).mockRejectedValue(new Error("Another window changed the saved draft."));
  const { user } = mount();
  await user.click(screen.getByRole("button", { name: "Open saved draft" }));
  await screen.findByText("Draft saved.");
  edit(`${source}\n`);
  await user.click(screen.getByRole("button", { name: "Review configuration" }));
  await screen.findByText("Structure checked");
  await user.click(screen.getByRole("button", { name: "Save draft" }));
  expect(await screen.findByText("Saved draft not confirmed")).toBeVisible();
  expect(screen.getByLabelText("Non-secret configuration JSON")).toHaveValue(`${source}\n`);
  expect(s3SetupApi.saveDraft).toHaveBeenCalledWith({ ...selected, configuration_json: `${source}\n`, expected_digest: hash });
  expect(s3SetupApi.savedDraft).toHaveBeenCalledOnce();
});

it("opens stale-profile data without making it current or enabling a save", async () => {
  vi.mocked(s3SetupApi.savedDraft).mockResolvedValue(saved());
  const { user, select } = mount(selected, selected.profile_id);
  select(undefined);
  await user.click(screen.getByRole("button", { name: "Open saved draft" }));
  await waitFor(() => expect(screen.getByLabelText("Non-secret configuration JSON")).toHaveValue(source));
  expect(screen.getByText(/Saved for a different or unavailable profile version/)).toBeVisible();
  expect(screen.getByRole("button", { name: "Review configuration" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Save draft" })).toBeDisabled();
});

it("does not replace source when no saved draft exists or reading it fails", async () => {
  const { user } = mount();
  edit("retained input");
  await user.click(screen.getByRole("button", { name: "Open saved draft" }));
  expect(await screen.findByText("No saved configuration draft for this profile.")).toBeVisible();
  vi.mocked(s3SetupApi.savedDraft).mockRejectedValue(new Error("Saved data is unavailable."));
  await user.click(screen.getByRole("button", { name: "Open saved draft" }));
  expect(await screen.findByText("Saved draft not confirmed")).toBeVisible();
  expect(screen.getByLabelText("Non-secret configuration JSON")).toHaveValue("retained input");
});

it.each(["extra", "profile", "digest", "time", "source", "oversize", "schema"])("rejects an incomplete saved-draft response: %s", async mutation => {
  const value = saved();
  if (mutation === "extra") Object.assign(value.draft!, { installed: true });
  else if (mutation === "profile") value.draft!.profile_id = "another-profile";
  else if (mutation === "digest") value.draft!.digest = "not-a-digest";
  else if (mutation === "time") value.draft!.updated_at = "not-a-time";
  else if (mutation === "source") value.draft!.configuration_json = "[null]";
  else if (mutation === "oversize") value.draft!.configuration_json = "x".repeat(MAX_S3_DRAFT_BYTES + 1);
  else Object.assign(value, { schema_version: "authorized" });
  await expect(checkedSavedDraft(value, selected.profile_id)).rejects.toThrow();
});

it("binds save responses to the submitted source and profile, while permitting stale reads", async () => {
  const input = { ...selected, configuration_json: source };
  await expect(checkedSavedDraft(saved(`${source}\n`), selected.profile_id, input)).rejects.toThrow();
  const stale = saved(source, { ...selected, profile_digest: `sha256:${"b".repeat(64)}` });
  await expect(checkedSavedDraft(stale, selected.profile_id)).resolves.toEqual(stale);
  await expect(checkedSavedDraft(stale, selected.profile_id, input)).rejects.toThrow();
  await expect(checkedSavedDraft({ schema_version: "bluefire.s3-saved-setup-draft.v1", draft: null }, selected.profile_id, input)).rejects.toThrow();
  expect(savedDraftProfileId("../different")).toBe(false);
  expect(savedDraftProfileId("s3-test.v1")).toBe(true);
});
