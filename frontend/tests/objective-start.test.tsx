import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ObjectiveStart } from "../src/components/ObjectiveStart";
import { fileAccessApi } from "../src/lib/file-access";
import { adSmbApi } from "../src/lib/ad-smb";
import { s3Api } from "../src/lib/s3-access";
import type { FileAccessStatus } from "../src/lib/file-access";

function Navigation() {
  const location = useLocation();
  const navigate = useNavigate();
  return <><output aria-label="Current location">{location.pathname}{location.search}</output><button onClick={() => navigate(-1)}>Return to start</button></>;
}

function mount(path = "/getting-started", cachedStatus?: FileAccessStatus) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  if (cachedStatus) client.setQueryData(["file-access-status"], cachedStatus);
  const view = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><Navigation /><Routes>
    <Route path="/getting-started" element={<ObjectiveStart />} />
    <Route path="*" element={<h1>Existing environment review</h1>} />
  </Routes></MemoryRouter></QueryClientProvider>);
  return { ...view, client };
}

beforeEach(() => {
  vi.spyOn(fileAccessApi, "status").mockResolvedValue({ schema_version: "bluefire.file-access-status.v1", available: false, enrollment: null, allowed_operations: [], problem: { code: "not_enrolled", message: "No enrolled workspace." } });
  vi.spyOn(fileAccessApi, "list").mockResolvedValue({ schema_version: "bluefire.file-access-control-list.v1", controls: [] });
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it("requires a deliberate objective choice without creating any stored authority", () => {
  const before = { ...localStorage };
  mount();
  expect(screen.getByRole("combobox", { name: "Objective" })).toHaveValue("");
  expect(screen.getByRole("button", { name: "Review environment" })).toBeDisabled();
  expect(screen.queryByRole("link")).not.toBeInTheDocument();
  expect({ ...localStorage }).toEqual(before);
  expect(fileAccessApi.status).not.toHaveBeenCalled();
  expect(fileAccessApi.list).not.toHaveBeenCalled();
});

it.each([
  ["data-handoff", "/compare?context=retained&receiver=1&goal=data-handoff", "Retained receiver redaction policy"],
  ["file-access", "/file-access?context=retained&goal=file-access", "File permission correction"],
  ["ad-access", "/ad-smb?context=retained&goal=ad-access", "Scoped share permission correction"],
  ["s3-access", "/s3-access?context=retained&goal=s3-access", "Scoped bucket-policy correction"],
])("opens only the existing %s review and restores the choice on Back", async (goal, target, change) => {
  const user = userEvent.setup();
  const before = { ...localStorage };
  mount("/getting-started?context=retained");
  await user.selectOptions(screen.getByRole("combobox", { name: "Objective" }), goal);
  expect(screen.getByText(change)).toBeVisible();
  if (goal === "file-access") {
    expect(await screen.findByText("No current workspace")).toBeVisible();
    expect(await screen.findByText("0 saved controls")).toBeVisible();
  } else {
    expect(screen.getByText("Not checked here")).toBeVisible();
  }
  expect(screen.getByLabelText("Current location")).toHaveTextContent(`/getting-started?context=retained&goal=${goal}`);
  const link = screen.getByRole("link", { name: "Review environment" });
  expect(link).toHaveAttribute("href", target);
  await user.click(link);
  expect(screen.getByRole("heading", { name: "Existing environment review" })).toBeVisible();
  expect(screen.getByLabelText("Current location")).toHaveTextContent(target);
  await user.click(screen.getByRole("button", { name: "Return to start" }));
  expect(screen.getByRole("combobox", { name: "Objective" })).toHaveValue(goal);
  expect({ ...localStorage }).toEqual(before);
  if (goal !== "file-access") {
    expect(fileAccessApi.status).not.toHaveBeenCalled();
    expect(fileAccessApi.list).not.toHaveBeenCalled();
  }
});

it("restores a valid direct URL without triggering preparation and permits clearing it", async () => {
  mount("/getting-started?goal=s3-access&context=retained");
  expect(screen.getByRole("combobox", { name: "Objective" })).toHaveValue("s3-access");
  await userEvent.selectOptions(screen.getByRole("combobox", { name: "Objective" }), "");
  expect(screen.getByRole("button", { name: "Review environment" })).toBeDisabled();
  expect(screen.getByLabelText("Current location")).toHaveTextContent("/getting-started?context=retained");
});

it.each(["data-handoff", "ad-access", "s3-access"])("labels direct %s scope as requirements, not verified resources", (goal) => {
  const before = { ...localStorage };
  mount(`/getting-started?goal=${goal}`);
  expect(screen.getByText("Required environment")).toBeVisible();
  expect(screen.getByText("Planned test data")).toBeVisible();
  expect(screen.getByText("Proposed change")).toBeVisible();
  expect(screen.getByText("Workspace setup")).toBeVisible();
  expect(screen.getByText("Not checked here")).toBeVisible();
  expect(screen.queryByText("Environment", { exact: true })).not.toBeInTheDocument();
  expect(screen.queryByText("Test data", { exact: true })).not.toBeInTheDocument();
  expect({ ...localStorage }).toEqual(before);
});

it("keeps saved setup distinct from active workspace readiness and task access", async () => {
  vi.mocked(fileAccessApi.status).mockResolvedValue({
    schema_version: "bluefire.file-access-status.v1",
    available: false,
    problem: { code: "windows_native_admission_unavailable", message: "Native access is unavailable." },
    enrollment: null,
    allowed_operations: [],
    setup: { enrollment_id: "enrollment-1", enrollment_digest: "sha256:" + "a".repeat(64), expires_at_ms: Date.now() + 60_000, verification: "protected_setup_only" },
  });
  mount("/getting-started?goal=file-access");
  expect(await screen.findByText("Setup receipt found")).toBeVisible();
  expect(screen.getByText("Effective access").nextElementSibling).toHaveTextContent("Not tested");
});

it("distinguishes an available paired setup from tested effective access", async () => {
  vi.mocked(fileAccessApi.status).mockResolvedValue({
    schema_version: "bluefire.file-access-status.v1",
    available: true,
    problem: null,
    enrollment: null,
    allowed_operations: [],
    setup: { enrollment_id: "enrollment-1", enrollment_digest: "sha256:" + "a".repeat(64), expires_at_ms: Date.now() + 60_000, verification: "protected_setup_only" },
  });
  mount("/getting-started?goal=file-access");
  expect(await screen.findByText("Paired setup available")).toBeVisible();
  expect(screen.getByText("Effective access").nextElementSibling).toHaveTextContent("Not tested");
});

it("labels expired protected setup as a historical receipt rather than current readiness", async () => {
  vi.mocked(fileAccessApi.status).mockResolvedValue({
    schema_version: "bluefire.file-access-status.v1",
    available: true,
    problem: null,
    enrollment: null,
    allowed_operations: [],
    setup: { enrollment_id: "enrollment-1", enrollment_digest: "sha256:" + "a".repeat(64), expires_at_ms: Date.now() - 1, verification: "protected_setup_only" },
  });
  mount("/getting-started?goal=file-access");
  expect(await screen.findByText("Setup receipt expired")).toBeVisible();
  expect(screen.queryByText("Paired setup available")).not.toBeInTheDocument();
  expect(screen.getByText("Effective access").nextElementSibling).toHaveTextContent("Not tested");
});

it("labels an expired workspace enrollment as no longer current", async () => {
  vi.mocked(fileAccessApi.status).mockResolvedValue({
    schema_version: "bluefire.file-access-status.v1",
    available: true,
    problem: null,
    enrollment: { enrollment_id: "enrollment-1", enrollment_digest: "sha256:" + "a".repeat(64), expires_at_ms: Date.now() - 1, owner_uid: 1000, probe_uid: 1001 },
    allowed_operations: ["create"],
  });
  mount("/getting-started?goal=file-access");
  expect(await screen.findByText("Workspace enrollment expired")).toBeVisible();
  expect(screen.queryByText("Workspace recognized")).not.toBeInTheDocument();
});

it("replaces cached readiness with Checking while a background status refresh is pending", async () => {
  const cached: FileAccessStatus = {
    schema_version: "bluefire.file-access-status.v1",
    available: true,
    problem: null,
    enrollment: null,
    allowed_operations: [],
    setup: { enrollment_id: "enrollment-1", enrollment_digest: "sha256:" + "a".repeat(64), expires_at_ms: Date.now() + 60_000, verification: "protected_setup_only" },
  };
  let resolveStatus!: (status: FileAccessStatus) => void;
  vi.mocked(fileAccessApi.status).mockImplementation(() => new Promise(resolve => { resolveStatus = resolve; }));
  mount("/getting-started?goal=file-access", cached);
  expect(await screen.findByText("Checking", { exact: true })).toBeVisible();
  expect(screen.queryByText("Paired setup available")).not.toBeInTheDocument();
  await act(async () => { resolveStatus(cached); });
  expect(await screen.findByText("Paired setup available", { exact: true })).toBeVisible();
});

it("shows selected file-access read failures as unavailable with an explicit retry", async () => {
  vi.mocked(fileAccessApi.status).mockRejectedValue(new Error("Status unavailable"));
  vi.mocked(fileAccessApi.list).mockRejectedValue(new Error("Saved controls unavailable"));
  mount("/getting-started?goal=file-access");
  expect(await screen.findAllByText("Unavailable")).toHaveLength(2);
  expect(screen.getByRole("button", { name: "Retry" })).toBeVisible();
});

it.each(["unknown", "__proto__", "https://example.test"])("refuses an unsupported goal %s without selecting another question", (goal) => {
  mount(`/getting-started?goal=${encodeURIComponent(goal)}`);
  expect(screen.getByRole("alert")).toHaveTextContent("This objective is unavailable");
  expect(screen.getByRole("combobox", { name: "Objective" })).toHaveValue("");
  expect(screen.getByRole("button", { name: "Review environment" })).toBeDisabled();
  expect(screen.queryByRole("link")).not.toBeInTheDocument();
});

it("does not check AD or S3 readiness merely because those objectives are selected", () => {
  const ad = vi.spyOn(adSmbApi, "environments");
  const s3 = vi.spyOn(s3Api, "environments");
  mount("/getting-started?goal=ad-access");
  expect(screen.getByText("Not checked here")).toBeVisible();
  expect(ad).not.toHaveBeenCalled();
  expect(s3).not.toHaveBeenCalled();
});
