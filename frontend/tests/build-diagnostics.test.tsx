import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { BuildDiagnostics } from "../src/components/BuildDiagnostics";
import { api, type BuildInfo } from "../src/lib/api";

const info: BuildInfo = { schema_version: "bluefire.build-info.v1", product:{name:"BlueFire Nexus",version:"3.0.0"}, source:{revision:"a".repeat(40),provenance:"git_archive"}, build:{metadata_status:"embedded",digest:"sha256:build"}, ui:{matches_build:true,digest:"sha256:ui",files:[]} };
const clients: QueryClient[] = [];
afterEach(() => { clients.splice(0).forEach(client => client.clear()); });
function mount() { const client = new QueryClient({defaultOptions:{queries:{retry:false}}}); clients.push(client); return render(<QueryClientProvider client={client}><BuildDiagnostics/></QueryClientProvider>); }
it("keeps recorded revision in accessible details and distinguishes service assets from the browser", async () => {
  vi.spyOn(api,"buildInfo").mockResolvedValue(info); const user = userEvent.setup(); mount();
  expect(await screen.findByText("Packaged UI files match this build.")).toBeVisible();
  expect(screen.getByText(info.source.revision!)).not.toBeVisible();
  await user.click(screen.getByText("Build and asset identity"));
  expect(screen.getByText(info.source.revision!)).toBeVisible();
  expect(screen.getByText(/do not identify a cached browser page/)).toBeVisible();
});
it.each([false,null] as const)("does not claim agreement when the result is %s", async matches => {
  vi.spyOn(api,"buildInfo").mockResolvedValue({...info,ui:{...info.ui,matches_build:matches}}); mount();
  expect(await screen.findByText(matches === false ? /UI files differ/ : /no usable build record/)).toBeVisible();
  expect(screen.queryByText("Packaged UI files match this build.")).not.toBeInTheDocument();
});
it("retries unavailable diagnostics without reporting a version or match", async () => {
  const request = vi.spyOn(api,"buildInfo").mockRejectedValueOnce(new Error("Service offline")).mockResolvedValue(info); const user = userEvent.setup(); mount();
  await screen.findByText("Package details unavailable");
  expect(screen.queryByText(/BlueFire Nexus 3/)).not.toBeInTheDocument();
  await user.click(screen.getByRole("button",{name:"Try again"}));
  expect(await screen.findByText("BlueFire Nexus 3.0.0")).toBeVisible(); expect(request).toHaveBeenCalledTimes(2);
});
