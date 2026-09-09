import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { HashRouter } from "react-router-dom";
import "@xyflow/react/dist/style.css";
import App from "./App";
import { BROWSER_SESSION_RELAUNCH_MESSAGE } from "./lib/api";
import { useBrowserSessionRoute, watchBrowserSession } from "./lib/browser-startup";
import { ProductProvider, readBrowserTheme } from "./state/ProductContext";
import "./styles.css";

const storedTheme = readBrowserTheme();
document.documentElement.dataset.theme = storedTheme === "system"
  ? window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark"
  : storedTheme;

const queryClient = new QueryClient({ defaultOptions: { queries: { retry: 1, staleTime: 15_000, refetchOnWindowFocus: false }, mutations: { retry: 0 } } });
const root = createRoot(document.getElementById("root")!);

let workspaceMounted = false;
const recheckConnection = () => {
  // Retire an old session GET before checking the newly established cookie.
  // No job mutation, runner probe or other workspace query is replayed here.
  void queryClient.cancelQueries({ queryKey: ["service-connection"], exact: true }).then(() =>
    queryClient.invalidateQueries({ queryKey: ["service-connection"], exact: true }));
};
const sessionWatch = watchBrowserSession({
  connected: () => {
    if (!workspaceMounted) {
      workspaceMounted = true;
      root.render(
        <StrictMode><QueryClientProvider client={queryClient}><ProductProvider><HashRouter><RememberSessionRoute /><App /></HashRouter></ProductProvider></QueryClientProvider></StrictMode>,
      );
    } else recheckConnection();
  },
  unavailable: () => {
    if (workspaceMounted) { recheckConnection(); return; }
    root.render(
      <StrictMode>
        <main role="alert" aria-live="assertive" style={{ margin: "4rem auto", maxWidth: "42rem", padding: "1.5rem" }}>
          <h1>BlueFire session unavailable</h1>
          <p>{BROWSER_SESSION_RELAUNCH_MESSAGE}</p>
        </main>
      </StrictMode>,
    );
  },
});
function RememberSessionRoute() { useBrowserSessionRoute(sessionWatch.rememberRoute); return null; }
if (import.meta.hot) import.meta.hot.dispose(sessionWatch.dispose);
