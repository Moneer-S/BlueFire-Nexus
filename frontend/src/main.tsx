import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { HashRouter } from "react-router-dom";
import "@xyflow/react/dist/style.css";
import App from "./App";
import { BrowserConnection } from "./components/BrowserConnection";
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
  // Retire an old session GET before checking the newly established authority.
  // No job mutation, runner probe or other workspace query is replayed here.
  void queryClient.cancelQueries({ queryKey: ["service-connection"], exact: true }).then(() =>
    queryClient.invalidateQueries({ queryKey: ["service-connection"], exact: true }));
};
const connected = () => {
  if (!workspaceMounted) {
    workspaceMounted = true;
    root.render(
      <StrictMode><QueryClientProvider client={queryClient}><ProductProvider><HashRouter><RememberSessionRoute /><App /></HashRouter></ProductProvider></QueryClientProvider></StrictMode>,
    );
  } else recheckConnection();
};
const sessionWatch = watchBrowserSession({
  connected,
  unavailable: () => {
    if (workspaceMounted) { recheckConnection(); return; }
    root.render(
      <StrictMode>
        <BrowserConnection connected={connected} />
      </StrictMode>,
    );
  },
});
function RememberSessionRoute() { useBrowserSessionRoute(sessionWatch.rememberRoute); return null; }
if (import.meta.hot) import.meta.hot.dispose(sessionWatch.dispose);
