import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { HashRouter } from "react-router-dom";
import "@xyflow/react/dist/style.css";
import App from "./App";
import { BROWSER_SESSION_RELAUNCH_MESSAGE, establishBrowserSession } from "./lib/api";
import { ProductProvider, readBrowserTheme } from "./state/ProductContext";
import "./styles.css";

const storedTheme = readBrowserTheme();
document.documentElement.dataset.theme = storedTheme === "system"
  ? window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark"
  : storedTheme;

const queryClient = new QueryClient({ defaultOptions: { queries: { retry: 1, staleTime: 15_000, refetchOnWindowFocus: false }, mutations: { retry: 0 } } });
const root = createRoot(document.getElementById("root")!);

async function start(): Promise<void> {
  try {
    await establishBrowserSession();
  } catch {
    root.render(
      <StrictMode>
        <main role="alert" aria-live="assertive" style={{ margin: "4rem auto", maxWidth: "42rem", padding: "1.5rem" }}>
          <h1>BlueFire session unavailable</h1>
          <p>{BROWSER_SESSION_RELAUNCH_MESSAGE}</p>
        </main>
      </StrictMode>,
    );
    return;
  }
  root.render(
    <StrictMode><QueryClientProvider client={queryClient}><ProductProvider><HashRouter><App /></HashRouter></ProductProvider></QueryClientProvider></StrictMode>,
  );
}

void start();
