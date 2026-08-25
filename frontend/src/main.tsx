import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { HashRouter } from "react-router-dom";
import "@xyflow/react/dist/style.css";
import App from "./App";
import { ProductProvider, readBrowserTheme } from "./state/ProductContext";
import "./styles.css";

const storedTheme = readBrowserTheme();
document.documentElement.dataset.theme = storedTheme === "system"
  ? window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark"
  : storedTheme;

const queryClient = new QueryClient({ defaultOptions: { queries: { retry: 1, staleTime: 15_000, refetchOnWindowFocus: false }, mutations: { retry: 0 } } });

createRoot(document.getElementById("root")!).render(
  <StrictMode><QueryClientProvider client={queryClient}><ProductProvider><HashRouter><App /></HashRouter></ProductProvider></QueryClientProvider></StrictMode>,
);
