import { useLayoutEffect } from "react";
import { useLocation } from "react-router-dom";
import { establishBrowserSession, hasBrowserBootstrapFragment } from "./api";

/** Install before the router: a launch fragment is a one-use credential, not a route. */
export function watchBrowserSession(callbacks: { connected: () => void; unavailable: () => void }): { dispose: () => void; rememberRoute: (hash: string) => void } {
  let generation = 0;
  let disposed = false;
  let route = window.location.hash.startsWith("#/") ? window.location.hash : "";
  const rememberRoute = (hash: string) => { if (hash.startsWith("#/")) route = hash; };
  const establish = (returnHash = "") => {
    const current = ++generation;
    // The async function consumes and scrubs the fragment synchronously, before
    // Router's navigation listener or any fetch can observe it as a product route.
    void establishBrowserSession(returnHash).then(() => {
      if (!disposed && current === generation) callbacks.connected();
    }, () => {
      if (!disposed && current === generation) callbacks.unavailable();
    });
  };
  const onNavigation = () => {
    if (hasBrowserBootstrapFragment()) establish(route);
    else route = window.location.hash.startsWith("#/") ? window.location.hash : "";
  };
  // Native fragment navigations can emit popstate before hashchange. Capture
  // both before HashRouter consumes an unknown fragment and replaces the URL.
  window.addEventListener("popstate", onNavigation, true);
  window.addEventListener("hashchange", onNavigation, true);
  establish();
  return { rememberRoute, dispose: () => {
    disposed = true; generation += 1;
    window.removeEventListener("popstate", onNavigation, true);
    window.removeEventListener("hashchange", onNavigation, true);
  } };
}

/** Router links use pushState without native navigation events. Remember their committed route. */
export function useBrowserSessionRoute(rememberRoute: (hash: string) => void) {
  const location = useLocation();
  useLayoutEffect(() => { rememberRoute(`#${location.pathname}${location.search}${location.hash}`); }, [rememberRoute, location.pathname, location.search, location.hash]);
}
