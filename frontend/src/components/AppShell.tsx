import * as Tooltip from "@radix-ui/react-tooltip";
import { useQuery } from "@tanstack/react-query";
import {
  Activity, Bot, Braces, BookOpen, ChevronDown, ChevronLeft, FlaskConical, GitCompareArrows, HelpCircle,
  Home, ListChecks, Menu, MoreHorizontal, Network, PackageCheck, PlaySquare, Puzzle, ScrollText, Settings, SlidersHorizontal, X,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { api, DEMO_MODE } from "../lib/api";
import { demoScenario } from "../lib/demo";
import { useProduct } from "../state/ProductContext";
import { AssistanceProvider } from "../state/AssistanceContext";
import { ExperimentAssistant } from "./ExperimentAssistant";
import { LabSessionNotice } from "./LabSessionNotice";
import { Badge, IconButton } from "./Primitives";
import "./AppShell.css";

const workItems = [
  { to: "/builder", label: "Build", icon: Network },
  { to: "/runs", label: "Runs", icon: PlaySquare },
  { to: "/detection-lab", label: "Detection Lab", icon: FlaskConical },
  { to: "/compare", label: "Compare", icon: GitCompareArrows },
  { to: "/scenarios", label: "Experiments", icon: ScrollText },
  { to: "/settings", label: "Settings", icon: Settings },
];
const settingsItems = [
  { to: "/runners", label: "Runners", icon: Activity },
  { to: "/runner-profiles", label: "Runner Profiles", icon: SlidersHorizontal },
  { to: "/actions", label: "Actions & Plugins", icon: Puzzle },
  { to: "/action-packages", label: "Action Packages", icon: PackageCheck },
];
const moreItems = [
  { to: "/", label: "Overview", icon: Home },
  { to: "/getting-started", label: "Getting Started", icon: ListChecks },
  { to: "/behaviors", label: "Behaviors", icon: Braces },
  { to: "/research-sources", label: "Research Sources", icon: BookOpen },
  { to: "/ai-planner", label: "AI Planner", icon: Bot },
  { to: "/help", label: "Help & Docs", icon: HelpCircle },
];
const allItems = [...workItems, ...settingsItems, ...moreItems];

function FlameMark() {
  return <svg className="brand-mark" viewBox="0 0 44 52" role="img" aria-label="BlueFire flame"><path d="M24 2c2 10-8 13-4 23 2 4 7 5 8 11 1 5-2 9-6 12 12-1 20-9 20-20 0-9-5-18-18-26Z"/><path className="brand-core" d="M18 21c0 8-10 10-10 20 0 5 4 9 10 9 7 0 12-5 12-12 0-6-4-11-7-14 0 6-4 9-7 8-4-2 1-7 2-11Z"/></svg>;
}

export function AppShell() {
  return <AssistanceProvider><WorkspaceShell /></AssistanceProvider>;
}

function WorkspaceShell() {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const location = useLocation();
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [moreOpen, setMoreOpen] = useState(false);
  const sidebarRef = useRef<HTMLElement>(null);
  const menuButtonRef = useRef<HTMLButtonElement>(null);
  const { theme, scenario, scenarioIsSeededFallback, setScenario } = useProduct();
  const catalog = useQuery({ queryKey: ["catalog"], queryFn: api.catalog, retry: 1, staleTime: 60_000 });
  const scenarios = useQuery({ queryKey: ["scenarios"], queryFn: api.scenarios, retry: 1, staleTime: 60_000 });
  useEffect(() => {
    if (theme !== "system") {
      document.documentElement.dataset.theme = theme;
      return;
    }
    const colorScheme = window.matchMedia?.("(prefers-color-scheme: light)");
    if (!colorScheme) return;
    const applySystemTheme = (matches: boolean) => { document.documentElement.dataset.theme = matches ? "light" : "dark"; };
    const handleColorSchemeChange = (event: MediaQueryListEvent) => applySystemTheme(event.matches);
    applySystemTheme(colorScheme.matches);
    colorScheme.addEventListener("change", handleColorSchemeChange);
    return () => colorScheme.removeEventListener("change", handleColorSchemeChange);
  }, [theme]);
  useEffect(() => {
    if (DEMO_MODE || !scenarioIsSeededFallback || scenario.id !== demoScenario.id || !catalog.data || !scenarios.data) return;
    const registered = new Set(catalog.data.behaviors.map((behavior) => behavior.id));
    if (scenario.steps.every((step) => registered.has(step.behavior_id))) return;
    const replacement = scenarios.data.scenarios.find((candidate) => candidate.steps.length > 0 && candidate.steps.every((step) => registered.has(step.behavior_id)));
    if (replacement) setScenario(structuredClone(replacement), false);
  }, [catalog.data, scenario, scenarioIsSeededFallback, scenarios.data, setScenario]);
  useEffect(() => {
    setMobileOpen(false);
    if (location.pathname === "/settings" || settingsItems.some((item) => item.to === location.pathname)) setSettingsOpen(true);
    if (moreItems.some((item) => item.to !== "/" && item.to === location.pathname)) setMoreOpen(true);
    window.scrollTo({ top: 0, left: 0, behavior: "auto" });
    document.getElementById("main-content")?.scrollTo?.({ top: 0, left: 0, behavior: "auto" });
  }, [location.pathname]);
  useEffect(() => {
    if (!mobileOpen) return;
    const menuButton = menuButtonRef.current;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    sidebarRef.current?.querySelector<HTMLButtonElement>(".mobile-close")?.focus();
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") { event.preventDefault(); setMobileOpen(false); return; }
      if (event.key !== "Tab") return;
      const controls = Array.from(sidebarRef.current?.querySelectorAll<HTMLElement>('a[href], button:not([disabled])') ?? [])
        .filter((control) => getComputedStyle(control).display !== "none" && getComputedStyle(control).visibility !== "hidden");
      const first = controls[0];
      const last = controls.at(-1);
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
    };
    document.addEventListener("keydown", handleKey);
    const viewport = window.matchMedia?.("(max-width: 900px)");
    const handleViewport = (event: MediaQueryListEvent) => { if (!event.matches) setMobileOpen(false); };
    viewport?.addEventListener("change", handleViewport);
    return () => {
      document.body.style.overflow = previousOverflow;
      document.removeEventListener("keydown", handleKey);
      viewport?.removeEventListener("change", handleViewport);
      menuButton?.focus();
    };
  }, [mobileOpen]);
  const current = allItems.find((item) => item.to === location.pathname || (item.to === "/runs" && location.pathname.startsWith("/runs/")))?.label ?? "BlueFire Nexus";
  const renderLink = (item: typeof allItems[number]) => {
    const Icon = item.icon;
    const link = <NavLink to={item.to} end={item.to === "/"} aria-label={item.label} onClick={() => setMobileOpen(false)} className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}><Icon aria-hidden="true"/><span>{item.label}</span></NavLink>;
    return collapsed ? <Tooltip.Root key={item.to}><Tooltip.Trigger asChild>{link}</Tooltip.Trigger><Tooltip.Portal><Tooltip.Content className="tooltip" side="right" sideOffset={10}>{item.label}</Tooltip.Content></Tooltip.Portal></Tooltip.Root> : <span key={item.to}>{link}</span>;
  };

  return <>
    <a className="skip-link" href="#main-content" onClick={(event) => { event.preventDefault(); document.getElementById("main-content")?.focus(); }}>Skip to content</a>
    <Tooltip.Provider delayDuration={350}>
    <div className={`app-shell workbench-shell ${collapsed ? "nav-collapsed" : ""}`}>
      <header className="mobile-header" inert={mobileOpen}>
        <button ref={menuButtonRef} aria-label="Open navigation" aria-expanded={mobileOpen} aria-controls="workspace-navigation" onClick={() => setMobileOpen(true)}><Menu /></button>
        <a className="brand" href="#/" aria-label="BlueFire Nexus home"><FlameMark/><span><strong>BlueFire Nexus</strong><small>Research workspace</small></span></a>
        <span role="img" className={`service-light ${catalog.isSuccess ? "ready" : catalog.isError ? "error" : "pending"}`} aria-label={catalog.isSuccess ? "Local service connected" : catalog.isError ? "Local service unavailable" : "Connecting"} />
      </header>
      <div className={`mobile-scrim ${mobileOpen ? "visible" : ""}`} onClick={() => setMobileOpen(false)} aria-hidden="true" />
      <aside ref={sidebarRef} id="workspace-navigation" className={`sidebar ${mobileOpen ? "mobile-open" : ""}`} role={mobileOpen ? "dialog" : undefined} aria-modal={mobileOpen || undefined} aria-label="Workspace navigation">
        <div className="sidebar-brand-row"><a className="brand" href="#/" aria-label="BlueFire Nexus home" onClick={() => setMobileOpen(false)}><FlameMark/><span><strong>BlueFire Nexus</strong><small>Research workspace</small></span></a><button className="mobile-close" aria-label="Close navigation" onClick={() => setMobileOpen(false)}><X /></button></div>
        <nav aria-label="Primary navigation">
          <div className="nav-group work-nav">{workItems.map(renderLink)}</div>
          <button className="nav-disclosure" aria-label={settingsOpen ? "Hide settings tools" : "Show settings tools"} aria-expanded={settingsOpen} aria-controls="settings-navigation" onClick={() => setSettingsOpen((value) => !value)}><SlidersHorizontal aria-hidden="true"/><span>Settings tools</span><ChevronDown aria-hidden="true"/></button>
          {settingsOpen && <div id="settings-navigation" className="nav-group secondary-nav" aria-label="Settings tools">{settingsItems.map(renderLink)}</div>}
          <button className="nav-disclosure" aria-label={moreOpen ? "Hide more tools" : "Show more tools"} aria-expanded={moreOpen} aria-controls="more-navigation" onClick={() => setMoreOpen((value) => !value)}><MoreHorizontal aria-hidden="true"/><span>More tools</span><ChevronDown aria-hidden="true"/></button>
          {moreOpen && <div id="more-navigation" className="nav-group secondary-nav" aria-label="More tools">{moreItems.map(renderLink)}</div>}
        </nav>
        <div className="sidebar-status">
          <div><span className={`service-light ${catalog.isSuccess ? "ready" : catalog.isError ? "error" : "pending"}`} role="img" aria-label={catalog.isSuccess ? "Local service ready" : catalog.isError ? "Service unavailable" : "Connecting locally"}/><span><strong>{catalog.isSuccess ? "Local service ready" : catalog.isError ? "Service unavailable" : "Connecting locally"}</strong>{DEMO_MODE && <small>Demo workspace</small>}</span></div>
        </div>
        <IconButton label={collapsed ? "Expand navigation" : "Collapse navigation"} className="sidebar-collapse" onClick={() => setCollapsed((value) => !value)}><ChevronLeft /></IconButton>
      </aside>
      <div className="workspace-shell" inert={mobileOpen}>
        <header className="workspace-topbar"><div><strong>{current}</strong></div><div className="topbar-actions"><ExperimentAssistant providers={catalog.data?.ai.providers ?? []} /><Badge tone={catalog.isSuccess ? "success" : catalog.isError ? "danger" : "warning"} dot>{catalog.isSuccess ? "Connected" : catalog.isError ? "Offline" : "Connecting"}</Badge>{DEMO_MODE && <Badge tone="violet">Demo</Badge>}</div></header>
        <main id="main-content" tabIndex={-1}><LabSessionNotice providers={catalog.data?.ai.providers} /><Outlet /></main>
      </div>
    </div>
    </Tooltip.Provider>
  </>;
}
