import * as Tooltip from "@radix-ui/react-tooltip";
import { useQuery } from "@tanstack/react-query";
import {
  Activity, Bot, Boxes, Braces, BookOpen, ChevronLeft, FlaskConical, GitCompareArrows, HelpCircle,
  Home, ListChecks, Menu, Network, PackageCheck, PlaySquare, Puzzle, ScrollText, Settings, ShieldCheck, SlidersHorizontal, X,
} from "lucide-react";
import { useEffect, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { api, DEMO_MODE } from "../lib/api";
import { Badge, IconButton } from "./Primitives";

const groups = [
  { label: "Operate", items: [
    { to: "/", label: "Overview", icon: Home }, { to: "/getting-started", label: "Getting Started", icon: ListChecks },
    { to: "/scenarios", label: "Scenarios", icon: ScrollText },
    { to: "/builder", label: "Scenario Builder", icon: Network }, { to: "/runs", label: "Runs", icon: PlaySquare },
    { to: "/compare", label: "Compare", icon: GitCompareArrows },
  ] },
  { label: "Research", items: [
    { to: "/behaviors", label: "Behaviors", icon: Braces }, { to: "/detection-lab", label: "Detection Lab", icon: FlaskConical },
    { to: "/research-sources", label: "Research Sources", icon: BookOpen },
  ] },
  { label: "Infrastructure", items: [
    { to: "/runner-profiles", label: "Runner Profiles", icon: SlidersHorizontal }, { to: "/runners", label: "Runners", icon: Activity },
    { to: "/actions", label: "Actions & Plugins", icon: Puzzle }, { to: "/action-packages", label: "Action Packages", icon: PackageCheck },
  ] },
  { label: "System", items: [
    { to: "/ai-planner", label: "AI Planner", icon: Bot }, { to: "/settings", label: "Settings", icon: Settings },
    { to: "/help", label: "Help & Docs", icon: HelpCircle },
  ] },
];

function FlameMark() {
  return <svg className="brand-mark" viewBox="0 0 44 52" role="img" aria-label="BlueFire flame"><path d="M24 2c2 10-8 13-4 23 2 4 7 5 8 11 1 5-2 9-6 12 12-1 20-9 20-20 0-9-5-18-18-26Z"/><path className="brand-core" d="M18 21c0 8-10 10-10 20 0 5 4 9 10 9 7 0 12-5 12-12 0-6-4-11-7-14 0 6-4 9-7 8-4-2 1-7 2-11Z"/></svg>;
}

export function AppShell() {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const location = useLocation();
  const catalog = useQuery({ queryKey: ["catalog"], queryFn: api.catalog, retry: 1, staleTime: 60_000 });
  useEffect(() => {
    setMobileOpen(false);
    window.scrollTo({ top: 0, left: 0, behavior: "auto" });
    document.getElementById("main-content")?.scrollTo?.({ top: 0, left: 0, behavior: "auto" });
  }, [location.pathname]);
  const current = groups.flatMap((group) => group.items).find((item) => item.to === location.pathname)?.label ?? "BlueFire Nexus";

  return <Tooltip.Provider delayDuration={350}>
    <div className={`app-shell ${collapsed ? "nav-collapsed" : ""}`}>
      <header className="mobile-header">
        <button aria-label="Open navigation" onClick={() => setMobileOpen(true)}><Menu /></button>
        <a className="brand" href="#/"><FlameMark/><span><strong>BlueFire Nexus</strong><small>Adaptive research platform</small></span></a>
        <span role="img" className={`service-light ${catalog.isSuccess ? "ready" : catalog.isError ? "error" : "pending"}`} aria-label={catalog.isSuccess ? "Local service connected" : catalog.isError ? "Local service unavailable" : "Connecting"} />
      </header>
      <div className={`mobile-scrim ${mobileOpen ? "visible" : ""}`} onClick={() => setMobileOpen(false)} aria-hidden="true" />
      <aside className={`sidebar ${mobileOpen ? "mobile-open" : ""}`}>
        <div className="sidebar-brand-row"><a className="brand" href="#/"><FlameMark/><span><strong>BlueFire Nexus</strong><small>Adaptive research platform</small></span></a><button className="mobile-close" aria-label="Close navigation" onClick={() => setMobileOpen(false)}><X /></button></div>
        <nav aria-label="Primary navigation">
          {groups.map((group) => <div className="nav-group" key={group.label}><p>{group.label}</p>{group.items.map((item) => {
            const Icon = item.icon;
            const link = <NavLink to={item.to} end={item.to === "/"} className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}><Icon aria-hidden="true"/><span>{item.label}</span></NavLink>;
            return collapsed ? <Tooltip.Root key={item.to}><Tooltip.Trigger asChild>{link}</Tooltip.Trigger><Tooltip.Portal><Tooltip.Content className="tooltip" side="right" sideOffset={10}>{item.label}</Tooltip.Content></Tooltip.Portal></Tooltip.Root> : <span key={item.to}>{link}</span>;
          })}</div>)}
        </nav>
        <div className="sidebar-status">
          <div><span className={`service-light ${catalog.isSuccess ? "ready" : catalog.isError ? "error" : "pending"}`} aria-hidden="true"/><span><strong>{catalog.isSuccess ? "Local service ready" : catalog.isError ? "Service unavailable" : "Connecting locally"}</strong><small>{DEMO_MODE ? "Sanitized demo data" : "Loopback trust boundary"}</small></span></div>
          {DEMO_MODE ? <Badge tone="violet">Demo</Badge> : <ShieldCheck aria-label="Loopback protected" />}
        </div>
        <IconButton label={collapsed ? "Expand navigation" : "Collapse navigation"} className="sidebar-collapse" onClick={() => setCollapsed((value) => !value)}><ChevronLeft /></IconButton>
      </aside>
      <div className="workspace-shell">
        <header className="workspace-topbar"><div><span>Workspace</span><strong>{current}</strong></div><div className="topbar-actions"><Badge tone={catalog.isSuccess ? "success" : catalog.isError ? "danger" : "warning"} dot>{catalog.isSuccess ? "Connected" : catalog.isError ? "Offline" : "Connecting"}</Badge><span className="trust-label"><Boxes aria-hidden="true"/>Local control plane</span></div></header>
        <main id="main-content" tabIndex={-1}><Outlet /></main>
      </div>
    </div>
  </Tooltip.Provider>;
}
