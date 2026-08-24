import { Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "./components/AppShell";
import { AIPlannerPage } from "./pages/AIPlanner";
import { BuilderPage } from "./pages/Builder";
import {
  ActionsPage,
  BehaviorsPage,
  ResearchSourcesPage,
  RunnerProfilesPage,
  RunnersPage,
} from "./pages/CatalogPages";
import { ComparePage } from "./pages/Compare";
import { DetectionLabPage } from "./pages/DetectionLab";
import { OverviewPage } from "./pages/Overview";
import { RunsPage } from "./pages/Runs";
import { ScenariosPage } from "./pages/Scenarios";
import { HelpPage, SettingsPage } from "./pages/SettingsHelp";

export default function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<OverviewPage />} />
        <Route path="scenarios" element={<ScenariosPage />} />
        <Route path="builder" element={<BuilderPage />} />
        <Route path="runs" element={<RunsPage />} />
        <Route path="compare" element={<ComparePage />} />
        <Route path="behaviors" element={<BehaviorsPage />} />
        <Route path="runner-profiles" element={<RunnerProfilesPage />} />
        <Route path="runners" element={<RunnersPage />} />
        <Route path="actions" element={<ActionsPage />} />
        <Route path="detection-lab" element={<DetectionLabPage />} />
        <Route path="research-sources" element={<ResearchSourcesPage />} />
        <Route path="ai-planner" element={<AIPlannerPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="help" element={<HelpPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
