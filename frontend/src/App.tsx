import { Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "./components/AppShell";
import { AIPlannerPage } from "./pages/AIPlanner";
import { ActionPackagesPage } from "./pages/ActionPackages";
import { BuilderPage } from "./pages/Builder";
import {
  ActionsPage,
  BehaviorsPage,
  ResearchSourcesPage,
  RunnerProfilesPage,
  RunnersPage,
} from "./pages/CatalogPages";
import { ComparePage } from "./pages/Compare";
import { CompositionPage } from "./pages/Composition";
import { DetectionLabPage } from "./pages/DetectionLab";
import { GettingStartedPage } from "./pages/GettingStarted";
import { OverviewPage } from "./pages/Overview";
import { RunsPage } from "./pages/Runs";
import { ScenariosPage } from "./pages/Scenarios";
import { S3AccessPage } from "./pages/S3Access";
import { HelpPage, SettingsPage } from "./pages/SettingsHelp";

export default function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<OverviewPage />} />
        <Route path="getting-started" element={<GettingStartedPage />} />
        <Route path="scenarios" element={<ScenariosPage />} />
        <Route path="builder" element={<BuilderPage />} />
        <Route path="runs" element={<RunsPage />} />
        <Route path="runs/:runId" element={<RunsPage />} />
        <Route path="compare" element={<ComparePage />} />
        <Route path="composition" element={<CompositionPage />} />
        <Route path="s3-access" element={<S3AccessPage />} />
        <Route path="behaviors" element={<BehaviorsPage />} />
        <Route path="runner-profiles" element={<RunnerProfilesPage />} />
        <Route path="runners" element={<RunnersPage />} />
        <Route path="actions" element={<ActionsPage />} />
        <Route path="action-packages" element={<ActionPackagesPage />} />
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
