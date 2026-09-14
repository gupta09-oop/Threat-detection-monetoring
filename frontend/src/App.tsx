import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AppShell } from './components/layout/AppShell';
import { CommandCenterPage } from './pages/CommandCenter';
import { AlertsPage } from './pages/Alerts';
import { AlertInvestigationPage } from './pages/AlertInvestigation';
import { CasesPage } from './pages/Cases';
import { CaseDetailsPage } from './pages/CaseDetails';
import { AttackTopologyPage } from './pages/AttackTopology';
import { DetectionAnalyticsPage } from './pages/DetectionAnalytics';
import { ReportsPage } from './pages/Reports';

export default function App() {
  return (
    <BrowserRouter>
      <AppShell>
        <Routes>
          <Route path="/" element={<CommandCenterPage />} />
          <Route path="/alerts" element={<AlertsPage />} />
          <Route path="/alerts/:alertId" element={<AlertInvestigationPage />} />
          <Route path="/cases" element={<CasesPage />} />
          <Route path="/cases/:caseId" element={<CaseDetailsPage />} />
          <Route path="/topology" element={<AttackTopologyPage />} />
          <Route path="/analytics" element={<DetectionAnalyticsPage />} />
          <Route path="/reports" element={<ReportsPage />} />
        </Routes>
      </AppShell>
    </BrowserRouter>
  );
}
