import { useEffect, useState } from 'react';
import { ShieldAlert, Briefcase, Cpu, RotateCcw } from 'lucide-react';
import { api } from '../api/client';
import { wsManager } from '../api/ws';
import type { AlertResult, CanonicalEvent, CaseResult, RiskScoreResult } from '../types';
import { RiskGauge } from '../components/dashboard/RiskGauge';
import { EvidenceCards } from '../components/dashboard/EvidenceCards';
import { KillChainTracker } from '../components/dashboard/KillChainTracker';
import { AlertTable } from '../components/alerts/AlertTable';
import { LiveTelemetryFeed } from '../components/dashboard/LiveTelemetryFeed';
import { AttackTopologyGraph } from '../components/topology/AttackTopologyGraph';
import { LiveSimulationPanel } from '../components/dashboard/LiveSimulationPanel';
import { AttackIntelligencePanel } from '../components/investigation/AttackIntelligencePanel';

export const CommandCenterPage: React.FC = () => {
  const [alerts, setAlerts] = useState<AlertResult[]>([]);
  const [cases, setCases] = useState<CaseResult[]>([]);
  const [events, setEvents] = useState<CanonicalEvent[]>([]);
  const [latestRisk, setLatestRisk] = useState<RiskScoreResult | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isResetting, setIsResetting] = useState<boolean>(false);
  const [selectedAlertForIntel, setSelectedAlertForIntel] = useState<AlertResult | null>(null);

  const loadDashboardData = async () => {
    try {
      const [alertsRes, casesRes, eventsRes, riskRes] = await Promise.all([
        api.getAlerts({ limit: 10 }),
        api.getCases({ limit: 10 }),
        api.getEvents({ limit: 50 }),
        api.getRiskResults({ limit: 1 }),
      ]);

      setAlerts(alertsRes);
      setCases(casesRes);
      setEvents(eventsRes);
      if (riskRes.length > 0) {
        setLatestRisk(riskRes[0]);
      } else {
        setLatestRisk(null);
      }
    } catch (err) {
      console.error('Failed to load dashboard data:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleResetDemoState = async () => {
    try {
      setIsResetting(true);
      await api.resetDemoState();
      setAlerts([]);
      setCases([]);
      setEvents([]);
      setLatestRisk(null);
      await loadDashboardData();
    } catch (err) {
      console.error('Failed to reset demo state:', err);
    } finally {
      setIsResetting(false);
    }
  };

  useEffect(() => {
    loadDashboardData();

    // Subscribe to real-time WebSocket events
    const unsub = wsManager.subscribeMessages((msg) => {
      if (msg.type === 'simulation.reset') {
        setAlerts([]);
        setCases([]);
        setEvents([]);
        setLatestRisk(null);
        return;
      }

      if (msg.type.startsWith('alert.')) {
        api.getAlerts({ limit: 10 }).then(setAlerts).catch(() => {});
        api.getRiskResults({ limit: 1 }).then((r) => setLatestRisk(r.length > 0 ? r[0] : null)).catch(() => {});
      }
      if (msg.type.startsWith('case.')) {
        api.getCases({ limit: 10 }).then(setCases).catch(() => {});
      }
    });

    // Fallback polling interval (10s)
    const interval = setInterval(() => {
      loadDashboardData();
    }, 10000);

    return () => {
      unsub();
      clearInterval(interval);
    };
  }, []);

  // Compute metrics with strict active-incident consistency
  const activeAlerts = alerts.filter((a: AlertResult) => a.status !== 'CLOSED');
  const activeCases = cases.filter((c: CaseResult) => c.status === 'OPEN' || c.status === 'INVESTIGATING');

  const activeAlertsCount = activeAlerts.length;
  const criticalAlertsCount = activeAlerts.filter((a: AlertResult) => a.severity === 'CRITICAL').length;
  const openCasesCount = activeCases.length;

  // Single consistent source of truth for current threat/risk
  const topActiveAlert = activeAlerts.slice().sort((a, b) => b.risk_score - a.risk_score)[0];
  const topActiveCase = activeCases.slice().sort((a, b) => b.total_risk_score - a.total_risk_score)[0];

  const hasActiveIncident = Boolean(topActiveAlert || topActiveCase);

  const currentRiskScore = hasActiveIncident
    ? (topActiveAlert ? topActiveAlert.risk_score : (topActiveCase ? topActiveCase.total_risk_score : 0.0))
    : 0.0;

  const currentSeverity = hasActiveIncident
    ? (topActiveAlert ? topActiveAlert.severity : (topActiveCase ? topActiveCase.severity : 'LOW'))
    : 'LOW';

  const detectorAgreement = hasActiveIncident
    ? (topActiveAlert ? topActiveAlert.evidence_strength : 'NORMAL')
    : 'NONE';

  const explanation = hasActiveIncident
    ? (topActiveAlert?.explanation || topActiveCase?.summary || 'Active anomalous behavior detected across evaluated platform models.')
    : 'All evaluated detection methods report normal behavior with no anomalous evidence.';

  const contributorBreakdown = hasActiveIncident
    ? topActiveAlert?.contributor_breakdown || latestRisk?.contributor_breakdown
    : undefined;

  const killChainStages: string[] = hasActiveIncident
    ? Array.from(new Set(activeCases.flatMap((c: CaseResult) => c.kill_chain_stages || [])))
    : [];

  return (
    <div className="space-y-6 max-w-[1600px] mx-auto">
      {/* Top Controls */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight">Command Center</h2>
          <p className="text-xs text-slate-400">
            Real-time behavioral threat monitoring & collective anomaly intelligence
          </p>
        </div>

        <button
          onClick={handleResetDemoState}
          disabled={isResetting}
          title="Completely reset demo state back to clean baseline"
          className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-rose-950/40 border border-rose-800/60 text-xs font-mono text-rose-300 hover:bg-rose-900/50 hover:text-white hover:border-rose-500 transition-all cursor-pointer shadow-[0_0_12px_rgba(244,63,94,0.15)]"
        >
          <RotateCcw className={`w-3.5 h-3.5 ${isResetting ? 'animate-spin' : ''}`} />
          <span>{isResetting ? 'Resetting Demo...' : 'Reset Demo State'}</span>
        </button>
      </div>

      {/* Live Synthetic Attack Simulation Console */}
      <LiveSimulationPanel onSimulationUpdate={loadDashboardData} />

      {/* Top Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-4 flex flex-col justify-between">
          <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
            Current Threat Level
          </span>
          <div className={`text-2xl font-mono font-bold mt-2 ${currentSeverity === 'CRITICAL' ? 'text-rose-400' : currentSeverity === 'HIGH' ? 'text-amber-400' : currentSeverity === 'MEDIUM' ? 'text-yellow-400' : 'text-emerald-400'}`}>
            {currentSeverity}
          </div>
          <span className="text-[10px] text-slate-500 font-mono mt-1">
            {hasActiveIncident ? `Active threat score ${currentRiskScore.toFixed(1)} / 100` : 'Normal baseline condition'}
          </span>
        </div>

        <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-[11px] font-mono uppercase tracking-wider">
            <span>Active Alerts</span>
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-mono font-bold text-cyan-400 mt-2">
            {activeAlertsCount}
          </div>
          <span className="text-[10px] text-slate-500 font-mono mt-1">
            Excludes closed incidents
          </span>
        </div>

        <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-[11px] font-mono uppercase tracking-wider">
            <span>Critical Threats</span>
            {criticalAlertsCount > 0 && <span className="w-2 h-2 rounded-full bg-rose-500 animate-ping" />}
          </div>
          <div className="text-2xl font-mono font-bold text-rose-400 mt-2">
            {criticalAlertsCount}
          </div>
          <span className="text-[10px] text-slate-500 font-mono mt-1">
            Score 85.0 - 100.0
          </span>
        </div>

        <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-[11px] font-mono uppercase tracking-wider">
            <span>Open Cases</span>
            <Briefcase className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-mono font-bold text-amber-400 mt-2">
            {openCasesCount}
          </div>
          <span className="text-[10px] text-slate-500 font-mono mt-1">
            Correlated incidents
          </span>
        </div>

        <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-[11px] font-mono uppercase tracking-wider">
            <span>Evidence Strength</span>
            <Cpu className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-mono font-bold text-purple-400 mt-2 truncate">
            {detectorAgreement}
          </div>
          <span className="text-[10px] text-slate-500 font-mono mt-1">
            Multi-detector agreement
          </span>
        </div>
      </div>

      {/* Main Center Area: Radial Risk Score & Kill Chain */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Left: Central Risk Score Card */}
        <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-5 flex flex-col items-center justify-center text-center shadow-lg">
          <RiskGauge
            score={currentRiskScore}
            severity={currentSeverity}
            evidenceStrength={String(detectorAgreement)}
            size={220}
          />
          <p className="text-xs text-slate-400 mt-3 max-w-xs font-sans leading-relaxed">
            {explanation}
          </p>
        </div>

        {/* Right: Kill-Chain Tracker and Quick Incident Highlights */}
        <div className="lg:col-span-2 flex flex-col justify-between space-y-4">
          <KillChainTracker stages={killChainStages} />

          <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-4 flex-1 flex flex-col justify-between">
            <div className="flex items-center justify-between border-b border-[#1c2638] pb-2">
              <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider font-mono">
                Active Incident Context
              </h3>
              <span className="text-[11px] font-mono text-cyan-400">
                {hasActiveIncident
                  ? (topActiveCase ? topActiveCase.title : (topActiveAlert ? topActiveAlert.title : 'Active Incident'))
                  : 'NONE'}
              </span>
            </div>

            <p className="text-xs text-slate-300 font-sans leading-relaxed my-2">
              {hasActiveIncident
                ? (topActiveCase?.summary || topActiveAlert?.summary || topActiveAlert?.explanation || 'Active security incident under evaluation.')
                : 'The platform baseline detector is continuously monitoring canonical authentication, network, and system event streams.'}
            </p>

            <div className="grid grid-cols-3 gap-2 pt-2 border-t border-[#182233] text-[11px] font-mono text-slate-400">
              <div>Target Entity: <span className="text-white">{hasActiveIncident ? (topActiveAlert?.entity_id || topActiveCase?.entity_id || 'N/A') : 'NONE'}</span></div>
              <div>Source Type: <span className="text-white">{hasActiveIncident ? (topActiveAlert?.entity_type || topActiveCase?.entity_type || 'GLOBAL') : 'GLOBAL'}</span></div>
              <div>Timestamp: <span className="text-white">{hasActiveIncident && topActiveAlert ? new Date(topActiveAlert.timestamp).toLocaleTimeString() : 'Current'}</span></div>
            </div>
          </div>
        </div>
      </div>

      {/* Centerpiece: Attack Topology */}
      <AttackTopologyGraph events={events} height={460} />

      {/* Multi-Detector Evidence Breakdown */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300">
            Evidence Breakdown (Independent Detection Families)
          </h3>
          <span className="text-[10px] font-mono text-slate-500">
            Bounded Transparent Scoring (0-100 pts)
          </span>
        </div>
        <EvidenceCards breakdown={contributorBreakdown} />
      </div>

      {/* Bottom Grid: Live Alerts & Live Telemetry Feed */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <div>
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300">
              Live Threat Alerts
            </h3>
            <span className="text-[10px] font-mono text-cyan-400">
              {alerts.length} alerts in buffer
            </span>
          </div>
          <AlertTable
            alerts={alerts.slice(0, 5)}
            isLoading={isLoading}
            onSelectAlert={(a) => setSelectedAlertForIntel(a)}
          />
        </div>

        <div>
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300">
              Live Ingested Telemetry
            </h3>
            <span className="text-[10px] font-mono text-slate-500">
              Bounded Ingest Stream
            </span>
          </div>
          <LiveTelemetryFeed events={events.slice(0, 8)} isLoading={isLoading} />
        </div>
      </div>

      {/* Attack Intelligence Drawer */}
      <AttackIntelligencePanel
        alert={selectedAlertForIntel}
        isOpen={!!selectedAlertForIntel}
        onClose={() => setSelectedAlertForIntel(null)}
        onUpdate={loadDashboardData}
      />
    </div>
  );
};
