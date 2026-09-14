import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  ArrowLeft,
  ShieldCheck,
  CheckCircle,
  Clock,
  User,
  CheckCircle2,
} from 'lucide-react';
import { api } from '../api/client';
import {
  ANALYST_ROSTER,
  type AlertResult,
  type AlertStatus,
  type AnalystNote,
  type ResolutionOutcome,
  type TimelineItem,
} from '../types';
import { SeverityBadge, StatusBadge } from '../components/common/Badges';
import { EvidenceCards } from '../components/dashboard/EvidenceCards';
import { InvestigationChecklist } from '../components/investigation/InvestigationChecklist';
import { AnalystNotesSection } from '../components/investigation/AnalystNotesSection';
import { ResolutionModal } from '../components/investigation/ResolutionModal';
import { CaseContextSidebar } from '../components/investigation/CaseContextSidebar';
import { AttackIntelligencePanel } from '../components/investigation/AttackIntelligencePanel';

export const AlertInvestigationPage: React.FC = () => {
  const { alertId } = useParams<{ alertId: string }>();
  const [alert, setAlert] = useState<AlertResult | null>(null);
  const [timeline, setTimeline] = useState<TimelineItem[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isUpdatingStatus, setIsUpdatingStatus] = useState<boolean>(false);
  const [isAssigning, setIsAssigning] = useState<boolean>(false);
  const [isResolutionModalOpen, setIsResolutionModalOpen] = useState<boolean>(false);
  const [isIntelligencePanelOpen, setIsIntelligencePanelOpen] = useState<boolean>(false);

  const fetchDetails = async () => {
    if (!alertId) return;
    try {
      setIsLoading(true);
      const data = await api.getAlertById(alertId);
      setAlert(data);

      if (data.case_id) {
        const tl = await api.getCaseTimeline(data.case_id);
        setTimeline(tl);
      }
    } catch (err) {
      console.error('Failed to fetch alert details:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchDetails();
  }, [alertId]);

  const handleStatusTransition = async (newStatus: AlertStatus) => {
    if (!alert) return;

    if (newStatus === 'CLOSED') {
      setIsResolutionModalOpen(true);
      return;
    }

    try {
      setIsUpdatingStatus(true);
      const updated = await api.updateAlertStatus(alert.alert_id, newStatus);
      setAlert(updated);
      if (updated.case_id) {
        const tl = await api.getCaseTimeline(updated.case_id);
        setTimeline(tl);
      }
    } catch (err: any) {
      console.error(err.message || 'Status transition failed');
    } finally {
      setIsUpdatingStatus(false);
    }
  };

  const handleAssignAnalyst = async (analyst: string) => {
    if (!alert) return;
    try {
      setIsAssigning(true);
      const updated = await api.assignAlert(alert.alert_id, analyst);
      setAlert(updated);
    } catch (err) {
      console.error('Failed to assign analyst:', err);
    } finally {
      setIsAssigning(false);
    }
  };

  const handleSaveNote = async (analyst: string, text: string) => {
    if (!alert) return;
    const updated = await api.addAlertNote(alert.alert_id, analyst, text);
    setAlert(updated);
  };

  const handleResolveAlert = async (
    resolution: ResolutionOutcome,
    analyst: string,
    notes: string
  ) => {
    if (!alert) return;
    const updated = await api.resolveAlert(alert.alert_id, resolution, analyst, notes);
    setAlert(updated);
    if (updated.case_id) {
      const tl = await api.getCaseTimeline(updated.case_id);
      setTimeline(tl);
    }
  };

  if (isLoading) {
    return (
      <div className="p-8 text-center font-mono text-sm text-slate-500 animate-pulse">
        Loading forensic alert evidence...
      </div>
    );
  }

  if (!alert) {
    return (
      <div className="p-8 text-center">
        <p className="text-rose-400 font-mono">Alert not found.</p>
        <Link to="/alerts" className="text-xs text-cyan-400 underline mt-2 inline-block">
          Return to alerts list
        </Link>
      </div>
    );
  }

  const validTransitions: Record<string, AlertStatus[]> = {
    NEW: ['ACKNOWLEDGED', 'ESCALATED', 'CLOSED'],
    ACKNOWLEDGED: ['ESCALATED', 'CLOSED'],
    ESCALATED: ['CLOSED'],
    CLOSED: [],
  };

  const allowedNext = validTransitions[alert.status] || [];

  // Extract analyst notes
  const notesList: AnalystNote[] =
    alert.details?.analyst_notes ||
    (alert.resolution_notes
      ? [
          {
            analyst: alert.assigned_analyst || 'SOC Analyst',
            timestamp: alert.updated_at,
            text: alert.resolution_notes,
          },
        ]
      : []);

  return (
    <div className="space-y-6 max-w-[1500px] mx-auto">
      {/* Header with Back button & Action controls */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-[#1c2638] pb-4">
        <div className="flex items-center space-x-3">
          <Link
            to="/alerts"
            className="p-2 rounded-lg bg-[#0d131d] border border-[#1c2638] text-slate-400 hover:text-white"
          >
            <ArrowLeft className="w-4 h-4" />
          </Link>
          <div>
            <div className="flex items-center space-x-2">
              <SeverityBadge severity={alert.severity} size="md" />
              <StatusBadge status={alert.status} />
              <span className="font-mono text-xs text-slate-500">ID: {alert.alert_id}</span>
            </div>
            <h1 className="text-xl font-bold text-white tracking-tight mt-1">{alert.title}</h1>
          </div>
        </div>

        {/* Top Controls: Analyst Assignment & Lifecycle Action Buttons */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Analyst Assignment Dropdown */}
          <div className="flex items-center space-x-2 bg-[#0d131d] border border-[#1c2638] rounded-lg px-2.5 py-1 text-xs font-mono">
            <User className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-400">ASSIGNED:</span>
            <select
              value={alert.assigned_analyst || ''}
              disabled={isAssigning || alert.status === 'CLOSED'}
              onChange={(e) => handleAssignAnalyst(e.target.value)}
              className="bg-transparent text-cyan-300 font-semibold focus:outline-none cursor-pointer"
            >
              <option value="" disabled className="bg-[#0b121e] text-slate-500">
                Unassigned
              </option>
              {ANALYST_ROSTER.map((name) => (
                <option key={name} value={name} className="bg-[#0b121e] text-slate-200">
                  {name}
                </option>
              ))}
            </select>
          </div>

          {/* Lifecycle State Controls */}
          {allowedNext.length > 0 ? (
            <div className="flex items-center space-x-1.5">
              {allowedNext.includes('ACKNOWLEDGED') && (
                <button
                  type="button"
                  onClick={() => handleStatusTransition('ACKNOWLEDGED')}
                  disabled={isUpdatingStatus}
                  className="px-3 py-1.5 rounded-lg bg-[#121a28] hover:bg-cyan-950/80 hover:text-cyan-300 border border-cyan-800/60 text-xs font-mono font-semibold transition-all cursor-pointer text-slate-200"
                >
                  Acknowledge
                </button>
              )}
              {allowedNext.includes('ESCALATED') && (
                <button
                  type="button"
                  onClick={() => handleStatusTransition('ESCALATED')}
                  disabled={isUpdatingStatus}
                  className="px-3 py-1.5 rounded-lg bg-[#121a28] hover:bg-amber-950/80 hover:text-amber-300 border border-amber-800/60 text-xs font-mono font-semibold transition-all cursor-pointer text-slate-200"
                >
                  Escalate
                </button>
              )}
              {allowedNext.includes('CLOSED') && (
                <button
                  type="button"
                  onClick={() => handleStatusTransition('CLOSED')}
                  disabled={isUpdatingStatus}
                  className="px-3 py-1.5 rounded-lg bg-rose-950/60 hover:bg-rose-900/60 hover:text-white border border-rose-800/80 text-xs font-mono font-semibold transition-all cursor-pointer text-rose-300 shadow-[0_0_10px_rgba(244,63,94,0.15)]"
                >
                  Close Alert
                </button>
              )}
            </div>
          ) : (
            <span className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-[11px] font-mono text-slate-400">
              TERMINAL (CLOSED)
            </span>
          )}

          <button
            type="button"
            onClick={() => setIsIntelligencePanelOpen(true)}
            className="px-3 py-1.5 rounded-lg bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-700/60 text-cyan-300 text-xs font-mono font-bold transition-all cursor-pointer flex items-center space-x-1.5 shadow-[0_0_10px_rgba(0,210,255,0.15)]"
          >
            <ShieldCheck className="w-4 h-4 text-cyan-400" />
            <span>Attack Intelligence</span>
          </button>
        </div>
      </div>

      {/* Resolution summary banner if closed */}
      {alert.status === 'CLOSED' && (
        <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-800/40 text-xs font-mono flex items-start space-x-3">
          <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <span className="font-bold text-emerald-300 uppercase">
                Resolution: {alert.resolution || 'Resolved'}
              </span>
              <span className="text-slate-500">•</span>
              <span className="text-slate-400">
                Closed by {alert.assigned_analyst || 'SOC Analyst'}
              </span>
            </div>
            {alert.resolution_notes && (
              <p className="text-slate-300 font-sans text-xs pt-1">{alert.resolution_notes}</p>
            )}
          </div>
        </div>
      )}

      {/* WHY DETECTED - Centerpiece Forensic Section */}
      <div className="bg-[#0f1726] border border-cyan-800/80 rounded-xl p-5 shadow-[0_0_20px_rgba(0,210,255,0.08)]">
        <div className="flex items-center space-x-2 text-cyan-400 mb-2 font-mono text-xs font-bold uppercase tracking-wider">
          <ShieldCheck className="w-4 h-4" />
          <span>Why was this detected? (Forensic Evidence Rationale)</span>
        </div>
        <p className="text-sm text-slate-200 font-sans leading-relaxed">
          {alert.explanation}
        </p>

        {/* Verified Detection Checkmarks */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 mt-4 pt-4 border-t border-cyan-950/80">
          <div className="flex items-center space-x-2 text-xs font-mono">
            <CheckCircle
              className={`w-4 h-4 ${
                alert.contributor_breakdown.statistical?.score > 0 ? 'text-cyan-400' : 'text-slate-600'
              }`}
            />
            <span
              className={
                alert.contributor_breakdown.statistical?.score > 0 ? 'text-slate-200 font-semibold' : 'text-slate-500'
              }
            >
              Statistical Baseline Anomaly
            </span>
          </div>

          <div className="flex items-center space-x-2 text-xs font-mono">
            <CheckCircle
              className={`w-4 h-4 ${
                alert.contributor_breakdown.isolation_forest?.score > 0 ? 'text-cyan-400' : 'text-slate-600'
              }`}
            />
            <span
              className={
                alert.contributor_breakdown.isolation_forest?.score > 0 ? 'text-slate-200 font-semibold' : 'text-slate-500'
              }
            >
              Isolation Forest Outlier
            </span>
          </div>

          <div className="flex items-center space-x-2 text-xs font-mono">
            <CheckCircle
              className={`w-4 h-4 ${
                alert.contributor_breakdown.behavioral_clustering?.score > 0 ? 'text-cyan-400' : 'text-slate-600'
              }`}
            />
            <span
              className={
                alert.contributor_breakdown.behavioral_clustering?.score > 0 ? 'text-slate-200 font-semibold' : 'text-slate-500'
              }
            >
              Behavioral Cluster Deviation
            </span>
          </div>

          <div className="flex items-center space-x-2 text-xs font-mono">
            <CheckCircle
              className={`w-4 h-4 ${
                alert.contributor_breakdown.cross_entity_correlation?.score > 0 ? 'text-cyan-400' : 'text-slate-600'
              }`}
            />
            <span
              className={
                alert.contributor_breakdown.cross_entity_correlation?.score > 0 ? 'text-slate-200 font-semibold' : 'text-slate-500'
              }
            >
              Multi-Detector Correlation
            </span>
          </div>
        </div>
      </div>

      {/* Attack-Specific Recommended Response & Interactive Checklist */}
      <InvestigationChecklist
        id={alert.alert_id}
        scenarioOrTitle={alert.title}
        details={alert.details}
      />

      {/* 2-Column Layout: Forensic Metadata & Notes / Timeline */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Left: CASE CONTEXT Sidebar */}
        <div className="space-y-5">
          <CaseContextSidebar alert={alert} />

          <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-5 space-y-4">
            <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300 border-b border-[#1c2638] pb-2">
              Investigation Summary
            </h3>

            <div className="space-y-2 text-xs font-mono">
              <div className="flex justify-between py-1 border-b border-[#162030]">
                <span className="text-slate-500">Risk Score:</span>
                <span className="text-cyan-400 font-bold">{alert.risk_score.toFixed(1)} / 100</span>
              </div>
              <div className="flex justify-between py-1 border-b border-[#162030]">
                <span className="text-slate-500">Evidence Strength:</span>
                <span className="text-slate-200">{alert.evidence_strength}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-[#162030]">
                <span className="text-slate-500">Assigned Analyst:</span>
                <span className="text-cyan-300 font-semibold">{alert.assigned_analyst || 'Unassigned'}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-[#162030]">
                <span className="text-slate-500">Target Entity:</span>
                <span className="text-slate-200 font-semibold">{alert.entity_id} ({alert.entity_type})</span>
              </div>
              <div className="flex justify-between py-1 border-b border-[#162030]">
                <span className="text-slate-500">Occurrence Count:</span>
                <span className="text-slate-200">x{alert.occurrence_count} (Deduplicated)</span>
              </div>
              <div className="flex justify-between py-1 border-b border-[#162030]">
                <span className="text-slate-500">Deduplication Key:</span>
                <span className="text-slate-300 text-[11px] truncate max-w-[160px]">{alert.dedup_key}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-[#162030]">
                <span className="text-slate-500">Linked Incident Case:</span>
                {alert.case_id ? (
                  <Link to={`/cases/${alert.case_id}`} className="text-cyan-400 hover:underline">
                    {alert.case_id.slice(0, 12)}...
                  </Link>
                ) : (
                  <span className="text-slate-600">None</span>
                )}
              </div>
              <div className="flex justify-between py-1">
                <span className="text-slate-500">Created:</span>
                <span className="text-slate-400">{new Date(alert.created_at).toLocaleString()}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Right: Notes & Evidence Cards */}
        <div className="lg:col-span-2 space-y-4">
          {/* Analyst Notes Section */}
          <AnalystNotesSection
            notes={notesList}
            currentAnalyst={alert.assigned_analyst}
            onSaveNote={handleSaveNote}
          />

          {/* Evidence Breakdown */}
          <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-5">
            <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300 mb-3">
              Independent Detection Breakdown
            </h3>
            <EvidenceCards breakdown={alert.contributor_breakdown} />
          </div>

          {/* Chronological Investigation Timeline */}
          {timeline.length > 0 && (
            <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-5">
              <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300 mb-4 flex items-center space-x-2">
                <Clock className="w-4 h-4 text-cyan-400" />
                <span>Forensic Investigation Timeline</span>
              </h3>

              <div className="relative pl-6 space-y-4 border-l border-[#1c2638]">
                {timeline.map((item) => (
                  <div key={item.item_id} className="relative">
                    <span className="absolute -left-[31px] top-1 w-3 h-3 rounded-full bg-cyan-500 ring-4 ring-[#0d131d]" />
                    <div className="flex items-center space-x-2 text-xs font-mono text-slate-400">
                      <span className="text-cyan-400 font-bold">{item.evidence_type}</span>
                      <span>•</span>
                      <span>{new Date(item.timestamp).toLocaleTimeString()}</span>
                      {item.severity && <SeverityBadge severity={item.severity} size="sm" />}
                    </div>
                    <p className="text-xs text-slate-200 font-sans mt-1">{item.explanation}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Resolution Modal */}
      <ResolutionModal
        isOpen={isResolutionModalOpen}
        onClose={() => setIsResolutionModalOpen(false)}
        onConfirm={handleResolveAlert}
        title={alert.title}
        itemType="Alert"
        currentAnalyst={alert.assigned_analyst}
      />

      {/* Attack Intelligence Drawer */}
      <AttackIntelligencePanel
        alert={alert}
        isOpen={isIntelligencePanelOpen}
        onClose={() => setIsIntelligencePanelOpen(false)}
        onUpdate={fetchDetails}
      />
    </div>
  );
};
