import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  ArrowLeft,
  Clock,
  User,
  CheckCircle2,
} from 'lucide-react';
import { api } from '../api/client';
import {
  ANALYST_ROSTER,
  type AlertResult,
  type AnalystNote,
  type CaseResult,
  type CaseStatus,
  type ResolutionOutcome,
  type TimelineItem,
} from '../types';
import { SeverityBadge, StatusBadge } from '../components/common/Badges';
import { AlertTable } from '../components/alerts/AlertTable';
import { InvestigationChecklist } from '../components/investigation/InvestigationChecklist';
import { AnalystNotesSection } from '../components/investigation/AnalystNotesSection';
import { ResolutionModal } from '../components/investigation/ResolutionModal';
import { CaseContextSidebar } from '../components/investigation/CaseContextSidebar';
import { AttackIntelligencePanel } from '../components/investigation/AttackIntelligencePanel';
import { ShieldCheck } from 'lucide-react';

export const CaseDetailsPage: React.FC = () => {
  const { caseId } = useParams<{ caseId: string }>();
  const [incidentCase, setIncidentCase] = useState<CaseResult | null>(null);
  const [alerts, setAlerts] = useState<AlertResult[]>([]);
  const [timeline, setTimeline] = useState<TimelineItem[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isUpdating, setIsUpdating] = useState<boolean>(false);
  const [isAssigning, setIsAssigning] = useState<boolean>(false);
  const [isResolutionModalOpen, setIsResolutionModalOpen] = useState<boolean>(false);
  const [isIntelligenceOpen, setIsIntelligenceOpen] = useState<boolean>(false);

  const fetchCase = async () => {
    if (!caseId) return;
    try {
      setIsLoading(true);
      const [caseData, alertsData, timelineData] = await Promise.all([
        api.getCaseById(caseId),
        api.getCaseAlerts(caseId),
        api.getCaseTimeline(caseId),
      ]);
      setIncidentCase(caseData);
      setAlerts(alertsData);
      setTimeline(timelineData);
    } catch (err) {
      console.error('Failed to load case details:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchCase();
  }, [caseId]);

  const handleStatusChange = async (newStatus: CaseStatus) => {
    if (!incidentCase) return;

    if (newStatus === 'RESOLVED' || newStatus === 'DISMISSED') {
      setIsResolutionModalOpen(true);
      return;
    }

    try {
      setIsUpdating(true);
      const updated = await api.updateCaseStatus(
        incidentCase.case_id,
        newStatus,
        incidentCase.resolution_notes || undefined,
        incidentCase.assigned_to || incidentCase.assigned_analyst || undefined
      );
      setIncidentCase(updated);
      const tl = await api.getCaseTimeline(incidentCase.case_id);
      setTimeline(tl);
    } catch (err: any) {
      console.error(err.message || 'Failed to update case status');
    } finally {
      setIsUpdating(false);
    }
  };

  const handleAssignAnalyst = async (analyst: string) => {
    if (!incidentCase) return;
    try {
      setIsAssigning(true);
      const updated = await api.assignCase(incidentCase.case_id, analyst);
      setIncidentCase(updated);
    } catch (err) {
      console.error('Failed to assign analyst to case:', err);
    } finally {
      setIsAssigning(false);
    }
  };

  const handleSaveNote = async (analyst: string, text: string) => {
    if (!incidentCase) return;
    const updated = await api.addCaseNote(incidentCase.case_id, analyst, text);
    setIncidentCase(updated);
  };

  const handleResolveCase = async (
    resolution: ResolutionOutcome,
    analyst: string,
    notes: string
  ) => {
    if (!incidentCase) return;
    const updated = await api.resolveCase(incidentCase.case_id, resolution, analyst, notes);
    setIncidentCase(updated);
    const tl = await api.getCaseTimeline(incidentCase.case_id);
    setTimeline(tl);
  };

  if (isLoading) {
    return (
      <div className="p-8 text-center font-mono text-sm text-slate-500 animate-pulse">
        Loading incident case details & forensic timeline...
      </div>
    );
  }

  if (!incidentCase) {
    return (
      <div className="p-8 text-center">
        <p className="text-rose-400 font-mono">Incident case not found.</p>
        <Link to="/cases" className="text-xs text-cyan-400 underline mt-2 inline-block">
          Return to cases
        </Link>
      </div>
    );
  }

  const validTransitions: Record<string, CaseStatus[]> = {
    OPEN: ['INVESTIGATING', 'RESOLVED', 'DISMISSED'],
    INVESTIGATING: ['RESOLVED', 'DISMISSED'],
    RESOLVED: [],
    DISMISSED: [],
  };

  const allowedNext = validTransitions[incidentCase.status] || [];

  const currentAnalyst = incidentCase.assigned_analyst || incidentCase.assigned_to;

  const notesList: AnalystNote[] =
    (incidentCase as any).details?.analyst_notes ||
    (incidentCase.resolution_notes
      ? [
          {
            analyst: currentAnalyst || 'SOC Analyst',
            timestamp: incidentCase.updated_at,
            text: incidentCase.resolution_notes,
          },
        ]
      : []);

  return (
    <div className="space-y-6 max-w-[1500px] mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-[#1c2638] pb-4">
        <div className="flex items-center space-x-3">
          <Link
            to="/cases"
            className="p-2 rounded-lg bg-[#0d131d] border border-[#1c2638] text-slate-400 hover:text-white"
          >
            <ArrowLeft className="w-4 h-4" />
          </Link>
          <div>
            <div className="flex items-center space-x-2">
              <SeverityBadge severity={incidentCase.severity} size="md" />
              <StatusBadge status={incidentCase.status} />
              <span className="font-mono text-xs text-slate-500">CASE ID: {incidentCase.case_id}</span>
            </div>
            <h1 className="text-xl font-bold text-white tracking-tight mt-1">{incidentCase.title}</h1>
          </div>
        </div>

        {/* Top Controls: Analyst Assignment & Lifecycle Action Buttons */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Analyst Assignment Dropdown */}
          <div className="flex items-center space-x-2 bg-[#0d131d] border border-[#1c2638] rounded-lg px-2.5 py-1 text-xs font-mono">
            <User className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-400">ASSIGNED:</span>
            <select
              value={currentAnalyst || ''}
              disabled={isAssigning || incidentCase.status === 'RESOLVED' || incidentCase.status === 'DISMISSED'}
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
              {allowedNext.includes('INVESTIGATING') && (
                <button
                  type="button"
                  onClick={() => handleStatusChange('INVESTIGATING')}
                  disabled={isUpdating}
                  className="px-3 py-1.5 rounded-lg bg-[#121a28] hover:bg-cyan-950/80 hover:text-cyan-300 border border-cyan-800/60 text-xs font-mono font-semibold transition-all cursor-pointer text-slate-200"
                >
                  Start Investigation
                </button>
              )}
              {allowedNext.includes('RESOLVED') && (
                <button
                  type="button"
                  onClick={() => handleStatusChange('RESOLVED')}
                  disabled={isUpdating}
                  className="px-3 py-1.5 rounded-lg bg-emerald-950/60 hover:bg-emerald-900/60 hover:text-white border border-emerald-800/80 text-xs font-mono font-semibold transition-all cursor-pointer text-emerald-300 shadow-[0_0_10px_rgba(16,185,129,0.15)]"
                >
                  Resolve Case
                </button>
              )}
              {allowedNext.includes('DISMISSED') && (
                <button
                  type="button"
                  onClick={() => handleStatusChange('DISMISSED')}
                  disabled={isUpdating}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-mono transition-all cursor-pointer"
                >
                  Dismiss
                </button>
              )}
            </div>
          ) : (
            <span className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-[11px] font-mono text-slate-400">
              TERMINAL ({incidentCase.status})
            </span>
          )}

          <button
            type="button"
            onClick={() => setIsIntelligenceOpen(true)}
            className="px-3 py-1.5 rounded-lg bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-700/60 text-cyan-300 text-xs font-mono font-bold transition-all cursor-pointer flex items-center space-x-1.5 shadow-[0_0_10px_rgba(0,210,255,0.15)]"
          >
            <ShieldCheck className="w-4 h-4 text-cyan-400" />
            <span>Attack Intelligence</span>
          </button>
        </div>
      </div>

      {/* Resolution banner if resolved/dismissed */}
      {(incidentCase.status === 'RESOLVED' || incidentCase.status === 'DISMISSED') && (
        <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-800/40 text-xs font-mono flex items-start space-x-3">
          <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <span className="font-bold text-emerald-300 uppercase">
                Resolution: {incidentCase.resolution || incidentCase.status}
              </span>
              <span className="text-slate-500">•</span>
              <span className="text-slate-400">
                Resolved by {currentAnalyst || 'SOC Analyst'}
              </span>
            </div>
            {incidentCase.resolution_notes && (
              <p className="text-slate-300 font-sans text-xs pt-1">{incidentCase.resolution_notes}</p>
            )}
          </div>
        </div>
      )}

      {/* Case Overview Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-4">
          <span className="text-[10px] font-mono uppercase text-slate-400">Total Bounded Risk</span>
          <div className="text-2xl font-mono font-bold text-rose-400 mt-1">
            {incidentCase.total_risk_score.toFixed(1)} / 100
          </div>
          <span className="text-[10px] text-slate-500 font-mono">Maximum across correlated alerts</span>
        </div>

        <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-4">
          <span className="text-[10px] font-mono uppercase text-slate-400">Correlated Alerts</span>
          <div className="text-2xl font-mono font-bold text-cyan-400 mt-1">
            {incidentCase.alert_count}
          </div>
          <span className="text-[10px] text-slate-500 font-mono">Unified in 300s window</span>
        </div>

        <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-4">
          <span className="text-[10px] font-mono uppercase text-slate-400">Target Entity</span>
          <div className="text-xl font-mono font-bold text-white mt-1 truncate">
            {incidentCase.entity_id}
          </div>
          <span className="text-[10px] text-slate-500 font-mono">Type: {incidentCase.entity_type}</span>
        </div>

        <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-4">
          <span className="text-[10px] font-mono uppercase text-slate-400">Kill-Chain Stages</span>
          <div className="flex flex-wrap gap-1 mt-1.5">
            {incidentCase.kill_chain_stages.length > 0 ? (
              incidentCase.kill_chain_stages.map((s) => (
                <span key={s} className="px-1.5 py-0.5 rounded bg-rose-950/70 border border-rose-800 text-rose-300 text-[10px] font-mono font-bold">
                  {s}
                </span>
              ))
            ) : (
              <span className="text-xs text-slate-500 font-mono">No stages confirmed</span>
            )}
          </div>
        </div>
      </div>

      {/* Case Summary & Affected Entities */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="lg:col-span-2 bg-[#0d131d] border border-[#1c2638] rounded-xl p-5 space-y-3">
          <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300">
            Incident Case Summary
          </h3>
          <p className="text-sm text-slate-200 font-sans leading-relaxed">
            {incidentCase.summary}
          </p>
        </div>

        {/* CASE CONTEXT Sidebar */}
        <CaseContextSidebar incidentCase={incidentCase} />
      </div>

      {/* Recommended Response & Interactive Checklist */}
      <InvestigationChecklist
        id={incidentCase.case_id}
        scenarioOrTitle={incidentCase.title}
        details={{ summary: incidentCase.summary }}
      />

      {/* Analyst Notes Section */}
      <AnalystNotesSection
        notes={notesList}
        currentAnalyst={currentAnalyst}
        onSaveNote={handleSaveNote}
      />

      {/* Correlated Alerts List */}
      <div className="space-y-2">
        <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300">
          Correlated Threat Alerts ({alerts.length})
        </h3>
        <AlertTable alerts={alerts} />
      </div>

      {/* Investigation Timeline */}
      {timeline.length > 0 && (
        <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-5">
          <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300 mb-4 flex items-center space-x-2">
            <Clock className="w-4 h-4 text-cyan-400" />
            <span>Unified Incident Timeline</span>
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

      {/* Resolution Modal */}
      <ResolutionModal
        isOpen={isResolutionModalOpen}
        onClose={() => setIsResolutionModalOpen(false)}
        onConfirm={handleResolveCase}
        title={incidentCase.title}
        itemType="Case"
        currentAnalyst={currentAnalyst}
      />

      {/* Attack Intelligence Drawer */}
      <AttackIntelligencePanel
        incidentCase={incidentCase}
        isOpen={isIntelligenceOpen}
        onClose={() => setIsIntelligenceOpen(false)}
        onUpdate={fetchCase}
      />
    </div>
  );
};
