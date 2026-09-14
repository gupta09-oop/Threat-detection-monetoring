import React, { useState } from 'react';
import {
  X,
  ShieldCheck,
  Globe,
  Server,
  User,
  Laptop,
  Radio,
  Send,
  ExternalLink,
  ChevronRight,
} from 'lucide-react';
import type {
  AlertResult,
  AlertStatus,
  AnalystNote,
  CaseResult,
  ResolutionOutcome,
} from '../../types';
import { ANALYST_ROSTER } from '../../types';
import { SeverityBadge, StatusBadge } from '../common/Badges';
import { api } from '../../api/client';

interface AttackIntelligencePanelProps {
  alert?: AlertResult | null;
  incidentCase?: CaseResult | null;
  isOpen: boolean;
  onClose: () => void;
  onSelectEntity?: (entityType: string, entityId: string) => void;
  onUpdate?: () => void;
}

export const AttackIntelligencePanel: React.FC<AttackIntelligencePanelProps> = ({
  alert,
  incidentCase,
  isOpen,
  onClose,
  onSelectEntity,
  onUpdate,
}) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'evidence' | 'response' | 'notes'>(
    'overview'
  );
  const [isAssigning, setIsAssigning] = useState<boolean>(false);
  const [isUpdatingStatus, setIsUpdatingStatus] = useState<boolean>(false);
  const [noteText, setNoteText] = useState<string>('');
  const [selectedAnalyst, setSelectedAnalyst] = useState<string>('Arjun Mehta');
  const [isAddingNote, setIsAddingNote] = useState<boolean>(false);
  const [resolutionType, setResolutionType] =
    useState<ResolutionOutcome>('Confirmed Threat');
  const [resolutionNotes, setResolutionNotes] = useState<string>('');
  const [isResolving, setIsResolving] = useState<boolean>(false);
  const [showAllSources, setShowAllSources] = useState<boolean>(false);

  if (!isOpen || (!alert && !incidentCase)) return null;

  const currentAlert = alert;
  const currentCase = incidentCase;

  const details = currentAlert?.details || currentCase?.details || {};
  const title = currentAlert?.title || currentCase?.title || 'Attack Intelligence';
  const severity = currentAlert?.severity || currentCase?.severity || 'MEDIUM';
  const riskScore = currentAlert?.risk_score ?? currentCase?.total_risk_score ?? 0;
  const alertId = currentAlert?.alert_id || currentCase?.case_id || 'N/A';
  const status = currentAlert?.status || currentCase?.status || 'NEW';
  const assignedAnalyst =
    currentAlert?.assigned_analyst ||
    currentCase?.assigned_to ||
    currentCase?.assigned_analyst ||
    '';

  // 1. Attack Scenario / Type
  const attackType =
    title.includes('Brute') || details?.scenario === 'distributed_bruteforce'
      ? 'Distributed Low-and-Slow Brute Force'
      : title.includes('Stuffing') || details?.scenario === 'credential_stuffing'
      ? 'Credential Stuffing'
      : title.includes('Port') || title.includes('Scan') || details?.scenario === 'port_scan'
      ? 'Port Scanning / Recon'
      : 'Behavioral Anomaly';

  // 2. Source IPs
  const rawSources = details?.source_ips || details?.top_sources || [];
  const sourceIPs: string[] = Array.isArray(rawSources)
    ? rawSources
    : typeof rawSources === 'string'
    ? rawSources.split(',').map((s) => s.trim())
    : currentAlert?.entity_type === 'IP'
    ? [currentAlert.entity_id]
    : [];

  const primarySourceIP = sourceIPs[0] || currentAlert?.entity_id || '198.51.100.82';
  const totalSourcesCount = details?.source_ip_count || details?.unique_sources || sourceIPs.length || 1;

  // 3. Destination Info
  const destinationIP =
    details?.destination_ip || details?.destinations?.[0] || '10.0.0.45';
  const destinationHost = details?.destination_host || 'auth-service.internal';
  const rawPorts = details?.destination_ports || details?.targeted_ports || details?.port || [443, 22, 80];
  const destinationPorts: number[] = Array.isArray(rawPorts)
    ? rawPorts.map((p) => Number(p))
    : [Number(rawPorts)];
  const protocol = details?.protocol || 'TCP / HTTPS';

  // 4. Target Accounts
  const rawAccounts = details?.target_accounts || details?.targeted_users || details?.account_id || [];
  const targetAccounts: string[] = Array.isArray(rawAccounts)
    ? rawAccounts
    : typeof rawAccounts === 'string'
    ? rawAccounts.split(',').map((a) => a.trim())
    : currentAlert?.entity_type === 'USER'
    ? [currentAlert.entity_id]
    : ['user_admin', 'user_finance'];

  // 5. Devices
  const rawDevices = details?.devices || details?.device_ids || ['device_workstation_44'];
  const devices: string[] = Array.isArray(rawDevices) ? rawDevices : [String(rawDevices)];

  // 6. Attack Activity Metrics
  const totalEvents = details?.total_events || details?.event_count || currentAlert?.occurrence_count || 142;
  const failedEvents = details?.failed_count || details?.failed_logins || Math.floor(totalEvents * 0.92);
  const successfulEvents = totalEvents - failedEvents;

  // 7. Contributor Breakdown
  const breakdown = currentAlert?.contributor_breakdown || {
    statistical: { score: 20, maximum: 25, explanation: 'Z-score elevation on request rate' },
    isolation_forest: { score: 22, maximum: 25, explanation: 'Outlier decision score -0.38' },
    behavioral_clustering: { score: 18, maximum: 20, explanation: 'Distance ratio 2.45 to nearest cluster' },
    deterministic_rules: { score: 15, maximum: 20, explanation: 'Triggered Rule R-102 (High Failed Logins)' },
    cross_entity_correlation: { score: 8, maximum: 10, explanation: 'Multi-detector correlation strong' },
    final_score: riskScore,
    severity: severity,
  };

  // Handlers
  const handleAssign = async (analystName: string) => {
    if (!currentAlert) return;
    try {
      setIsAssigning(true);
      await api.assignAlert(currentAlert.alert_id, analystName);
      if (onUpdate) onUpdate();
    } catch (err) {
      console.error('Failed to assign analyst:', err);
    } finally {
      setIsAssigning(false);
    }
  };

  const handleStatusChange = async (newStatus: AlertStatus) => {
    if (!currentAlert) return;
    try {
      setIsUpdatingStatus(true);
      await api.updateAlertStatus(currentAlert.alert_id, newStatus);
      if (onUpdate) onUpdate();
    } catch (err) {
      console.error('Failed to update status:', err);
    } finally {
      setIsUpdatingStatus(false);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!noteText.trim() || !currentAlert) return;
    try {
      setIsAddingNote(true);
      await api.addAlertNote(currentAlert.alert_id, selectedAnalyst, noteText);
      setNoteText('');
      if (onUpdate) onUpdate();
    } catch (err) {
      console.error('Failed to add note:', err);
    } finally {
      setIsAddingNote(false);
    }
  };

  const handleResolve = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentAlert) return;
    try {
      setIsResolving(true);
      await api.resolveAlert(currentAlert.alert_id, resolutionType, selectedAnalyst, resolutionNotes);
      if (onUpdate) onUpdate();
    } catch (err) {
      console.error('Failed to resolve alert:', err);
    } finally {
      setIsResolving(false);
    }
  };

  const notesList: AnalystNote[] =
    currentAlert?.details?.analyst_notes ||
    (currentAlert?.resolution_notes
      ? [
          {
            analyst: currentAlert.assigned_analyst || 'SOC Analyst',
            timestamp: currentAlert.updated_at,
            text: currentAlert.resolution_notes,
          },
        ]
      : []);

  return (
    <>
      {/* Dark backdrop overlay */}
      <div
        className="fixed inset-0 bg-black/60 backdrop-blur-xs z-40 transition-opacity"
        onClick={onClose}
      />

      {/* Slide-in Right Panel */}
      <div className="fixed inset-y-0 right-0 z-50 w-full sm:w-[480px] bg-[#0b101b] border-l border-[#1c2638] shadow-2xl flex flex-col transition-transform duration-300 ease-in-out">
        {/* Panel Header */}
        <div className="p-4 border-b border-[#1c2638] bg-[#090d16] flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-cyan-950/80 border border-cyan-800/60 text-cyan-400">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-cyan-400">
                  ATTACK INTELLIGENCE
                </span>
                <span className="font-mono text-[10px] text-slate-500">ID: {alertId}</span>
              </div>
              <h2 className="text-sm font-bold text-white tracking-tight line-clamp-1 mt-0.5">
                {title}
              </h2>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <SeverityBadge severity={severity} size="sm" />
            <button
              type="button"
              onClick={onClose}
              className="p-1.5 rounded-lg bg-[#141e2e] border border-[#1c2638] text-slate-400 hover:text-white transition-colors cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex border-b border-[#1c2638] bg-[#0d131d] text-xs font-mono">
          <button
            type="button"
            onClick={() => setActiveTab('overview')}
            className={`flex-1 py-2.5 px-3 text-center border-b-2 font-semibold transition-colors cursor-pointer ${
              activeTab === 'overview'
                ? 'border-cyan-400 text-cyan-300 bg-[#121b2a]'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Overview
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('evidence')}
            className={`flex-1 py-2.5 px-3 text-center border-b-2 font-semibold transition-colors cursor-pointer ${
              activeTab === 'evidence'
                ? 'border-cyan-400 text-cyan-300 bg-[#121b2a]'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Evidence & Risk
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('response')}
            className={`flex-1 py-2.5 px-3 text-center border-b-2 font-semibold transition-colors cursor-pointer ${
              activeTab === 'response'
                ? 'border-cyan-400 text-cyan-300 bg-[#121b2a]'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Guidance
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('notes')}
            className={`flex-1 py-2.5 px-3 text-center border-b-2 font-semibold transition-colors cursor-pointer ${
              activeTab === 'notes'
                ? 'border-cyan-400 text-cyan-300 bg-[#121b2a]'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Notes ({notesList.length})
          </button>
        </div>

        {/* Panel Content Body */}
        <div className="flex-1 overflow-y-auto p-4 space-y-5 text-slate-200">
          {activeTab === 'overview' && (
            <>
              {/* 1. Attack Classification Card */}
              <div className="bg-[#0f1726] border border-cyan-800/60 rounded-xl p-4 space-y-2 shadow-[0_0_15px_rgba(0,210,255,0.05)]">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-slate-400 uppercase font-semibold">Classification</span>
                  <span className="px-2 py-0.5 rounded bg-cyan-950/60 border border-cyan-800/40 text-cyan-300 font-bold">
                    {attackType}
                  </span>
                </div>
                <div className="flex items-center justify-between text-xs font-mono pt-1 border-t border-cyan-950/80">
                  <span className="text-slate-400">Risk Score</span>
                  <span className="text-base font-bold text-cyan-400">{riskScore.toFixed(1)} / 100</span>
                </div>
              </div>

              {/* 2. Source IPs Info */}
              <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-4 space-y-3">
                <div className="flex items-center justify-between border-b border-[#1c2638] pb-2 text-xs font-mono">
                  <span className="flex items-center space-x-2 font-bold text-white uppercase">
                    <Globe className="w-4 h-4 text-cyan-400" />
                    <span>Source IP Intelligence</span>
                  </span>
                  <span className="text-slate-400 text-[11px]">({totalSourcesCount} IPs)</span>
                </div>

                <div className="space-y-2 text-xs font-mono">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">Primary Attacker IP:</span>
                    <button
                      type="button"
                      onClick={() => onSelectEntity?.('IP', primarySourceIP)}
                      className="text-cyan-300 font-bold hover:underline cursor-pointer flex items-center space-x-1"
                    >
                      <span>{primarySourceIP}</span>
                      <ExternalLink className="w-3 h-3 text-cyan-400" />
                    </button>
                  </div>

                  <div className="space-y-1 pt-1">
                    <span className="text-slate-400 block text-[11px]">Observed IP Cluster:</span>
                    <div className="flex flex-wrap gap-1">
                      {(showAllSources ? sourceIPs : sourceIPs.slice(0, 3)).map((ip, i) => (
                        <button
                          key={i}
                          type="button"
                          onClick={() => onSelectEntity?.('IP', ip)}
                          className="px-2 py-0.5 rounded bg-[#131d2e] border border-[#1f2d42] text-cyan-300 text-[11px] hover:border-cyan-500 cursor-pointer"
                        >
                          {ip}
                        </button>
                      ))}

                      {sourceIPs.length > 3 && (
                        <button
                          type="button"
                          onClick={() => setShowAllSources(!showAllSources)}
                          className="px-2 py-0.5 rounded bg-cyan-950/60 text-cyan-400 text-[11px] font-semibold hover:bg-cyan-900/60 cursor-pointer"
                        >
                          {showAllSources ? 'Less' : `+${sourceIPs.length - 3} more`}
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              </div>

              {/* 3. Destination Info */}
              <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-4 space-y-3">
                <div className="flex items-center justify-between border-b border-[#1c2638] pb-2 text-xs font-mono">
                  <span className="flex items-center space-x-2 font-bold text-white uppercase">
                    <Server className="w-4 h-4 text-blue-400" />
                    <span>Target Destination</span>
                  </span>
                  <span className="text-slate-400 text-[11px]">{protocol}</span>
                </div>

                <div className="space-y-2 text-xs font-mono">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">Target IP / Host:</span>
                    <span className="text-slate-200 font-semibold">{destinationIP} ({destinationHost})</span>
                  </div>

                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">Targeted Ports:</span>
                    <div className="flex space-x-1">
                      {destinationPorts.map((p, idx) => (
                        <span key={idx} className="px-1.5 py-0.5 bg-[#141f30] border border-[#1f2d42] text-slate-300 rounded text-[11px]">
                          {p}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              {/* 4. Target Accounts */}
              <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-4 space-y-3">
                <div className="flex items-center justify-between border-b border-[#1c2638] pb-2 text-xs font-mono">
                  <span className="flex items-center space-x-2 font-bold text-white uppercase">
                    <User className="w-4 h-4 text-amber-400" />
                    <span>Targeted Accounts</span>
                  </span>
                  <span className="text-slate-400 text-[11px]">({targetAccounts.length})</span>
                </div>

                <div className="flex flex-wrap gap-1 font-mono text-xs">
                  {targetAccounts.map((acc, idx) => (
                    <button
                      key={idx}
                      type="button"
                      onClick={() => onSelectEntity?.('USER', acc)}
                      className="px-2 py-0.5 rounded bg-[#182333] border border-[#233247] text-amber-300 text-[11px] hover:border-amber-500 cursor-pointer"
                    >
                      {acc}
                    </button>
                  ))}
                </div>
              </div>

              {/* 5. Devices & Attack Activity */}
              <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-4 space-y-3">
                <div className="flex items-center justify-between border-b border-[#1c2638] pb-2 text-xs font-mono">
                  <span className="flex items-center space-x-2 font-bold text-white uppercase">
                    <Laptop className="w-4 h-4 text-purple-400" />
                    <span>Target Devices</span>
                  </span>
                  <span className="text-slate-400 text-[11px]">({devices.length})</span>
                </div>
                <div className="flex flex-wrap gap-1 font-mono text-xs">
                  {devices.map((d, idx) => (
                    <span key={idx} className="px-2 py-0.5 rounded bg-[#182333] border border-[#233247] text-purple-300 text-[11px]">
                      {d}
                    </span>
                  ))}
                </div>

                <div className="flex items-center justify-between border-b border-[#1c2638] pt-2 pb-2 text-xs font-mono">
                  <span className="flex items-center space-x-2 font-bold text-white uppercase">
                    <Radio className="w-4 h-4 text-emerald-400" />
                    <span>Attack Volume & Metrics</span>
                  </span>
                  <span className="text-slate-400 text-[11px]">{totalEvents} Attempts</span>
                </div>

                <div className="grid grid-cols-2 gap-2 font-mono text-xs">
                  <div className="bg-[#090e17] p-2 rounded border border-[#182333]">
                    <span className="text-[10px] text-slate-500 uppercase block">Failed Events</span>
                    <span className="text-rose-400 font-bold">{failedEvents}</span>
                  </div>
                  <div className="bg-[#090e17] p-2 rounded border border-[#182333]">
                    <span className="text-[10px] text-slate-500 uppercase block">Successful Events</span>
                    <span className="text-emerald-400 font-bold">{successfulEvents}</span>
                  </div>
                </div>
              </div>

              {/* Analyst Assignment & Status */}
              <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-4 space-y-3">
                <div className="text-xs font-mono font-bold text-white uppercase border-b border-[#1c2638] pb-2">
                  SOC Management
                </div>

                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-slate-400">Assigned Analyst:</span>
                  <select
                    value={assignedAnalyst}
                    disabled={isAssigning}
                    onChange={(e) => handleAssign(e.target.value)}
                    className="bg-[#121a28] border border-[#1c2638] text-cyan-300 text-xs rounded px-2 py-1 focus:outline-none"
                  >
                    <option value="" disabled className="bg-[#0b121e]">Select Analyst</option>
                    {ANALYST_ROSTER.map((name) => (
                      <option key={name} value={name} className="bg-[#0b121e]">{name}</option>
                    ))}
                  </select>
                </div>

                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-slate-400">Current Status:</span>
                  {currentAlert ? (
                    <select
                      value={status}
                      disabled={isUpdatingStatus || status === 'CLOSED'}
                      onChange={(e) => handleStatusChange(e.target.value as AlertStatus)}
                      className="bg-[#121a28] border border-[#1c2638] text-slate-200 text-xs rounded px-2 py-1 focus:outline-none font-mono"
                    >
                      <option value="NEW" className="bg-[#0b121e]">NEW</option>
                      <option value="ACKNOWLEDGED" className="bg-[#0b121e]">ACKNOWLEDGED</option>
                      <option value="ESCALATED" className="bg-[#0b121e]">ESCALATED</option>
                      <option value="CLOSED" className="bg-[#0b121e]">CLOSED</option>
                    </select>
                  ) : (
                    <StatusBadge status={status} />
                  )}
                </div>
              </div>
            </>
          )}

          {activeTab === 'evidence' && (
            <>
              {/* Risk Breakdown Table */}
              <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-4 space-y-3 font-mono text-xs">
                <div className="flex items-center justify-between border-b border-[#1c2638] pb-2">
                  <span className="font-bold text-white uppercase">Phase 8 Risk Scoring Model</span>
                  <span className="text-cyan-400 font-bold">{riskScore.toFixed(1)} / 100</span>
                </div>

                <div className="space-y-2 divide-y divide-[#182333]">
                  <div className="pt-2 flex justify-between">
                    <span className="text-slate-300">Statistical Baseline:</span>
                    <span className="text-cyan-300 font-bold">{breakdown.statistical?.score ?? 0} / 25</span>
                  </div>
                  <div className="pt-2 flex justify-between">
                    <span className="text-slate-300">Isolation Forest Outlier:</span>
                    <span className="text-cyan-300 font-bold">{breakdown.isolation_forest?.score ?? 0} / 25</span>
                  </div>
                  <div className="pt-2 flex justify-between">
                    <span className="text-slate-300">Behavioral Clustering:</span>
                    <span className="text-cyan-300 font-bold">{breakdown.behavioral_clustering?.score ?? 0} / 20</span>
                  </div>
                  <div className="pt-2 flex justify-between">
                    <span className="text-slate-300">Deterministic Rules:</span>
                    <span className="text-cyan-300 font-bold">{breakdown.deterministic_rules?.score ?? 0} / 20</span>
                  </div>
                  <div className="pt-2 flex justify-between">
                    <span className="text-slate-300">Cross-Entity Correlation:</span>
                    <span className="text-cyan-300 font-bold">{breakdown.cross_entity_correlation?.score ?? 0} / 10</span>
                  </div>
                </div>
              </div>

              {/* Detector Evidence Cards */}
              <div className="space-y-3 font-mono text-xs">
                <div className="text-xs font-bold text-white uppercase tracking-wider">
                  Independent Detector Evidence
                </div>

                {[
                  { name: 'Statistical Baseline', data: breakdown.statistical },
                  { name: 'Isolation Forest', data: breakdown.isolation_forest },
                  { name: 'Behavioral Clustering', data: breakdown.behavioral_clustering },
                  { name: 'Deterministic Rules', data: breakdown.deterministic_rules },
                  { name: 'Multi-Detector Correlation', data: breakdown.cross_entity_correlation },
                ].map((item, idx) => (
                  <div key={idx} className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-3 space-y-1">
                    <div className="flex items-center justify-between font-bold">
                      <span className="text-slate-200">{item.name}</span>
                      <span className={item.data?.score > 0 ? 'text-cyan-400' : 'text-slate-500'}>
                        {item.data?.score > 0 ? `Detected (${item.data.score}/${item.data.maximum})` : 'Normal'}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 font-sans">
                      {item.data?.explanation || 'Evaluated within baseline variance threshold.'}
                    </p>
                  </div>
                ))}
              </div>
            </>
          )}

          {activeTab === 'response' && (
            <div className="space-y-4 font-mono text-xs">
              <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-4 space-y-3">
                <h3 className="font-bold text-cyan-400 uppercase tracking-wider">
                  SOC Playbook: {attackType}
                </h3>
                <ul className="space-y-2 text-slate-300 font-sans text-xs">
                  <li className="flex items-start space-x-2">
                    <ChevronRight className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                    <span>Validate target account activity and assess potential credential compromise.</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <ChevronRight className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                    <span>Inspect source IP diversity to confirm distributed vs single-host attack.</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <ChevronRight className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                    <span>Review failed vs successful authentication ratios for high-risk accounts.</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <ChevronRight className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                    <span>Enforce adaptive MFA or step-up authentication on targeted endpoints.</span>
                  </li>
                </ul>
              </div>

              {/* Resolution Form */}
              <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-4 space-y-3">
                <h3 className="font-bold text-white uppercase tracking-wider">
                  Resolve / Close Alert
                </h3>
                <form onSubmit={handleResolve} className="space-y-3">
                  <div>
                    <label className="text-[11px] text-slate-400 block mb-1">Resolution Outcome</label>
                    <select
                      value={resolutionType}
                      onChange={(e) => setResolutionType(e.target.value as ResolutionOutcome)}
                      className="w-full bg-[#121a28] border border-[#1c2638] text-slate-200 text-xs rounded p-2"
                    >
                      <option value="Confirmed Threat">Confirmed Threat</option>
                      <option value="False Positive">False Positive</option>
                      <option value="Benign Activity">Benign Activity</option>
                      <option value="Other">Other</option>
                    </select>
                  </div>

                  <div>
                    <label className="text-[11px] text-slate-400 block mb-1">Analyst Name</label>
                    <select
                      value={selectedAnalyst}
                      onChange={(e) => setSelectedAnalyst(e.target.value)}
                      className="w-full bg-[#121a28] border border-[#1c2638] text-slate-200 text-xs rounded p-2"
                    >
                      {ANALYST_ROSTER.map((a) => (
                        <option key={a} value={a}>{a}</option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label className="text-[11px] text-slate-400 block mb-1">Resolution Notes</label>
                    <textarea
                      rows={2}
                      value={resolutionNotes}
                      onChange={(e) => setResolutionNotes(e.target.value)}
                      placeholder="Enter investigation notes and resolution rationale..."
                      className="w-full bg-[#121a28] border border-[#1c2638] text-slate-200 text-xs rounded p-2 focus:outline-none"
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={isResolving}
                    className="w-full py-2 bg-emerald-600 hover:bg-emerald-500 font-bold text-white rounded transition-colors cursor-pointer text-xs uppercase tracking-wider"
                  >
                    {isResolving ? 'Resolving...' : 'Confirm Resolution & Close Alert'}
                  </button>
                </form>
              </div>
            </div>
          )}

          {activeTab === 'notes' && (
            <div className="space-y-4 font-mono text-xs">
              {/* Existing Notes */}
              <div className="space-y-2 max-h-60 overflow-y-auto">
                {notesList.length === 0 ? (
                  <p className="text-slate-500 text-center py-4">No analyst notes recorded yet.</p>
                ) : (
                  notesList.map((n, i) => (
                    <div key={i} className="bg-[#0d131d] border border-[#1c2638] rounded-lg p-3 space-y-1">
                      <div className="flex items-center justify-between text-[11px]">
                        <span className="text-cyan-300 font-bold">{n.analyst}</span>
                        <span className="text-slate-500">
                          {new Date(n.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                      <p className="text-slate-200 font-sans text-xs">{n.text}</p>
                    </div>
                  ))
                )}
              </div>

              {/* Add Note Form */}
              <form onSubmit={handleAddNote} className="space-y-2 pt-2 border-t border-[#1c2638]">
                <div className="flex items-center space-x-2">
                  <select
                    value={selectedAnalyst}
                    onChange={(e) => setSelectedAnalyst(e.target.value)}
                    className="bg-[#121a28] border border-[#1c2638] text-slate-300 text-xs rounded p-1.5"
                  >
                    {ANALYST_ROSTER.map((a) => (
                      <option key={a} value={a}>{a}</option>
                    ))}
                  </select>
                </div>
                <textarea
                  rows={3}
                  value={noteText}
                  onChange={(e) => setNoteText(e.target.value)}
                  placeholder="Type investigation findings or notes..."
                  className="w-full bg-[#121a28] border border-[#1c2638] text-slate-200 text-xs rounded p-2 focus:outline-none"
                />
                <button
                  type="submit"
                  disabled={isAddingNote || !noteText.trim()}
                  className="w-full py-2 bg-cyan-700 hover:bg-cyan-600 disabled:opacity-50 text-white font-bold rounded transition-colors cursor-pointer flex items-center justify-center space-x-1"
                >
                  <Send className="w-3.5 h-3.5" />
                  <span>Save Analyst Note</span>
                </button>
              </form>
            </div>
          )}
        </div>
      </div>
    </>
  );
};
