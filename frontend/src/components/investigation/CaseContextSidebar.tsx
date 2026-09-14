import React, { useState } from 'react';
import {
  ShieldAlert,
  Server,
  User,
  Laptop,
  Globe,
  Radio,
  Clock,
  ChevronDown,
  ChevronUp,
  UserCheck,
  Tag,
  Hash,
} from 'lucide-react';
import type { AlertResult, CaseResult } from '../../types';
import { SeverityBadge, StatusBadge } from '../common/Badges';

interface CaseContextSidebarProps {
  alert?: AlertResult | null;
  incidentCase?: CaseResult | null;
  className?: string;
}

/**
 * Normalizes entity array extraction from alert/case details
 */
function extractEntities(
  primaryValue: string | undefined | null,
  details: Record<string, any> = {},
  keys: string[]
): string[] {
  const set = new Set<string>();

  if (primaryValue && primaryValue !== 'GLOBAL' && primaryValue !== 'NONE') {
    set.add(primaryValue);
  }

  for (const key of keys) {
    const val = details[key];
    if (Array.isArray(val)) {
      val.forEach((item) => {
        if (item) set.add(String(item));
      });
    } else if (typeof val === 'string' && val.trim()) {
      val.split(',').forEach((item) => set.add(item.trim()));
    } else if (typeof val === 'number') {
      set.add(String(val));
    }
  }

  return Array.from(set);
}

export const CaseContextSidebar: React.FC<CaseContextSidebarProps> = ({
  alert,
  incidentCase,
  className = '',
}) => {
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({});

  const toggleExpand = (sectionKey: string) => {
    setExpandedSections((prev) => ({ ...prev, [sectionKey]: !prev[sectionKey] }));
  };

  const details = alert?.details || incidentCase?.details || {};
  const caseId = incidentCase?.case_id || alert?.case_id || 'N/A';
  const alertId = alert?.alert_id || 'N/A';
  const title = alert?.title || incidentCase?.title || 'Security Incident';
  const severity = alert?.severity || incidentCase?.severity || 'MEDIUM';
  const riskScore = alert?.risk_score ?? incidentCase?.total_risk_score ?? 0;
  const status = alert?.status || incidentCase?.status || 'OPEN';
  const evidenceStrength =
    alert?.evidence_strength || details?.evidence_strength || 'STRONG';
  const assignedAnalyst =
    alert?.assigned_analyst ||
    incidentCase?.assigned_to ||
    incidentCase?.assigned_analyst ||
    'Unassigned';

  // Entity Lists
  const sourceIPs = extractEntities(
    alert?.entity_type === 'IP' ? alert.entity_id : incidentCase?.entity_type === 'IP' ? incidentCase.entity_id : null,
    details,
    ['source_ips', 'top_sources', 'source_ip', 'attacker_ip', 'client_ip']
  );

  const targetAccounts = extractEntities(
    alert?.entity_type === 'USER' ? alert.entity_id : incidentCase?.entity_type === 'USER' ? incidentCase.entity_id : null,
    details,
    ['target_accounts', 'targeted_users', 'user_id', 'account_id', 'accounts', 'user_ids']
  );

  const devices = extractEntities(null, details, [
    'devices',
    'device_ids',
    'device_id',
    'workstations',
    'hosts',
  ]);

  const destinationIPs = extractEntities(null, details, [
    'destination_ips',
    'destinations',
    'destination_ip',
    'target_host',
    'server_ip',
  ]);

  const destinationPorts = extractEntities(null, details, [
    'destination_ports',
    'targeted_ports',
    'ports',
    'port',
  ]);

  const protocol =
    details?.protocol ||
    details?.protocols?.[0] ||
    (destinationPorts.includes('22')
      ? 'SSH (TCP 22)'
      : destinationPorts.includes('443')
      ? 'HTTPS (TCP 443)'
      : destinationPorts.includes('80')
      ? 'HTTP (TCP 80)'
      : 'TCP/IP');

  const firstSeen =
    details?.first_seen ||
    alert?.created_at ||
    incidentCase?.opened_at ||
    alert?.timestamp ||
    new Date().toISOString();

  const lastSeen =
    details?.last_seen ||
    alert?.updated_at ||
    incidentCase?.updated_at ||
    alert?.timestamp ||
    new Date().toISOString();

  const eventCount =
    details?.event_count ??
    details?.total_events ??
    alert?.occurrence_count ??
    incidentCase?.alert_count ??
    1;

  const renderEntityGroup = (
    label: string,
    icon: React.ReactNode,
    entities: string[],
    key: string
  ) => {
    if (entities.length === 0) return null;
    const isExpanded = expandedSections[key];
    const displayItems = isExpanded ? entities : entities.slice(0, 3);
    const hiddenCount = entities.length - 3;

    return (
      <div className="space-y-1 py-1.5 border-b border-[#182333]/80 last:border-b-0">
        <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
          <span className="flex items-center space-x-1.5">
            {icon}
            <span className="font-semibold">{label}</span>
          </span>
          <span className="text-slate-500 font-mono">({entities.length})</span>
        </div>

        <div className="flex flex-wrap gap-1 pt-1 font-mono text-xs">
          {displayItems.map((item, idx) => (
            <span
              key={idx}
              className="px-2 py-0.5 rounded bg-[#131d2e] border border-[#1f2d42] text-cyan-300 text-[11px] font-mono break-all"
            >
              {item}
            </span>
          ))}

          {!isExpanded && hiddenCount > 0 && (
            <button
              type="button"
              onClick={() => toggleExpand(key)}
              className="px-2 py-0.5 rounded bg-cyan-950/40 hover:bg-cyan-900/60 border border-cyan-800/40 text-cyan-400 text-[11px] font-mono font-semibold transition-colors cursor-pointer flex items-center space-x-1"
            >
              <span>+{hiddenCount} more</span>
              <ChevronDown className="w-3 h-3" />
            </button>
          )}

          {isExpanded && entities.length > 3 && (
            <button
              type="button"
              onClick={() => toggleExpand(key)}
              className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 hover:text-white text-[11px] font-mono transition-colors cursor-pointer flex items-center space-x-1"
            >
              <span>Show less</span>
              <ChevronUp className="w-3 h-3" />
            </button>
          )}
        </div>
      </div>
    );
  };

  return (
    <div className={`bg-[#0d131d] border border-[#1c2638] rounded-xl p-4 shadow-lg space-y-4 text-slate-200 ${className}`}>
      {/* Sidebar Header */}
      <div className="flex items-center justify-between border-b border-[#1c2638] pb-3">
        <div className="flex items-center space-x-2">
          <div className="p-1.5 rounded-lg bg-cyan-950/60 border border-cyan-800/50 text-cyan-400">
            <ShieldAlert className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-xs font-mono font-bold text-white uppercase tracking-wider">
              CASE CONTEXT
            </h2>
            <p className="text-[10px] font-mono text-slate-400">SOC Forensic Summary</p>
          </div>
        </div>
        <StatusBadge status={status} />
      </div>

      {/* Primary Overview Badges */}
      <div className="grid grid-cols-2 gap-2 bg-[#090e17] p-2.5 rounded-lg border border-[#182333]">
        <div>
          <div className="text-[10px] font-mono text-slate-500 uppercase">Severity</div>
          <div className="mt-0.5">
            <SeverityBadge severity={severity} size="sm" />
          </div>
        </div>
        <div>
          <div className="text-[10px] font-mono text-slate-500 uppercase">Risk Score</div>
          <div className="text-sm font-mono font-bold text-cyan-300">
            {riskScore.toFixed(1)} <span className="text-[10px] text-slate-500">/ 100</span>
          </div>
        </div>
      </div>

      {/* Key Metadata Table */}
      <div className="space-y-1.5 text-xs font-mono">
        <div className="flex items-center justify-between py-1 border-b border-[#182333]">
          <span className="text-slate-400 flex items-center space-x-1">
            <Hash className="w-3 h-3 text-slate-500" />
            <span>Incident ID</span>
          </span>
          <span className="text-cyan-300 font-semibold truncate max-w-[150px]">
            {alertId !== 'N/A' ? alertId : caseId}
          </span>
        </div>

        <div className="flex items-center justify-between py-1 border-b border-[#182333]">
          <span className="text-slate-400 flex items-center space-x-1">
            <Tag className="w-3 h-3 text-slate-500" />
            <span>Attack Classification</span>
          </span>
          <span className="text-slate-200 font-medium truncate max-w-[160px]" title={title}>
            {title}
          </span>
        </div>

        <div className="flex items-center justify-between py-1 border-b border-[#182333]">
          <span className="text-slate-400">Evidence Strength</span>
          <span className="px-2 py-0.5 rounded bg-cyan-950/40 border border-cyan-800/40 text-cyan-300 font-bold text-[10px] uppercase">
            {evidenceStrength}
          </span>
        </div>

        <div className="flex items-center justify-between py-1 border-b border-[#182333]">
          <span className="text-slate-400 flex items-center space-x-1">
            <UserCheck className="w-3 h-3 text-slate-500" />
            <span>Assigned Analyst</span>
          </span>
          <span className="text-slate-200">{assignedAnalyst}</span>
        </div>

        <div className="flex items-center justify-between py-1 border-b border-[#182333]">
          <span className="text-slate-400 flex items-center space-x-1">
            <Radio className="w-3 h-3 text-slate-500" />
            <span>Protocol</span>
          </span>
          <span className="text-cyan-400">{protocol}</span>
        </div>

        <div className="flex items-center justify-between py-1 border-b border-[#182333]">
          <span className="text-slate-400 flex items-center space-x-1">
            <Radio className="w-3 h-3 text-slate-500" />
            <span>Event Count</span>
          </span>
          <span className="text-cyan-300 font-bold">{eventCount} events</span>
        </div>
      </div>

      {/* Observed Entity Lists */}
      <div className="space-y-1">
        <div className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-bold mb-1">
          Observed Incident Entities
        </div>

        {renderEntityGroup(
          'Source IPs (FROM WHERE)',
          <Globe className="w-3.5 h-3.5 text-cyan-400" />,
          sourceIPs,
          'sources'
        )}

        {renderEntityGroup(
          'Target Accounts (WHO / TARGET)',
          <User className="w-3.5 h-3.5 text-amber-400" />,
          targetAccounts,
          'accounts'
        )}

        {renderEntityGroup(
          'Devices (WHAT DEVICE)',
          <Laptop className="w-3.5 h-3.5 text-emerald-400" />,
          devices,
          'devices'
        )}

        {renderEntityGroup(
          'Destination IPs / Hosts',
          <Server className="w-3.5 h-3.5 text-blue-400" />,
          destinationIPs,
          'destinations'
        )}

        {renderEntityGroup(
          'Destination Ports',
          <Hash className="w-3.5 h-3.5 text-violet-400" />,
          destinationPorts,
          'ports'
        )}
      </div>

      {/* Timeline Footprint */}
      <div className="pt-2 border-t border-[#1c2638] space-y-1 text-[11px] font-mono text-slate-400">
        <div className="flex items-center justify-between">
          <span className="flex items-center space-x-1">
            <Clock className="w-3 h-3 text-slate-500" />
            <span>First Seen</span>
          </span>
          <span className="text-slate-300">
            {new Date(firstSeen).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
          </span>
        </div>

        <div className="flex items-center justify-between">
          <span className="flex items-center space-x-1">
            <Clock className="w-3 h-3 text-slate-500" />
            <span>Last Seen</span>
          </span>
          <span className="text-slate-300">
            {new Date(lastSeen).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
          </span>
        </div>
      </div>
    </div>
  );
};
