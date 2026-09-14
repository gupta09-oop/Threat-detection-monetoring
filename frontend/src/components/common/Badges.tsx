import React from 'react';
import type { RiskSeverity, AlertStatus, CaseStatus } from '../../types';

interface SeverityBadgeProps {
  severity: RiskSeverity | string;
  size?: 'sm' | 'md' | 'lg';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, size = 'sm' }) => {
  const sev = (severity || 'LOW').toUpperCase();

  const styles: Record<string, string> = {
    CRITICAL: 'bg-red-950/80 text-red-400 border-red-800/80 shadow-[0_0_10px_rgba(239,68,68,0.2)]',
    HIGH: 'bg-orange-950/80 text-orange-400 border-orange-800/80',
    MEDIUM: 'bg-amber-950/80 text-amber-400 border-amber-800/80',
    LOW: 'bg-emerald-950/80 text-emerald-400 border-emerald-800/80',
  };

  const sizeStyles: Record<string, string> = {
    sm: 'text-xs px-2 py-0.5',
    md: 'text-sm px-2.5 py-1',
    lg: 'text-base px-3 py-1.5',
  };

  return (
    <span
      className={`inline-flex items-center font-mono font-semibold tracking-wider rounded border ${
        styles[sev] || styles.LOW
      } ${sizeStyles[size]}`}
    >
      {sev}
    </span>
  );
};

interface StatusBadgeProps {
  status: AlertStatus | CaseStatus | string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status }) => {
  const s = (status || 'NEW').toUpperCase();

  const styles: Record<string, string> = {
    NEW: 'bg-cyan-950/60 text-cyan-400 border-cyan-800/60',
    ACKNOWLEDGED: 'bg-blue-950/60 text-blue-400 border-blue-800/60',
    ESCALATED: 'bg-purple-950/60 text-purple-400 border-purple-800/60',
    CLOSED: 'bg-slate-800/60 text-slate-400 border-slate-700/60',
    OPEN: 'bg-rose-950/60 text-rose-400 border-rose-800/60',
    INVESTIGATING: 'bg-amber-950/60 text-amber-400 border-amber-800/60',
    RESOLVED: 'bg-emerald-950/60 text-emerald-400 border-emerald-800/60',
    DISMISSED: 'bg-slate-800/60 text-slate-400 border-slate-700/60',
  };

  return (
    <span
      className={`inline-flex items-center text-xs font-mono font-medium px-2 py-0.5 rounded border ${
        styles[s] || 'bg-slate-800 text-slate-300 border-slate-700'
      }`}
    >
      {s}
    </span>
  );
};
