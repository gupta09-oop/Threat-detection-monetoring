import React from 'react';
import { Link } from 'react-router-dom';
import { ShieldAlert, ExternalLink, Clock } from 'lucide-react';
import type { AlertResult } from '../../types';
import { SeverityBadge, StatusBadge } from '../common/Badges';

interface AlertTableProps {
  alerts: AlertResult[];
  isLoading?: boolean;
}

export const AlertTable: React.FC<AlertTableProps> = ({ alerts, isLoading }) => {
  if (isLoading) {
    return (
      <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-6 text-center animate-pulse">
        <div className="h-4 bg-[#1c2638] rounded w-1/4 mx-auto mb-3" />
        <div className="h-3 bg-[#1c2638] rounded w-1/2 mx-auto" />
      </div>
    );
  }

  if (!alerts || alerts.length === 0) {
    return (
      <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-8 text-center">
        <ShieldAlert className="w-8 h-8 text-slate-600 mx-auto mb-2" />
        <p className="text-sm text-slate-400 font-mono">No active alerts detected</p>
        <p className="text-xs text-slate-600 mt-1">Telemetry within normal baseline limits</p>
      </div>
    );
  }

  return (
    <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl overflow-hidden shadow-lg">
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-[#090e17] border-b border-[#1c2638] text-slate-400 font-mono text-[11px] uppercase tracking-wider">
            <tr>
              <th className="py-3 px-4">Severity</th>
              <th className="py-3 px-4">Alert Title / Detection Rationale</th>
              <th className="py-3 px-4">Entity</th>
              <th className="py-3 px-4 text-center">Risk Score</th>
              <th className="py-3 px-4 text-center">Occurrences</th>
              <th className="py-3 px-4 text-center">Status</th>
              <th className="py-3 px-4">Timestamp</th>
              <th className="py-3 px-4 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#162030] text-slate-300">
            {alerts.map((a) => (
              <tr
                key={a.alert_id}
                className="hover:bg-[#121927] transition-colors group font-sans"
              >
                <td className="py-3 px-4">
                  <SeverityBadge severity={a.severity} />
                </td>
                <td className="py-3 px-4">
                  <div className="font-medium text-slate-100 group-hover:text-cyan-400 transition-colors">
                    {a.title}
                  </div>
                  <div className="text-[11px] text-slate-400 truncate max-w-md font-mono">
                    {a.explanation}
                  </div>
                </td>
                <td className="py-3 px-4 font-mono text-slate-200">
                  {a.entity_id}
                </td>
                <td className="py-3 px-4 text-center font-mono font-bold text-slate-100">
                  {a.risk_score.toFixed(1)}
                </td>
                <td className="py-3 px-4 text-center font-mono text-slate-400">
                  x{a.occurrence_count}
                </td>
                <td className="py-3 px-4 text-center">
                  <StatusBadge status={a.status} />
                </td>
                <td className="py-3 px-4 font-mono text-[11px] text-slate-400 whitespace-nowrap">
                  <span className="flex items-center space-x-1">
                    <Clock className="w-3 h-3 text-slate-500" />
                    <span>{new Date(a.timestamp).toLocaleTimeString()}</span>
                  </span>
                </td>
                <td className="py-3 px-4 text-right">
                  <Link
                    to={`/alerts/${a.alert_id}`}
                    className="inline-flex items-center space-x-1 px-2.5 py-1 rounded bg-[#152132] hover:bg-cyan-950/60 hover:text-cyan-400 hover:border-cyan-800/60 border border-[#1c2638] text-xs font-mono transition-all text-slate-300"
                  >
                    <span>Investigate</span>
                    <ExternalLink className="w-3 h-3" />
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
