import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Briefcase, ExternalLink, RefreshCw, Filter } from 'lucide-react';
import { api } from '../api/client';
import { wsManager } from '../api/ws';
import type { CaseResult } from '../types';
import { SeverityBadge, StatusBadge } from '../components/common/Badges';

export const CasesPage: React.FC = () => {
  const [cases, setCases] = useState<CaseResult[]>([]);
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const fetchCases = async () => {
    try {
      setIsLoading(true);
      const data = await api.getCases({
        limit: 100,
        status: statusFilter || undefined,
      });
      setCases(data);
    } catch (err) {
      console.error('Failed to fetch cases:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchCases();

    const unsub = wsManager.subscribeMessages((msg) => {
      if (msg.type.startsWith('case.')) {
        fetchCases();
      }
    });

    return () => unsub();
  }, [statusFilter]);

  return (
    <div className="space-y-6 max-w-[1600px] mx-auto">
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight flex items-center space-x-2">
            <Briefcase className="w-5 h-5 text-amber-400" />
            <span>SOC Incident Cases</span>
          </h2>
          <p className="text-xs text-slate-400">
            Correlated multi-alert incident management lifecycle (OPEN, INVESTIGATING, RESOLVED, DISMISSED)
          </p>
        </div>

        {/* Filters */}
        <div className="flex items-center space-x-3 text-xs font-mono">
          <div className="flex items-center space-x-1.5 bg-[#0d131d] border border-[#1c2638] rounded-lg px-2.5 py-1.5">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-transparent text-slate-200 outline-none cursor-pointer"
            >
              <option value="" className="bg-[#0d131d]">All Statuses</option>
              <option value="OPEN" className="bg-[#0d131d]">OPEN</option>
              <option value="INVESTIGATING" className="bg-[#0d131d]">INVESTIGATING</option>
              <option value="RESOLVED" className="bg-[#0d131d]">RESOLVED</option>
              <option value="DISMISSED" className="bg-[#0d131d]">DISMISSED</option>
            </select>
          </div>

          <button
            onClick={fetchCases}
            className="p-1.5 rounded-lg bg-[#0d131d] border border-[#1c2638] text-slate-400 hover:text-white"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {isLoading ? (
        <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-8 text-center animate-pulse font-mono text-xs text-slate-500">
          Loading incident cases...
        </div>
      ) : cases.length === 0 ? (
        <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-8 text-center">
          <Briefcase className="w-8 h-8 text-slate-600 mx-auto mb-2" />
          <p className="text-sm text-slate-400 font-mono">No active incident cases</p>
          <p className="text-xs text-slate-600 mt-1">Telemetry within safe operational limits</p>
        </div>
      ) : (
        <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl overflow-hidden shadow-lg">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#090e17] border-b border-[#1c2638] text-slate-400 font-mono text-[11px] uppercase tracking-wider">
              <tr>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Incident Case Title</th>
                <th className="py-3 px-4">Primary Entity</th>
                <th className="py-3 px-4 text-center">Bounded Risk Score</th>
                <th className="py-3 px-4 text-center">Correlated Alerts</th>
                <th className="py-3 px-4 text-center">Status</th>
                <th className="py-3 px-4">Kill-Chain Stages</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#162030] text-slate-300 font-sans">
              {cases.map((c) => (
                <tr key={c.case_id} className="hover:bg-[#121927] transition-colors group">
                  <td className="py-3 px-4">
                    <SeverityBadge severity={c.severity} />
                  </td>
                  <td className="py-3 px-4">
                    <div className="font-semibold text-slate-100 group-hover:text-cyan-400 transition-colors">
                      {c.title}
                    </div>
                    <div className="text-[11px] text-slate-400 truncate max-w-md">
                      {c.summary}
                    </div>
                  </td>
                  <td className="py-3 px-4 font-mono text-slate-200">
                    {c.entity_id}
                  </td>
                  <td className="py-3 px-4 text-center font-mono font-bold text-slate-100">
                    {c.total_risk_score.toFixed(1)} / 100
                  </td>
                  <td className="py-3 px-4 text-center font-mono text-cyan-400 font-semibold">
                    {c.alert_count}
                  </td>
                  <td className="py-3 px-4 text-center">
                    <StatusBadge status={c.status} />
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex flex-wrap gap-1">
                      {(c.kill_chain_stages || []).map((st) => (
                        <span
                          key={st}
                          className="px-1.5 py-0.5 rounded bg-rose-950/60 text-rose-300 border border-rose-900/60 text-[10px] font-mono font-medium"
                        >
                          {st}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="py-3 px-4 text-right">
                    <Link
                      to={`/cases/${c.case_id}`}
                      className="inline-flex items-center space-x-1 px-2.5 py-1 rounded bg-[#152132] hover:bg-cyan-950/60 hover:text-cyan-400 hover:border-cyan-800/60 border border-[#1c2638] text-xs font-mono transition-all text-slate-300"
                    >
                      <span>Manage</span>
                      <ExternalLink className="w-3 h-3" />
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
