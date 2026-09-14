import React, { useEffect, useState } from 'react';
import { ShieldAlert, Filter, RefreshCw } from 'lucide-react';
import { api } from '../api/client';
import { wsManager } from '../api/ws';
import type { AlertResult } from '../types';
import { AlertTable } from '../components/alerts/AlertTable';

export const AlertsPage: React.FC = () => {
  const [alerts, setAlerts] = useState<AlertResult[]>([]);
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const fetchAlerts = async () => {
    try {
      setIsLoading(true);
      const data = await api.getAlerts({
        limit: 100,
        severity: severityFilter || undefined,
        status: statusFilter || undefined,
      });
      setAlerts(data);
    } catch (err) {
      console.error('Failed to fetch alerts:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();

    const unsub = wsManager.subscribeMessages((msg) => {
      if (msg.type.startsWith('alert.')) {
        fetchAlerts();
      }
    });

    return () => unsub();
  }, [severityFilter, statusFilter]);

  return (
    <div className="space-y-6 max-w-[1600px] mx-auto">
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight flex items-center space-x-2">
            <ShieldAlert className="w-5 h-5 text-cyan-400" />
            <span>Security Alerts</span>
          </h2>
          <p className="text-xs text-slate-400">
            Deduplicated threat alerts evaluated when Risk Score ≥ 40.0
          </p>
        </div>

        {/* Filters */}
        <div className="flex items-center space-x-3 text-xs font-mono">
          <div className="flex items-center space-x-1.5 bg-[#0d131d] border border-[#1c2638] rounded-lg px-2.5 py-1.5">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-transparent text-slate-200 outline-none cursor-pointer"
            >
              <option value="" className="bg-[#0d131d]">All Severities</option>
              <option value="CRITICAL" className="bg-[#0d131d]">CRITICAL</option>
              <option value="HIGH" className="bg-[#0d131d]">HIGH</option>
              <option value="MEDIUM" className="bg-[#0d131d]">MEDIUM</option>
            </select>
          </div>

          <div className="flex items-center space-x-1.5 bg-[#0d131d] border border-[#1c2638] rounded-lg px-2.5 py-1.5">
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-transparent text-slate-200 outline-none cursor-pointer"
            >
              <option value="" className="bg-[#0d131d]">All Statuses</option>
              <option value="NEW" className="bg-[#0d131d]">NEW</option>
              <option value="ACKNOWLEDGED" className="bg-[#0d131d]">ACKNOWLEDGED</option>
              <option value="ESCALATED" className="bg-[#0d131d]">ESCALATED</option>
              <option value="CLOSED" className="bg-[#0d131d]">CLOSED</option>
            </select>
          </div>

          <button
            onClick={fetchAlerts}
            className="p-1.5 rounded-lg bg-[#0d131d] border border-[#1c2638] text-slate-400 hover:text-white"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      <AlertTable alerts={alerts} isLoading={isLoading} />
    </div>
  );
};
