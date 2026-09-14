import React from 'react';
import { Terminal } from 'lucide-react';
import type { CanonicalEvent } from '../../types';

interface LiveTelemetryFeedProps {
  events: CanonicalEvent[];
  isLoading?: boolean;
}

export const LiveTelemetryFeed: React.FC<LiveTelemetryFeedProps> = ({ events, isLoading }) => {
  if (isLoading) {
    return (
      <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-6 text-center animate-pulse">
        <div className="h-4 bg-[#1c2638] rounded w-1/4 mx-auto" />
      </div>
    );
  }

  if (!events || events.length === 0) {
    return (
      <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-6 text-center font-mono text-xs text-slate-500">
        No recent telemetry events recorded in SQLite.
      </div>
    );
  }

  return (
    <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl overflow-hidden shadow-lg">
      <div className="p-3 bg-[#090e17] border-b border-[#1c2638] flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <Terminal className="w-4 h-4 text-cyan-400" />
          <h3 className="text-xs font-mono font-semibold text-slate-200 uppercase tracking-wider">
            Canonical Telemetry Log (/api/events)
          </h3>
        </div>
        <span className="text-[10px] font-mono text-slate-500">
          Showing {events.length} most recent events
        </span>
      </div>

      <div className="overflow-x-auto max-h-72 overflow-y-auto">
        <table className="w-full text-left text-xs font-mono">
          <thead className="bg-[#090e17]/80 text-slate-400 text-[10px] uppercase border-b border-[#182233] sticky top-0">
            <tr>
              <th className="py-2 px-3">Time</th>
              <th className="py-2 px-3">Source</th>
              <th className="py-2 px-3">Type</th>
              <th className="py-2 px-3">Source IP</th>
              <th className="py-2 px-3">User / Target</th>
              <th className="py-2 px-3">Dest / Port</th>
              <th className="py-2 px-3 text-right">Result</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#141d2c] text-slate-300 text-[11px]">
            {events.map((e) => {
              const isFailure =
                e.result === 'FAILURE' ||
                e.result === 'DENY' ||
                e.result === 'REFUSED' ||
                e.result === 'TIMEOUT';

              return (
                <tr key={e.event_id} className="hover:bg-[#121927]">
                  <td className="py-2 px-3 text-slate-500 whitespace-nowrap">
                    {new Date(e.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="py-2 px-3 text-cyan-400 font-semibold">{e.source_type}</td>
                  <td className="py-2 px-3 text-slate-300">{e.event_type}</td>
                  <td className="py-2 px-3 text-slate-300">{e.source_ip || '-'}</td>
                  <td className="py-2 px-3 text-slate-200">{e.user_id || e.device_id || '-'}</td>
                  <td className="py-2 px-3 text-slate-400">
                    {e.destination_ip ? `${e.destination_ip}:${e.port || '*'}` : e.port ? `Port ${e.port}` : '-'}
                  </td>
                  <td className="py-2 px-3 text-right">
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        isFailure
                          ? 'bg-rose-950/70 text-rose-400 border border-rose-800/60'
                          : 'bg-emerald-950/70 text-emerald-400 border border-emerald-800/60'
                      }`}
                    >
                      {e.result}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
