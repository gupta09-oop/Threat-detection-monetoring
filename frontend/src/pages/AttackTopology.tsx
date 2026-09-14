import React, { useEffect, useState } from 'react';
import { Network, RefreshCw } from 'lucide-react';
import { api } from '../api/client';
import type { CanonicalEvent } from '../types';
import { AttackTopologyGraph } from '../components/topology/AttackTopologyGraph';

export const AttackTopologyPage: React.FC = () => {
  const [events, setEvents] = useState<CanonicalEvent[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const fetchTopologyEvents = async () => {
    try {
      setIsLoading(true);
      const data = await api.getEvents({ limit: 150 });
      setEvents(data);
    } catch (err) {
      console.error('Failed to fetch topology telemetry:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchTopologyEvents();
  }, []);

  return (
    <div className="space-y-4 max-w-[1600px] mx-auto h-[calc(100vh-100px)] flex flex-col">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight flex items-center space-x-2">
            <Network className="w-5 h-5 text-cyan-400" />
            <span>Attack Topology Environment</span>
          </h2>
          <p className="text-xs text-slate-400">
            Full-screen interactive entity relationship graph (IP → Account → Device → Destination → Port)
          </p>
        </div>

        <button
          onClick={fetchTopologyEvents}
          disabled={isLoading}
          className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-[#0d131d] border border-[#1c2638] text-xs font-mono text-slate-300 hover:text-cyan-400 hover:border-cyan-800 transition-all cursor-pointer"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
          <span>Refresh Graph</span>
        </button>
      </div>

      <div className="flex-1 w-full">
        <AttackTopologyGraph events={events} height="100%" />
      </div>
    </div>
  );
};
