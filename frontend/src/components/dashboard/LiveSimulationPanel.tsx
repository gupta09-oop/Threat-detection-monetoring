import React, { useState, useEffect } from 'react';
import {
  Play,
  Square,
  Activity,
  Shield,
  Crosshair,
  Radio,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Flame,
  Check,
} from 'lucide-react';
import { api } from '../../api/client';
import { wsManager } from '../../api/ws';
import type { SimulationStatusResponse } from '../../types';

interface LiveSimulationPanelProps {
  onSimulationUpdate?: () => void;
}

export const LiveSimulationPanel: React.FC<LiveSimulationPanelProps> = ({ onSimulationUpdate }) => {
  const [status, setStatus] = useState<SimulationStatusResponse>({
    running: false,
    progress: 0,
    events_generated: 0,
    current_stage: 'idle',
    elapsed_seconds: 0,
    completed: false,
  });
  const [isStarting, setIsStarting] = useState<boolean>(false);
  const [isStopping, setIsStopping] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Poll status while running or check periodically
  const fetchStatus = async () => {
    try {
      const current = await api.getSimulationStatus();
      setStatus(current);
      if (current.running && onSimulationUpdate) {
        onSimulationUpdate();
      }
    } catch {
      // ignore transient network hiccups
    }
  };

  useEffect(() => {
    fetchStatus();

    // Subscribe to WebSocket simulation events
    const unsubWs = wsManager.subscribeMessages((msg) => {
      if (msg.type === 'simulation.status' && msg.data) {
        setStatus(msg.data);
        if (onSimulationUpdate) {
          onSimulationUpdate();
        }
      }
    });

    // Short polling while running, slow polling otherwise
    const interval = setInterval(() => {
      fetchStatus();
    }, status.running ? 1000 : 5000);

    return () => {
      unsubWs();
      clearInterval(interval);
    };
  }, [status.running]);

  const handleStart = async (scenario: string, durationSeconds: number = 30) => {
    try {
      setIsStarting(true);
      setErrorMessage(null);
      const res = await api.startSimulation({
        scenario,
        seed: 42,
        duration_seconds: durationSeconds,
        intensity: 'normal',
      });
      setStatus(res);
      if (onSimulationUpdate) {
        onSimulationUpdate();
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to start simulation');
    } finally {
      setIsStarting(false);
    }
  };

  const handleStop = async () => {
    try {
      setIsStopping(true);
      await api.stopSimulation();
      fetchStatus();
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to stop simulation');
    } finally {
      setIsStopping(false);
    }
  };

  const formatElapsed = (secs: number) => {
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    return `${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
  };

  const scenarios = [
    {
      id: 'distributed_bruteforce',
      title: 'Distributed Brute Force',
      badge: 'Low-and-Slow Auth',
      duration: 30,
      description: 'Distributed auth across 100+ rotating source IPs targeting accounts to evade per-IP thresholds.',
      icon: Shield,
      color: 'border-cyan-800/40 hover:border-cyan-500 text-cyan-400',
    },
    {
      id: 'credential_stuffing',
      title: 'Credential Stuffing',
      badge: 'Account Takeover',
      duration: 30,
      description: 'Mass credential reuse distributed across diverse IPs, targeted accounts, and new device identifiers.',
      icon: Crosshair,
      color: 'border-amber-800/40 hover:border-amber-500 text-amber-400',
    },
    {
      id: 'port_scan',
      title: 'Port Scan / Recon',
      badge: 'Network Discovery',
      duration: 25,
      description: 'High-frequency TCP probes across destination ports exhibiting elevated connection refused and timeout rates.',
      icon: Radio,
      color: 'border-indigo-800/40 hover:border-indigo-500 text-indigo-400',
    },
    {
      id: 'all',
      title: 'Full Attack Showcase',
      badge: 'Sequential Multi-Stage',
      duration: 120,
      description: 'Sequential execution: Normal Baseline → Distributed Brute Force → Credential Stuffing → Port Scan.',
      icon: Flame,
      color: 'border-rose-800/40 hover:border-rose-500 text-rose-400 bg-rose-950/10',
    },
  ];

  return (
    <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-5 shadow-lg space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-[#1c2638] pb-3 gap-2">
        <div className="flex items-center space-x-2.5">
          <div className="p-2 rounded-lg bg-cyan-950/30 border border-cyan-800/30 text-cyan-400">
            <Activity className="w-4 h-4 animate-pulse" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-white tracking-wide flex items-center space-x-2">
              <span>LIVE ATTACK SIMULATION</span>
              {status.running && (
                <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono bg-rose-950/50 text-rose-400 border border-rose-800/40 animate-pulse">
                  RUNNING
                </span>
              )}
            </h3>
            <p className="text-xs text-slate-400">Generate controlled synthetic attack telemetry</p>
          </div>
        </div>

        {status.running && (
          <button
            onClick={handleStop}
            disabled={isStopping}
            className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-rose-950/60 border border-rose-800/60 text-rose-300 hover:bg-rose-900/60 hover:text-white text-xs font-mono transition-all cursor-pointer shadow-[0_0_10px_rgba(244,63,94,0.15)]"
          >
            <Square className="w-3.5 h-3.5 fill-current" />
            <span>{isStopping ? 'STOPPING...' : 'STOP SIMULATION'}</span>
          </button>
        )}
      </div>

      {/* Error alert if any */}
      {errorMessage && (
        <div className="p-3 rounded-lg bg-rose-950/30 border border-rose-800/40 text-xs text-rose-300 flex items-center space-x-2">
          <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
          <span>{errorMessage}</span>
        </div>
      )}

      {/* Active Run Status Monitor */}
      {status.running ? (
        <div className="p-4 rounded-xl bg-[#090e17] border border-[#1c2638] space-y-3">
          <div className="flex flex-wrap items-center justify-between text-xs font-mono gap-2">
            <div className="flex items-center space-x-2">
              <span className="text-slate-400">Scenario:</span>
              <span className="text-cyan-400 font-semibold uppercase">{status.scenario || 'Live Attack'}</span>
            </div>
            <div className="flex items-center space-x-2">
              <span className="text-slate-400">Stage:</span>
              <span className="text-amber-400 font-semibold">{status.current_stage}</span>
            </div>
            <div className="flex items-center space-x-2">
              <span className="text-slate-400">Events:</span>
              <span className="text-white font-bold">{status.events_generated}</span>
            </div>
            <div className="flex items-center space-x-1.5 text-slate-400">
              <Clock className="w-3.5 h-3.5" />
              <span className="text-slate-200">{formatElapsed(status.elapsed_seconds)}</span>
            </div>
          </div>

          {/* Progress Bar */}
          <div className="space-y-1">
            <div className="flex justify-between text-[11px] font-mono text-slate-400">
              <span>Execution Progress</span>
              <span className="text-cyan-400">{status.progress}%</span>
            </div>
            <div className="w-full bg-[#162030] rounded-full h-2 overflow-hidden border border-[#25334a]">
              <div
                className="bg-gradient-to-r from-cyan-500 to-blue-500 h-full transition-all duration-300 ease-out rounded-full"
                style={{ width: `${Math.max(4, status.progress)}%` }}
              />
            </div>
          </div>
        </div>
      ) : (
        /* Scenario Selection Buttons */
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {scenarios.map((sc) => {
            const Icon = sc.icon;
            return (
              <div
                key={sc.id}
                className={`p-3.5 rounded-xl bg-[#090e17] border ${sc.color} flex flex-col justify-between transition-all group`}
              >
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <div className="p-1.5 rounded-lg bg-[#121a28] border border-[#1c2638] text-current">
                      <Icon className="w-4 h-4" />
                    </div>
                    <span className="text-[10px] font-mono text-slate-400 bg-[#121a28] px-2 py-0.5 rounded border border-[#1c2638]">
                      {sc.badge}
                    </span>
                  </div>
                  <h4 className="text-xs font-semibold text-white tracking-wide group-hover:text-cyan-300 transition-colors">
                    {sc.title}
                  </h4>
                  <p className="text-[11px] text-slate-400 mt-1 leading-snug line-clamp-3">
                    {sc.description}
                  </p>
                </div>

                <button
                  onClick={() => handleStart(sc.id, sc.duration)}
                  disabled={isStarting || status.running}
                  className="mt-3 w-full flex items-center justify-center space-x-1.5 py-1.5 px-3 rounded-lg bg-[#121a28] hover:bg-cyan-950/40 hover:border-cyan-700/50 border border-[#1c2638] text-xs font-mono text-slate-300 hover:text-cyan-300 transition-all cursor-pointer disabled:opacity-50"
                >
                  <Play className="w-3 h-3 fill-current" />
                  <span>Launch Simulation</span>
                </button>
              </div>
            );
          })}
        </div>
      )}

      {/* Completed Run Result Summary Card */}
      {status.completed && status.last_result && !status.running && (
        <div className="p-4 rounded-xl bg-[#090e17] border border-emerald-900/40 space-y-3">
          <div className="flex items-center justify-between border-b border-[#182433] pb-2">
            <div className="flex items-center space-x-2 text-emerald-400 text-xs font-mono font-semibold">
              <CheckCircle2 className="w-4 h-4" />
              <span>SIMULATION COMPLETE</span>
            </div>
            <span className="text-[11px] font-mono text-slate-400 uppercase">
              {status.last_result.scenario || status.scenario}
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono">
            <div className="p-2.5 rounded-lg bg-[#0d131d] border border-[#1c2638]">
              <span className="text-[10px] text-slate-400 block">Events Ingested</span>
              <span className="text-base font-bold text-white">{status.last_result.events_generated || 0}</span>
            </div>
            <div className="p-2.5 rounded-lg bg-[#0d131d] border border-[#1c2638]">
              <span className="text-[10px] text-slate-400 block">Alerts Triggered</span>
              <span className="text-base font-bold text-cyan-400">{status.last_result.alerts_created || 0}</span>
            </div>
            <div className="p-2.5 rounded-lg bg-[#0d131d] border border-[#1c2638]">
              <span className="text-[10px] text-slate-400 block">Cases Correlated</span>
              <span className="text-base font-bold text-amber-400">{status.last_result.cases_created || 0}</span>
            </div>
            <div className="p-2.5 rounded-lg bg-[#0d131d] border border-[#1c2638]">
              <span className="text-[10px] text-slate-400 block">Peak Risk Score</span>
              <span className="text-base font-bold text-rose-400">
                {status.last_result.peak_risk_score ?? 0} / 100
              </span>
            </div>
          </div>

          {/* Genuine Detection Signals */}
          <div className="pt-2 flex flex-wrap items-center gap-2 text-[11px] font-mono text-slate-300">
            <span className="text-slate-400">Active Signals:</span>
            {status.last_result.contributing_detectors && status.last_result.contributing_detectors.length > 0 ? (
              status.last_result.contributing_detectors.map((det: string, i: number) => (
                <span
                  key={i}
                  className="px-2 py-0.5 rounded bg-cyan-950/40 border border-cyan-800/40 text-cyan-300 flex items-center space-x-1"
                >
                  <Check className="w-3 h-3 text-cyan-400" />
                  <span>{det.replace('_', ' ')}</span>
                </span>
              ))
            ) : (
              <span className="text-slate-400 italic">Evaluating continuous baseline metrics</span>
            )}
            {status.last_result.evidence_strength && (
              <span className="px-2 py-0.5 rounded bg-purple-950/40 border border-purple-800/40 text-purple-300">
                Evidence: {status.last_result.evidence_strength}
              </span>
            )}
          </div>

          {status.last_result.explanation && (
            <p className="text-xs text-slate-300 font-sans italic border-t border-[#182433] pt-2">
              "{status.last_result.explanation}"
            </p>
          )}
        </div>
      )}
    </div>
  );
};
