import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldAlert, ArrowRight, X } from 'lucide-react';
import { wsManager, type WebSocketMessage } from '../../api/ws';
import type { AlertResult } from '../../types';

export const LiveAlertPopup: React.FC = () => {
  const [activeAlert, setActiveAlert] = useState<AlertResult | null>(null);
  const [progress, setProgress] = useState(100);
  const navigate = useNavigate();

  useEffect(() => {
    const unsub = wsManager.subscribeMessages((msg: WebSocketMessage) => {
      if (msg.type === 'simulation.reset') {
        setActiveAlert(null);
        return;
      }

      if (msg.type === 'alert.created' && msg.data) {
        setActiveAlert(msg.data as AlertResult);
        setProgress(100);

        // Optional Web Audio notification beep
        try {
          const AudioContextClass = window.AudioContext || (window as any).webkitAudioContext;
          if (AudioContextClass) {
            const ctx = new AudioContextClass();
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.type = 'sine';
            osc.frequency.setValueAtTime(880, ctx.currentTime);
            gain.gain.setValueAtTime(0.08, ctx.currentTime);
            gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.35);
            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.start();
            osc.stop(ctx.currentTime + 0.35);
          }
        } catch {
          // Ignore audio restriction if browser requires user gesture
        }
      }
    });

    return () => unsub();
  }, []);

  // Auto-dismiss countdown after 15 seconds
  useEffect(() => {
    if (!activeAlert) return;

    const duration = 15000;
    const intervalTime = 100;
    const step = (intervalTime / duration) * 100;

    const timer = setInterval(() => {
      setProgress((prev) => {
        if (prev <= 1) {
          clearInterval(timer);
          setActiveAlert(null);
          return 0;
        }
        return prev - step;
      });
    }, intervalTime);

    return () => clearInterval(timer);
  }, [activeAlert]);

  if (!activeAlert) return null;

  const isCritical = activeAlert.severity === 'CRITICAL';
  const isHigh = activeAlert.severity === 'HIGH';

  const borderColor = isCritical
    ? 'border-red-500 shadow-[0_0_25px_rgba(239,68,68,0.45)]'
    : isHigh
    ? 'border-amber-500 shadow-[0_0_20px_rgba(245,158,11,0.35)]'
    : 'border-cyan-500 shadow-[0_0_20px_rgba(6,182,212,0.3)]';

  const badgeBg = isCritical
    ? 'bg-red-500/20 text-red-400 border-red-500/40'
    : isHigh
    ? 'bg-amber-500/20 text-amber-400 border-amber-500/40'
    : 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40';

  const attackClassification =
    activeAlert.details?.attack_type ||
    activeAlert.details?.scenario ||
    activeAlert.details?.attack_classification ||
    null;

  const handleInvestigate = () => {
    const alertId = activeAlert.alert_id;
    setActiveAlert(null);
    navigate(`/alerts/${alertId}`);
  };

  return (
    <div
      role="alert"
      aria-live="assertive"
      className={`fixed top-20 right-6 z-50 w-96 rounded-xl border bg-[#0b121e]/95 backdrop-blur-md p-4 transition-all duration-300 animate-in slide-in-from-top-4 ${borderColor}`}
    >
      {/* Header bar */}
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center space-x-2">
          <div className="p-1.5 rounded-lg bg-red-500/20 text-red-400 animate-pulse">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold tracking-wider uppercase border ${badgeBg}`}>
                {activeAlert.severity} THREAT DETECTED
              </span>
            </div>
            <h4 className="text-xs font-semibold text-white mt-1 line-clamp-1">
              {activeAlert.title}
            </h4>
          </div>
        </div>
        <button
          type="button"
          onClick={() => setActiveAlert(null)}
          className="text-slate-400 hover:text-white p-1 rounded transition-colors"
          title="Dismiss notification"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Metric details */}
      <div className="mt-3 grid grid-cols-2 gap-2 bg-[#070b12]/80 rounded-lg p-2.5 border border-[#1c2638] text-xs font-mono">
        <div>
          <div className="text-[10px] uppercase text-slate-400">Risk Score</div>
          <div className="text-sm font-bold text-red-400">
            {activeAlert.risk_score.toFixed(1)} <span className="text-[10px] text-slate-400">/ 100</span>
          </div>
        </div>
        <div>
          <div className="text-[10px] uppercase text-slate-400">Evidence</div>
          <div className="text-xs font-semibold text-amber-400">
            {activeAlert.evidence_strength || 'STRONG'}
          </div>
        </div>
        <div className="col-span-2 pt-1 border-t border-[#1c2638]/60">
          <div className="text-[10px] uppercase text-slate-400">Affected Entity</div>
          <div className="text-xs text-cyan-300 truncate font-mono">
            {activeAlert.entity_id}
          </div>
        </div>
        {attackClassification && (
          <div className="col-span-2 pt-1 border-t border-[#1c2638]/60">
            <div className="text-[10px] uppercase text-slate-400">Attack Pattern</div>
            <div className="text-xs text-amber-300 font-semibold uppercase">
              {attackClassification}
            </div>
          </div>
        )}
      </div>

      {/* Rationale explanation */}
      {activeAlert.explanation && (
        <p className="mt-2 text-[11px] text-slate-300 line-clamp-2 leading-relaxed">
          {activeAlert.explanation}
        </p>
      )}

      {/* Action button */}
      <div className="mt-3 flex items-center justify-between gap-2">
        <span className="text-[10px] font-mono text-slate-400">
          {new Date(activeAlert.timestamp).toLocaleTimeString()}
        </span>
        <button
          type="button"
          onClick={handleInvestigate}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 text-black font-semibold text-xs hover:from-cyan-400 hover:to-blue-500 transition-all shadow-[0_0_12px_rgba(0,210,255,0.4)] cursor-pointer"
        >
          <span>INVESTIGATE</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Countdown progress bar */}
      <div className="mt-2.5 h-1 w-full bg-[#1c2638] rounded-full overflow-hidden">
        <div
          className="h-full bg-cyan-400 transition-all duration-100 ease-linear"
          style={{ width: `${progress}%` }}
        />
      </div>
    </div>
  );
};
