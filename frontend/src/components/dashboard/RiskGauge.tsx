import React from 'react';
import type { RiskSeverity } from '../../types';

interface RiskGaugeProps {
  score: number;
  severity: RiskSeverity | string;
  evidenceStrength?: string;
  size?: number;
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({
  score = 0,
  severity = 'LOW',
  evidenceStrength = 'LOW',
  size = 200,
}) => {
  const clampedScore = Math.min(100, Math.max(0, score));
  const strokeWidth = 14;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  // Use a 270 degree arc for gauge look
  const strokeDashoffset = circumference - (clampedScore / 100) * (circumference * 0.75);

  const getSeverityColors = (sev: string) => {
    switch (sev.toUpperCase()) {
      case 'CRITICAL':
        return {
          stroke: '#ef4444',
          glow: 'rgba(239, 68, 68, 0.4)',
          text: 'text-red-400',
        };
      case 'HIGH':
        return {
          stroke: '#f97316',
          glow: 'rgba(249, 115, 22, 0.4)',
          text: 'text-orange-400',
        };
      case 'MEDIUM':
        return {
          stroke: '#f59e0b',
          glow: 'rgba(245, 158, 11, 0.4)',
          text: 'text-amber-400',
        };
      default:
        return {
          stroke: '#10b981',
          glow: 'rgba(16, 185, 129, 0.3)',
          text: 'text-emerald-400',
        };
    }
  };

  const colors = getSeverityColors(severity);

  return (
    <div className="flex flex-col items-center justify-center relative p-2">
      <svg width={size} height={size} className="transform -rotate-90">
        {/* Track circle */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="#131c2a"
          strokeWidth={strokeWidth}
          fill="transparent"
          strokeDasharray={`${circumference * 0.75} ${circumference * 0.25}`}
        />
        {/* Active gauge circle */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={colors.stroke}
          strokeWidth={strokeWidth}
          fill="transparent"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          style={{
            filter: `drop-shadow(0 0 8px ${colors.glow})`,
            transition: 'stroke-dashoffset 0.8s ease-out, stroke 0.5s ease',
          }}
        />
      </svg>

      {/* Value Overlay */}
      <div className="absolute inset-0 flex flex-col items-center justify-center pt-2">
        <span className="text-[11px] font-mono uppercase tracking-widest text-slate-400">
          Risk Score
        </span>
        <div className="flex items-baseline space-x-0.5">
          <span className={`text-4xl font-mono font-bold tracking-tighter ${colors.text}`}>
            {clampedScore.toFixed(1)}
          </span>
          <span className="text-xs font-mono text-slate-500">/100</span>
        </div>
        <div className="flex items-center space-x-1.5 mt-1">
          <span
            className={`text-xs font-mono font-semibold px-2 py-0.5 rounded border border-[#1c2638] bg-[#070b12] ${colors.text}`}
          >
            {severity.toUpperCase()}
          </span>
          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-900/60 text-slate-400 border border-slate-800">
            {evidenceStrength}
          </span>
        </div>
      </div>
    </div>
  );
};
