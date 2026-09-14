import React from 'react';
import { Shield, ChevronRight } from 'lucide-react';

interface KillChainTrackerProps {
  stages?: string[];
}

export const KillChainTracker: React.FC<KillChainTrackerProps> = ({ stages = [] }) => {
  const allStages = [
    { key: 'RECON', label: '1. Reconnaissance' },
    { key: 'INITIAL_ACCESS', label: '2. Initial Access' },
    { key: 'STAGING', label: '3. Staging' },
    { key: 'EXFILTRATION', label: '4. Exfiltration' },
    { key: 'COVER-UP', label: '5. Cover-Up' },
  ];

  const activeSet = new Set((stages || []).map((s) => s.toUpperCase()));

  return (
    <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-4">
      <div className="flex items-center space-x-2 mb-3">
        <Shield className="w-4 h-4 text-cyan-400" />
        <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider font-mono">
          Kill-Chain Stage Progression
        </h3>
      </div>

      <div className="flex items-center justify-between gap-1 overflow-x-auto py-1">
        {allStages.map((stage, idx) => {
          const isActive = activeSet.has(stage.key);

          return (
            <React.Fragment key={stage.key}>
              <div
                className={`flex-1 min-w-[130px] p-2.5 rounded-lg border text-center transition-all ${
                  isActive
                    ? 'bg-rose-950/40 border-rose-800/80 text-rose-300 shadow-[0_0_10px_rgba(239,68,68,0.15)]'
                    : 'bg-[#090e17] border-[#182233] text-slate-500'
                }`}
              >
                <div className="text-[11px] font-mono font-medium">
                  {stage.label}
                </div>
                <div className="text-[10px] font-mono mt-1">
                  {isActive ? (
                    <span className="text-rose-400 font-bold uppercase tracking-wider">
                      ● Detected
                    </span>
                  ) : (
                    <span className="text-slate-600">No Evidence</span>
                  )}
                </div>
              </div>

              {idx < allStages.length - 1 && (
                <ChevronRight className="w-4 h-4 text-slate-700 shrink-0" />
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
};
