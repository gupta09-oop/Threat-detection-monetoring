import React from 'react';
import { Cpu, Trees, Boxes, ShieldCheck, Share2 } from 'lucide-react';
import type { ContributorBreakdown } from '../../types';

interface EvidenceCardsProps {
  breakdown?: ContributorBreakdown | null;
}

export const EvidenceCards: React.FC<EvidenceCardsProps> = ({ breakdown }) => {
  const defaultBreakdown = {
    statistical: { score: 0, maximum: 25, evidence: 'NORMAL', explanation: 'Normal baseline distribution' },
    isolation_forest: { score: 0, maximum: 25, evidence: 'NORMAL', explanation: 'Normal behavioral vector distribution' },
    behavioral_clustering: { score: 0, maximum: 20, evidence: 'NORMAL', explanation: 'Normal cluster membership' },
    deterministic_rules: { score: 0, maximum: 20, evidence: 'NORMAL', explanation: 'No deterministic rule violations' },
    cross_entity_correlation: { score: 0, maximum: 10, evidence_strength: 'NONE', explanation: 'Zero cross-entity correlation' },
    final_score: 0,
    severity: 'LOW' as const,
  };

  const activeBreakdown = breakdown || defaultBreakdown;

  const detectors = [
    {
      name: 'Statistical Baseline',
      icon: Cpu,
      score: activeBreakdown.statistical?.score ?? 0,
      max: activeBreakdown.statistical?.maximum ?? 25,
      evidence: activeBreakdown.statistical?.evidence || 'NORMAL',
      explanation: activeBreakdown.statistical?.explanation || 'Normal baseline features',
      isAnomalous: (activeBreakdown.statistical?.score ?? 0) > 0,
    },
    {
      name: 'Isolation Forest',
      icon: Trees,
      score: activeBreakdown.isolation_forest?.score ?? 0,
      max: activeBreakdown.isolation_forest?.maximum ?? 25,
      evidence: activeBreakdown.isolation_forest?.evidence || 'NORMAL',
      explanation: activeBreakdown.isolation_forest?.explanation || 'Normal behavioral vector distribution',
      isAnomalous: (activeBreakdown.isolation_forest?.score ?? 0) > 0,
    },
    {
      name: 'Behavioral Clustering',
      icon: Boxes,
      score: activeBreakdown.behavioral_clustering?.score ?? 0,
      max: activeBreakdown.behavioral_clustering?.maximum ?? 20,
      evidence: activeBreakdown.behavioral_clustering?.evidence || 'NORMAL',
      explanation: activeBreakdown.behavioral_clustering?.explanation || 'Normal cluster membership',
      isAnomalous: (activeBreakdown.behavioral_clustering?.score ?? 0) > 0,
    },
    {
      name: 'Deterministic Rules',
      icon: ShieldCheck,
      score: activeBreakdown.deterministic_rules?.score ?? 0,
      max: activeBreakdown.deterministic_rules?.maximum ?? 20,
      evidence: (activeBreakdown.deterministic_rules?.score ?? 0) > 0 ? 'ANOMALOUS' : 'NORMAL',
      explanation: activeBreakdown.deterministic_rules?.explanation || 'No rule matches triggered',
      isAnomalous: (activeBreakdown.deterministic_rules?.score ?? 0) > 0,
    },
    {
      name: 'Cross-Entity Correlation',
      icon: Share2,
      score: activeBreakdown.cross_entity_correlation?.score ?? 0,
      max: activeBreakdown.cross_entity_correlation?.maximum ?? 10,
      evidence: activeBreakdown.cross_entity_correlation?.evidence_strength || 'NONE',
      explanation: activeBreakdown.cross_entity_correlation?.explanation || 'Zero cross-entity correlation',
      isAnomalous: (activeBreakdown.cross_entity_correlation?.score ?? 0) > 0,
    },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
      {detectors.map((d, idx) => {
        const Icon = d.icon;
        const isAnom = d.isAnomalous;

        return (
          <div
            key={idx}
            className={`rounded-xl p-3.5 border transition-all ${
              isAnom
                ? 'bg-[#121927] border-cyan-800/60 shadow-[0_0_12px_rgba(0,210,255,0.08)]'
                : 'bg-[#0d131d] border-[#1c2638]'
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center space-x-2">
                <Icon
                  className={`w-4 h-4 ${isAnom ? 'text-cyan-400' : 'text-slate-500'}`}
                />
                <span className="text-xs font-semibold text-slate-200 truncate">
                  {d.name}
                </span>
              </div>
              <span
                className={`text-[10px] font-mono font-medium px-1.5 py-0.5 rounded border ${
                  isAnom
                    ? 'bg-rose-950/70 text-rose-400 border-rose-800/80'
                    : 'bg-emerald-950/70 text-emerald-400 border-emerald-800/80'
                }`}
              >
                {d.evidence}
              </span>
            </div>

            <div className="flex items-baseline space-x-1 mb-1.5">
              <span
                className={`text-xl font-mono font-bold ${
                  isAnom ? 'text-cyan-300' : 'text-slate-400'
                }`}
              >
                {d.score.toFixed(1)}
              </span>
              <span className="text-[11px] font-mono text-slate-500">
                / {d.max} pts
              </span>
            </div>

            <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed">
              {d.explanation}
            </p>
          </div>
        );
      })}
    </div>
  );
};
