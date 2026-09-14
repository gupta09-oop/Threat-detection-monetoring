import React, { useState, useEffect } from 'react';
import { CheckSquare, Square, ShieldAlert, CheckCircle2 } from 'lucide-react';

interface InvestigationChecklistProps {
  id: string;
  scenarioOrTitle?: string;
  details?: Record<string, any>;
}

export const InvestigationChecklist: React.FC<InvestigationChecklistProps> = ({
  id,
  scenarioOrTitle = '',
  details = {},
}) => {
  const text = (scenarioOrTitle + ' ' + (details.scenario || '') + ' ' + (details.attack_type || '')).toLowerCase();

  let attackType = 'GENERIC';
  let steps: string[] = [];

  if (text.includes('brute') || text.includes('distributed')) {
    attackType = 'DISTRIBUTED BRUTE FORCE';
    steps = [
      'Validate the targeted accounts.',
      'Review source IP diversity.',
      'Confirm the distributed low-and-slow pattern.',
      'Review failed login activity.',
      'Check affected sessions and successful authentications.',
      'Apply appropriate authentication protections.',
      'Document the investigation.',
      'Resolve or escalate the incident.',
    ];
  } else if (text.includes('credential') || text.includes('stuffing')) {
    attackType = 'CREDENTIAL STUFFING';
    steps = [
      'Identify affected accounts.',
      'Review successful authentications.',
      'Inspect unseen devices.',
      'Check geographic anomalies.',
      'Review account/session activity.',
      'Apply appropriate account protection.',
      'Investigate potential credential reuse.',
      'Document and resolve/escalate.',
    ];
  } else if (text.includes('port') || text.includes('scan') || text.includes('recon')) {
    attackType = 'PORT SCAN / RECON';
    steps = [
      'Identify scanner IPs.',
      'Review destination systems.',
      'Inspect targeted ports.',
      'Review refused/timeout ratios.',
      'Identify exposed services.',
      'Check related network activity.',
      'Determine whether reconnaissance preceded another attack.',
      'Document and resolve/escalate.',
    ];
  } else {
    attackType = 'STANDARD FORENSIC INVESTIGATION';
    steps = [
      'Verify the anomalous entity activity.',
      'Correlate with historical baseline metrics.',
      'Inspect related network and authentication events.',
      'Review detector contributor breakdown.',
      'Document findings and triage severity.',
      'Mitigate risk and resolve/escalate.',
    ];
  }

  const storageKey = `sh4d0w_checklist_${id}`;

  const [completedIndices, setCompletedIndices] = useState<number[]>(() => {
    try {
      const saved = localStorage.getItem(storageKey);
      return saved ? JSON.parse(saved) : [];
    } catch {
      return [];
    }
  });

  useEffect(() => {
    try {
      localStorage.setItem(storageKey, JSON.stringify(completedIndices));
    } catch {
      // ignore
    }
  }, [completedIndices, storageKey]);

  const toggleStep = (index: number) => {
    setCompletedIndices((prev) =>
      prev.includes(index) ? prev.filter((i) => i !== index) : [...prev, index]
    );
  };

  const completedCount = completedIndices.filter((i) => i < steps.length).length;
  const totalCount = steps.length;
  const progressPct = Math.round((completedCount / totalCount) * 100);

  return (
    <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-5 space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-[#1c2638] pb-3 gap-2">
        <div>
          <div className="flex items-center space-x-2 text-cyan-400">
            <CheckCircle2 className="w-4 h-4" />
            <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-200">
              Recommended Response & Investigation Checklist
            </h3>
          </div>
          <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wide mt-0.5 block">
            Pattern: {attackType}
          </span>
        </div>

        <div className="flex items-center space-x-3 text-xs font-mono">
          <span className="text-slate-400">Investigation Progress:</span>
          <span className="px-2 py-0.5 rounded bg-[#162030] text-cyan-400 font-bold border border-[#25334a]">
            {completedCount} / {totalCount} completed
          </span>
        </div>
      </div>

      {/* Progress Bar */}
      <div className="space-y-1">
        <div className="w-full bg-[#121927] rounded-full h-1.5 overflow-hidden border border-[#1c2638]">
          <div
            className="bg-gradient-to-r from-cyan-500 to-blue-500 h-full transition-all duration-300 rounded-full"
            style={{ width: `${progressPct}%` }}
          />
        </div>
      </div>

      {/* Guidance Notice */}
      <div className="p-2.5 rounded-lg bg-amber-950/20 border border-amber-800/30 text-[11px] font-mono text-amber-300/90 flex items-center space-x-2">
        <ShieldAlert className="w-4 h-4 shrink-0 text-amber-400" />
        <span>
          <strong>Guidance only:</strong> Do NOT automatically modify firewall rules, accounts, credentials, network controls, or production systems.
        </span>
      </div>

      {/* Interactive Checklist Items */}
      <div className="space-y-2 pt-1">
        {steps.map((step, idx) => {
          const isDone = completedIndices.includes(idx);
          return (
            <div
              key={idx}
              onClick={() => toggleStep(idx)}
              className={`flex items-start space-x-3 p-2.5 rounded-lg border text-xs transition-all cursor-pointer select-none ${
                isDone
                  ? 'bg-cyan-950/20 border-cyan-800/40 text-slate-400 line-through'
                  : 'bg-[#090e17] border-[#182233] text-slate-200 hover:border-cyan-800/60'
              }`}
            >
              <button
                type="button"
                className="mt-0.5 text-cyan-400 shrink-0 focus:outline-none"
                aria-label={isDone ? 'Mark step incomplete' : 'Mark step complete'}
              >
                {isDone ? (
                  <CheckSquare className="w-4 h-4 text-cyan-400 fill-cyan-950" />
                ) : (
                  <Square className="w-4 h-4 text-slate-500 hover:text-cyan-400" />
                )}
              </button>
              <span className="font-sans leading-relaxed">
                <strong className="font-mono text-slate-500 mr-2">{idx + 1}.</strong>
                {step}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
};
