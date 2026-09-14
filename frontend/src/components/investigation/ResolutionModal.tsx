import React, { useState } from 'react';
import { CheckCircle, X } from 'lucide-react';
import { ANALYST_ROSTER, type ResolutionOutcome } from '../../types';

interface ResolutionModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: (resolution: ResolutionOutcome, analyst: string, notes: string) => Promise<void>;
  title: string;
  itemType: 'Alert' | 'Case';
  currentAnalyst?: string | null;
}

const RESOLUTION_OPTIONS: ResolutionOutcome[] = [
  'Confirmed Threat',
  'False Positive',
  'Benign Activity',
  'Other',
];

export const ResolutionModal: React.FC<ResolutionModalProps> = ({
  isOpen,
  onClose,
  onConfirm,
  title,
  itemType,
  currentAnalyst,
}) => {
  const [resolution, setResolution] = useState<ResolutionOutcome>('Confirmed Threat');
  const [analyst, setAnalyst] = useState<string>(currentAnalyst || ANALYST_ROSTER[0]);
  const [notes, setNotes] = useState<string>('');
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setIsSubmitting(true);
      await onConfirm(resolution, analyst, notes.trim());
      onClose();
    } catch (err) {
      console.error('Failed to resolve:', err);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4 animate-in fade-in duration-200"
    >
      <div className="w-full max-w-lg rounded-2xl bg-[#0b121e] border border-[#1c2638] shadow-[0_0_50px_rgba(0,0,0,0.8)] overflow-hidden">
        {/* Modal Header */}
        <div className="flex items-center justify-between p-5 border-b border-[#1c2638] bg-[#0d1524]">
          <div className="flex items-center space-x-2.5 text-cyan-400">
            <CheckCircle className="w-5 h-5 text-cyan-400" />
            <h3 className="text-sm font-semibold text-white tracking-wide">
              Resolve & Close {itemType}
            </h3>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded-lg transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Form */}
        <form onSubmit={handleSubmit} className="p-5 space-y-4">
          <div>
            <span className="text-xs text-slate-400 font-mono block">Target:</span>
            <p className="text-xs font-semibold text-slate-200 line-clamp-1 mt-0.5">
              {title}
            </p>
          </div>

          {/* Resolution Outcome */}
          <div className="space-y-1.5">
            <label className="text-xs font-mono text-slate-300 block">
              Resolution Outcome <span className="text-rose-400">*</span>
            </label>
            <div className="grid grid-cols-2 gap-2">
              {RESOLUTION_OPTIONS.map((opt) => (
                <button
                  type="button"
                  key={opt}
                  onClick={() => setResolution(opt)}
                  className={`p-2.5 rounded-lg border text-xs font-mono text-left transition-all cursor-pointer ${
                    resolution === opt
                      ? 'bg-cyan-950/60 border-cyan-500 text-cyan-300 shadow-[0_0_12px_rgba(0,210,255,0.2)]'
                      : 'bg-[#090e17] border-[#1c2638] text-slate-400 hover:border-slate-600'
                  }`}
                >
                  <span className="font-bold">{opt}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Analyst Selection */}
          <div className="space-y-1.5">
            <label className="text-xs font-mono text-slate-300 block">
              Resolving Analyst <span className="text-rose-400">*</span>
            </label>
            <select
              value={analyst}
              onChange={(e) => setAnalyst(e.target.value)}
              className="w-full bg-[#090e17] border border-[#1c2638] rounded-lg p-2.5 text-xs font-mono text-slate-200 focus:border-cyan-500 outline-none"
            >
              {ANALYST_ROSTER.map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
          </div>

          {/* Resolution Notes */}
          <div className="space-y-1.5">
            <label className="text-xs font-mono text-slate-300 block">
              Final Resolution Notes (Optional)
            </label>
            <textarea
              rows={3}
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder="Detail the containment actions, root cause validation, or false positive reason..."
              className="w-full bg-[#090e17] border border-[#1c2638] rounded-lg p-3 text-xs text-slate-200 placeholder-slate-500 font-sans focus:border-cyan-500 outline-none resize-none leading-relaxed"
            />
          </div>

          {/* Action Buttons */}
          <div className="flex items-center justify-end space-x-3 pt-3 border-t border-[#1c2638]">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-lg bg-[#090e17] border border-[#1c2638] text-xs font-mono text-slate-400 hover:text-white transition-all cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 text-black font-semibold text-xs font-mono hover:from-cyan-400 hover:to-blue-500 transition-all shadow-[0_0_15px_rgba(0,210,255,0.3)] cursor-pointer disabled:opacity-50"
            >
              {isSubmitting ? 'Resolving...' : `Confirm & Close ${itemType}`}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
