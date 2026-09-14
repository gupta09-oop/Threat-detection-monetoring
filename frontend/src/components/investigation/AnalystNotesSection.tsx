import React, { useState } from 'react';
import { MessageSquare, Send, User } from 'lucide-react';
import { ANALYST_ROSTER, type AnalystNote } from '../../types';

interface AnalystNotesSectionProps {
  notes: AnalystNote[];
  currentAnalyst?: string | null;
  onSaveNote: (analyst: string, text: string) => Promise<void>;
  isLoading?: boolean;
}

export const AnalystNotesSection: React.FC<AnalystNotesSectionProps> = ({
  notes = [],
  currentAnalyst,
  onSaveNote,
  isLoading = false,
}) => {
  const [selectedAnalyst, setSelectedAnalyst] = useState<string>(
    currentAnalyst || ANALYST_ROSTER[0]
  );
  const [noteText, setNoteText] = useState<string>('');
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!noteText.trim()) return;

    try {
      setIsSubmitting(true);
      await onSaveNote(selectedAnalyst, noteText.trim());
      setNoteText('');
    } catch (err) {
      console.error('Failed to save analyst note:', err);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-5 space-y-4">
      <div className="flex items-center space-x-2 border-b border-[#1c2638] pb-3 text-cyan-400">
        <MessageSquare className="w-4 h-4" />
        <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-200">
          Analyst Investigation Notes
        </h3>
        <span className="text-[10px] font-mono text-slate-500 ml-auto">
          {notes.length} saved {notes.length === 1 ? 'note' : 'notes'}
        </span>
      </div>

      {/* Saved notes list */}
      <div className="space-y-2.5 max-h-64 overflow-y-auto pr-1">
        {notes.length === 0 ? (
          <p className="text-xs text-slate-500 font-mono italic py-2">
            No analyst notes recorded yet. Add initial observations below.
          </p>
        ) : (
          notes.map((n, idx) => (
            <div
              key={idx}
              className="p-3 rounded-lg bg-[#090e17] border border-[#182233] space-y-1 text-xs"
            >
              <div className="flex items-center justify-between text-[11px] font-mono">
                <span className="text-cyan-400 font-semibold flex items-center space-x-1">
                  <User className="w-3 h-3 text-cyan-500 inline" />
                  <span>{n.analyst}</span>
                </span>
                <span className="text-slate-500">
                  {n.timestamp ? new Date(n.timestamp).toLocaleString() : 'Recent'}
                </span>
              </div>
              <p className="text-slate-300 font-sans leading-relaxed pt-1 whitespace-pre-wrap">
                {n.text}
              </p>
            </div>
          ))
        )}
      </div>

      {/* New Note Form */}
      <form onSubmit={handleSubmit} className="pt-2 border-t border-[#182233] space-y-3">
        <div className="flex items-center justify-between gap-2">
          <label className="text-[11px] font-mono text-slate-400">Recording Analyst:</label>
          <select
            value={selectedAnalyst}
            onChange={(e) => setSelectedAnalyst(e.target.value)}
            className="bg-[#090e17] border border-[#1c2638] rounded-lg px-2.5 py-1 text-xs font-mono text-slate-200 focus:border-cyan-500 outline-none"
          >
            {ANALYST_ROSTER.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        </div>

        <textarea
          rows={3}
          value={noteText}
          onChange={(e) => setNoteText(e.target.value)}
          placeholder="Record forensic findings, containment actions, or triage observations..."
          className="w-full bg-[#090e17] border border-[#1c2638] rounded-lg p-3 text-xs text-slate-200 placeholder-slate-500 font-sans focus:border-cyan-500 outline-none resize-none leading-relaxed"
        />

        <div className="flex justify-end">
          <button
            type="submit"
            disabled={!noteText.trim() || isSubmitting || isLoading}
            className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg bg-cyan-950/60 hover:bg-cyan-900/60 border border-cyan-800/80 text-xs font-mono font-semibold text-cyan-300 hover:text-white transition-all cursor-pointer disabled:opacity-50"
          >
            <Send className="w-3.5 h-3.5" />
            <span>{isSubmitting ? 'Saving Note...' : 'Save Note'}</span>
          </button>
        </div>
      </form>
    </div>
  );
};
