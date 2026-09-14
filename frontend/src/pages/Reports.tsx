import React, { useEffect, useState } from 'react';
import {
  FileText,
  Download,
  Printer,
  Clock,
  RefreshCw,
} from 'lucide-react';
import { api } from '../api/client';
import type { ThreatReportResponse } from '../types';
import { SeverityBadge } from '../components/common/Badges';

export const ReportsPage: React.FC = () => {
  const [incidents, setIncidents] = useState<{ alerts: any[]; cases: any[] }>({
    alerts: [],
    cases: [],
  });
  const [selectedType, setSelectedType] = useState<'alert' | 'case'>('alert');
  const [selectedId, setSelectedId] = useState<string>('');
  const [report, setReport] = useState<ThreatReportResponse | null>(null);
  const [isLoadingList, setIsLoadingList] = useState<boolean>(true);
  const [isGenerating, setIsGenerating] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const loadIncidents = async () => {
    try {
      setIsLoadingList(true);
      setError(null);
      const data = await api.getReportableIncidents();
      setIncidents(data);

      // Auto-select first available incident if none selected
      if (!selectedId) {
        if (data.alerts && data.alerts.length > 0) {
          setSelectedType('alert');
          setSelectedId(data.alerts[0].id);
          generateReport('alert', data.alerts[0].id);
        } else if (data.cases && data.cases.length > 0) {
          setSelectedType('case');
          setSelectedId(data.cases[0].id);
          generateReport('case', data.cases[0].id);
        }
      }
    } catch (err: any) {
      console.error('Failed to fetch reportable incidents:', err);
      setError('Failed to fetch incidents list');
    } finally {
      setIsLoadingList(false);
    }
  };

  const generateReport = async (type: string, id: string) => {
    if (!id) return;
    try {
      setIsGenerating(true);
      setError(null);
      const rep = await api.generateReport(type, id);
      setReport(rep);
    } catch (err: any) {
      console.error('Failed to generate threat report:', err);
      setError(err.message || 'Report generation failed');
    } finally {
      setIsGenerating(false);
    }
  };

  useEffect(() => {
    loadIncidents();
  }, []);

  const handleSelectIncident = (type: 'alert' | 'case', id: string) => {
    setSelectedType(type);
    setSelectedId(id);
    generateReport(type, id);
  };

  const handleDownloadJSON = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `SH4D0W_REPORT_${report.report_header.report_id}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handlePrintPDF = () => {
    window.print();
  };

  const totalIncidents = incidents.alerts.length + incidents.cases.length;

  return (
    <div className="space-y-6 max-w-[1500px] mx-auto pb-12">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-[#1c2638] pb-4 gap-3">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight flex items-center space-x-2">
            <FileText className="w-5 h-5 text-cyan-400" />
            <span>Threat Intelligence Reports</span>
          </h2>
          <p className="text-xs text-slate-400">
            Automated forensic incident summaries, explainable risk audits, and intelligence exports
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <button
            type="button"
            onClick={loadIncidents}
            disabled={isLoadingList}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-[#0d131d] border border-[#1c2638] text-xs font-mono text-slate-300 hover:text-cyan-400 transition-all cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoadingList ? 'animate-spin text-cyan-400' : ''}`} />
            <span>Refresh</span>
          </button>

          {report && (
            <>
              <button
                type="button"
                onClick={handleDownloadJSON}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-[#121a28] hover:bg-cyan-950/80 hover:text-cyan-300 border border-cyan-800/60 text-xs font-mono font-semibold transition-all cursor-pointer text-slate-200"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export JSON</span>
              </button>

              <button
                type="button"
                onClick={handlePrintPDF}
                className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 text-black font-semibold text-xs font-mono hover:from-cyan-400 hover:to-blue-500 transition-all shadow-[0_0_12px_rgba(0,210,255,0.3)] cursor-pointer"
              >
                <Printer className="w-3.5 h-3.5" />
                <span>Print / Save PDF</span>
              </button>
            </>
          )}
        </div>
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-rose-950/30 border border-rose-800/40 text-xs text-rose-300">
          {error}
        </div>
      )}

      {totalIncidents === 0 && !isLoadingList ? (
        <div className="p-12 text-center rounded-2xl bg-[#0d131d] border border-[#1c2638] max-w-xl mx-auto space-y-3 mt-8">
          <FileText className="w-10 h-10 text-slate-600 mx-auto" />
          <h3 className="text-sm font-semibold text-slate-200 font-mono">
            No Security Incidents in Current Session
          </h3>
          <p className="text-xs text-slate-400 font-sans leading-relaxed">
            There are currently 0 active or historical alerts to compile. Launch an attack simulation from the Command Center to evaluate behavioral detections and generate threat intelligence reports.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Incident Selector Sidebar */}
          <div className="lg:col-span-1 space-y-4">
            <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-4 space-y-3">
              <div className="flex items-center justify-between border-b border-[#1c2638] pb-2">
                <span className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300">
                  Select Incident
                </span>
                <span className="text-[10px] font-mono text-slate-500">
                  {totalIncidents} available
                </span>
              </div>

              {/* Type Toggle */}
              <div className="grid grid-cols-2 gap-1 p-1 bg-[#090e17] border border-[#182233] rounded-lg text-xs font-mono">
                <button
                  type="button"
                  onClick={() => {
                    setSelectedType('alert');
                    if (incidents.alerts.length > 0) {
                      handleSelectIncident('alert', incidents.alerts[0].id);
                    }
                  }}
                  className={`py-1.5 rounded text-center transition-all cursor-pointer ${
                    selectedType === 'alert'
                      ? 'bg-cyan-950/80 text-cyan-300 font-bold border border-cyan-800/60'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Alerts ({incidents.alerts.length})
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setSelectedType('case');
                    if (incidents.cases.length > 0) {
                      handleSelectIncident('case', incidents.cases[0].id);
                    }
                  }}
                  className={`py-1.5 rounded text-center transition-all cursor-pointer ${
                    selectedType === 'case'
                      ? 'bg-cyan-950/80 text-cyan-300 font-bold border border-cyan-800/60'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Cases ({incidents.cases.length})
                </button>
              </div>

              {/* Incidents List */}
              <div className="space-y-2 max-h-[520px] overflow-y-auto pr-1">
                {selectedType === 'alert' &&
                  incidents.alerts.map((alt) => (
                    <div
                      key={alt.id}
                      onClick={() => handleSelectIncident('alert', alt.id)}
                      className={`p-3 rounded-lg border text-xs transition-all cursor-pointer ${
                        selectedId === alt.id
                          ? 'bg-cyan-950/40 border-cyan-500/80 shadow-[0_0_12px_rgba(0,210,255,0.15)]'
                          : 'bg-[#090e17] border-[#182233] hover:border-slate-600'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <SeverityBadge severity={alt.severity} size="sm" />
                        <span className="font-mono text-cyan-400 font-bold text-[11px]">
                          {alt.risk_score?.toFixed(1)}
                        </span>
                      </div>
                      <h4 className="text-slate-200 font-semibold line-clamp-1 text-xs">
                        {alt.title}
                      </h4>
                      <div className="flex items-center justify-between text-[10px] font-mono text-slate-500 mt-1">
                        <span className="truncate max-w-[120px]">{alt.entity_id}</span>
                        <span>{alt.status}</span>
                      </div>
                    </div>
                  ))}

                {selectedType === 'case' &&
                  incidents.cases.map((cs) => (
                    <div
                      key={cs.id}
                      onClick={() => handleSelectIncident('case', cs.id)}
                      className={`p-3 rounded-lg border text-xs transition-all cursor-pointer ${
                        selectedId === cs.id
                          ? 'bg-cyan-950/40 border-cyan-500/80 shadow-[0_0_12px_rgba(0,210,255,0.15)]'
                          : 'bg-[#090e17] border-[#182233] hover:border-slate-600'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <SeverityBadge severity={cs.severity} size="sm" />
                        <span className="font-mono text-cyan-400 font-bold text-[11px]">
                          {cs.total_risk_score?.toFixed(1)}
                        </span>
                      </div>
                      <h4 className="text-slate-200 font-semibold line-clamp-1 text-xs">
                        {cs.title}
                      </h4>
                      <div className="flex items-center justify-between text-[10px] font-mono text-slate-500 mt-1">
                        <span className="truncate max-w-[120px]">{cs.entity_id}</span>
                        <span>{cs.status}</span>
                      </div>
                    </div>
                  ))}
              </div>
            </div>
          </div>

          {/* Full Threat Report Preview Container */}
          <div className="lg:col-span-3">
            {isGenerating ? (
              <div className="p-16 text-center font-mono text-sm text-slate-500 rounded-xl bg-[#0d131d] border border-[#1c2638] animate-pulse">
                Compiling forensic telemetry and explainable detector breakdowns...
              </div>
            ) : report ? (
              <div
                id="threat-report-document"
                className="bg-[#0b121e] border border-[#1c2638] rounded-2xl p-6 sm:p-8 space-y-6 shadow-2xl print:bg-white print:text-black print:p-0 print:border-none print:shadow-none"
              >
                {/* 1. REPORT HEADER */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-[#1c2638] pb-5 gap-3">
                  <div className="flex items-center space-x-3">
                    <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center font-mono font-bold text-black text-sm shadow-[0_0_15px_rgba(0,210,255,0.3)]">
                      S4
                    </div>
                    <div>
                      <div className="font-mono text-xs text-cyan-400 uppercase tracking-widest font-bold">
                        {report.report_header.platform}
                      </div>
                      <h1 className="text-base sm:text-lg font-bold text-white tracking-tight">
                        {report.report_header.title}
                      </h1>
                    </div>
                  </div>

                  <div className="text-left sm:text-right font-mono text-xs space-y-0.5">
                    <div className="text-cyan-400 font-bold">{report.report_header.report_id}</div>
                    <div className="text-slate-500">
                      Generated: {new Date(report.report_header.generated_at).toLocaleString()}
                    </div>
                  </div>
                </div>

                {/* 2. INCIDENT INFORMATION BANNER */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-[#070b12] border border-[#1c2638] rounded-xl p-4 text-xs font-mono">
                  <div>
                    <span className="text-[10px] text-slate-500 uppercase block">Incident ID</span>
                    <span className="text-cyan-300 font-bold truncate block">{report.incident_info.incident_id}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-500 uppercase block">Attack Pattern</span>
                    <span className="text-amber-300 font-bold block truncate">{report.incident_info.attack_classification}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-500 uppercase block">Severity & Status</span>
                    <div className="flex items-center space-x-1.5 mt-0.5">
                      <SeverityBadge severity={report.incident_info.severity as any} size="sm" />
                      <span className="text-slate-300 font-semibold">{report.incident_info.status}</span>
                    </div>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-500 uppercase block">Assigned Analyst</span>
                    <span className="text-white font-bold block">{report.incident_info.assigned_analyst || 'Unassigned'}</span>
                  </div>
                </div>

                {/* 3. RISK SUMMARY & 4. RISK BREAKDOWN */}
                <div className="space-y-3">
                  <div className="flex items-center justify-between border-b border-[#1c2638] pb-2">
                    <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300">
                      Bounded Threat Risk Evaluation (0 - 100)
                    </h3>
                    <span className="text-xs font-mono font-bold text-rose-400">
                      Score: {report.risk_summary.risk_score.toFixed(1)} / {report.risk_summary.max_score} ({report.risk_summary.severity})
                    </span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-5 gap-2.5 text-xs font-mono">
                    <div className="p-3 rounded-xl bg-[#090e17] border border-[#182233] space-y-1">
                      <div className="flex justify-between text-slate-400">
                        <span>Statistical</span>
                        <span className="text-cyan-400 font-bold">
                          {report.risk_breakdown.statistical_baseline.score.toFixed(1)} / {report.risk_breakdown.statistical_baseline.maximum}
                        </span>
                      </div>
                      <p className="text-[10px] text-slate-400 font-sans line-clamp-2">
                        {report.risk_breakdown.statistical_baseline.explanation}
                      </p>
                    </div>

                    <div className="p-3 rounded-xl bg-[#090e17] border border-[#182233] space-y-1">
                      <div className="flex justify-between text-slate-400">
                        <span>Isolation Forest</span>
                        <span className="text-cyan-400 font-bold">
                          {report.risk_breakdown.isolation_forest.score.toFixed(1)} / {report.risk_breakdown.isolation_forest.maximum}
                        </span>
                      </div>
                      <p className="text-[10px] text-slate-400 font-sans line-clamp-2">
                        {report.risk_breakdown.isolation_forest.explanation}
                      </p>
                    </div>

                    <div className="p-3 rounded-xl bg-[#090e17] border border-[#182233] space-y-1">
                      <div className="flex justify-between text-slate-400">
                        <span>Clustering</span>
                        <span className="text-cyan-400 font-bold">
                          {report.risk_breakdown.behavioral_clustering.score.toFixed(1)} / {report.risk_breakdown.behavioral_clustering.maximum}
                        </span>
                      </div>
                      <p className="text-[10px] text-slate-400 font-sans line-clamp-2">
                        {report.risk_breakdown.behavioral_clustering.explanation}
                      </p>
                    </div>

                    <div className="p-3 rounded-xl bg-[#090e17] border border-[#182233] space-y-1">
                      <div className="flex justify-between text-slate-400">
                        <span>Deterministic</span>
                        <span className="text-cyan-400 font-bold">
                          {report.risk_breakdown.deterministic_rules.score.toFixed(1)} / {report.risk_breakdown.deterministic_rules.maximum}
                        </span>
                      </div>
                      <p className="text-[10px] text-slate-400 font-sans line-clamp-2">
                        {report.risk_breakdown.deterministic_rules.explanation}
                      </p>
                    </div>

                    <div className="p-3 rounded-xl bg-[#090e17] border border-[#182233] space-y-1">
                      <div className="flex justify-between text-slate-400">
                        <span>Correlation</span>
                        <span className="text-cyan-400 font-bold">
                          {report.risk_breakdown.cross_entity_correlation.score.toFixed(1)} / {report.risk_breakdown.cross_entity_correlation.maximum}
                        </span>
                      </div>
                      <p className="text-[10px] text-slate-400 font-sans line-clamp-2">
                        {report.risk_breakdown.cross_entity_correlation.explanation}
                      </p>
                    </div>
                  </div>
                </div>

                {/* 5. DETECTION EVIDENCE & RATIONALE */}
                <div className="p-4 rounded-xl bg-[#090e17] border border-[#182233] space-y-2">
                  <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-cyan-400">
                    Detection Evidence & Forensic Rationale
                  </h3>
                  <p className="text-xs text-slate-200 font-sans leading-relaxed">
                    {report.detection_evidence.rationale}
                  </p>
                  <div className="pt-2 flex flex-wrap gap-2 text-[11px] font-mono">
                    <span className="text-slate-400">Flagging Detectors:</span>
                    {report.detection_evidence.contributing_detectors.map((d, i) => (
                      <span key={i} className="px-2 py-0.5 rounded bg-cyan-950/50 border border-cyan-800/60 text-cyan-300">
                        {d}
                      </span>
                    ))}
                  </div>
                </div>

                {/* 6. AFFECTED ENTITIES */}
                <div className="p-4 rounded-xl bg-[#090e17] border border-[#182233] space-y-2 text-xs font-mono">
                  <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300">
                    Correlated Entity Scope
                  </h3>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-1 text-slate-300">
                    <div>
                      <span className="text-[10px] text-slate-500 block">Target Entity:</span>
                      <span className="text-white font-semibold">{report.affected_entities.target_entity_id} ({report.affected_entities.entity_type})</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-500 block">Source IPs:</span>
                      <span className="text-cyan-400">{report.affected_entities.source_ips.join(', ') || 'None'}</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-500 block">Target Accounts:</span>
                      <span className="text-slate-200">{report.affected_entities.accounts.join(', ') || 'None'}</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-500 block">Target Ports:</span>
                      <span className="text-emerald-400">{report.affected_entities.ports.join(', ') || 'None'}</span>
                    </div>
                  </div>
                </div>

                {/* 7. INCIDENT TIMELINE */}
                {report.incident_timeline && report.incident_timeline.length > 0 && (
                  <div className="space-y-3">
                    <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300 border-b border-[#1c2638] pb-2">
                      Incident Timeline & Audit Trail
                    </h3>
                    <div className="space-y-2 text-xs font-mono">
                      {report.incident_timeline.map((item, idx) => (
                        <div key={idx} className="flex items-start space-x-3 p-2.5 rounded-lg bg-[#090e17] border border-[#182233]">
                          <Clock className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                          <div className="space-y-0.5 flex-1">
                            <div className="flex items-center justify-between">
                              <span className="font-bold text-cyan-300">{item.evidence_type}</span>
                              <span className="text-[11px] text-slate-500">
                                {new Date(item.timestamp).toLocaleString()}
                              </span>
                            </div>
                            <p className="text-xs text-slate-300 font-sans">{item.explanation}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* 8. INVESTIGATION & NOTES */}
                {report.investigation.analyst_notes && report.investigation.analyst_notes.length > 0 && (
                  <div className="p-4 rounded-xl bg-[#090e17] border border-[#182233] space-y-2">
                    <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300">
                      Analyst Forensic Notes
                    </h3>
                    <div className="space-y-2">
                      {report.investigation.analyst_notes.map((n, i) => (
                        <div key={i} className="text-xs space-y-0.5 border-l-2 border-cyan-500 pl-3">
                          <div className="flex items-center space-x-2 text-[11px] font-mono text-slate-400">
                            <span className="text-cyan-400 font-semibold">{n.analyst}</span>
                            <span>•</span>
                            <span>{new Date(n.timestamp).toLocaleString()}</span>
                          </div>
                          <p className="text-slate-300 font-sans">{n.text}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* 9. RESOLUTION & 10. RECOMMENDATIONS */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
                  <div className="p-4 rounded-xl bg-[#090e17] border border-[#182233] space-y-2">
                    <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-emerald-400">
                      Incident Resolution
                    </h3>
                    <div className="text-xs font-mono space-y-1 text-slate-300">
                      <div>Outcome: <span className="text-white font-bold">{report.resolution.resolution || 'Pending Resolution'}</span></div>
                      <div>Closed By: <span className="text-white">{report.resolution.resolved_by || 'Active Investigation'}</span></div>
                      <div>Final Status: <span className="text-cyan-400">{report.resolution.final_status}</span></div>
                      {report.resolution.resolution_notes && (
                        <p className="text-xs font-sans text-slate-300 pt-1 border-t border-[#182233] mt-2">
                          "{report.resolution.resolution_notes}"
                        </p>
                      )}
                    </div>
                  </div>

                  <div className="p-4 rounded-xl bg-[#090e17] border border-[#182233] space-y-2">
                    <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-cyan-400">
                      Recommended Response Playbook
                    </h3>
                    <ul className="text-xs font-sans text-slate-300 space-y-1 list-none">
                      {report.recommendations.map((rec, i) => (
                        <li key={i} className="flex items-start space-x-1.5">
                          <span className="text-cyan-400 font-mono">✓</span>
                          <span>{rec}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>

                {/* Report Footer */}
                <div className="pt-4 border-t border-[#1c2638] text-center font-mono text-[11px] text-slate-500">
                  SH4D0W_ST4LK3R Threat Intelligence Platform • End of Incident Report {report.report_header.report_id}
                </div>
              </div>
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
};
