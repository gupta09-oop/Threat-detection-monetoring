import { useEffect, useState } from 'react';
import { BarChart2 } from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart as RechartsPie,
  Pie,
  Cell,
} from 'recharts';
import { api } from '../api/client';
import type { AlertResult, RiskScoreResult } from '../types';

export const DetectionAnalyticsPage: React.FC = () => {
  const [alerts, setAlerts] = useState<AlertResult[]>([]);
  const [riskScores, setRiskScores] = useState<RiskScoreResult[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        setIsLoading(true);
        const [alertsData, riskData] = await Promise.all([
          api.getAlerts({ limit: 100 }),
          api.getRiskResults({ limit: 50 }),
        ]);
        setAlerts(alertsData);
        setRiskScores(riskData);
      } catch (err) {
        console.error('Failed to load analytics data:', err);
      } finally {
        setIsLoading(false);
      }
    };
    fetchData();
  }, []);

  if (isLoading) {
    return (
      <div className="p-8 text-center font-mono text-sm text-slate-500 animate-pulse">
        Loading multi-detector analytics from backend...
      </div>
    );
  }

  // 1. Alert Severity Distribution
  const severityCounts: Record<string, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
  };
  alerts.forEach((a: AlertResult) => {
    if (severityCounts[a.severity] !== undefined) {
      severityCounts[a.severity]++;
    }
  });

  const severityChartData = [
    { name: 'CRITICAL', value: severityCounts.CRITICAL, color: '#ef4444' },
    { name: 'HIGH', value: severityCounts.HIGH, color: '#f97316' },
    { name: 'MEDIUM', value: severityCounts.MEDIUM, color: '#f59e0b' },
    { name: 'LOW', value: severityCounts.LOW, color: '#10b981' },
  ].filter((d) => d.value > 0);

  // 2. Detector Contribution Breakdown
  const detectorStats = [
    { name: 'Statistical', score: 0, max: 25 },
    { name: 'Isolation Forest', score: 0, max: 25 },
    { name: 'Clustering', score: 0, max: 20 },
    { name: 'Rules', score: 0, max: 20 },
    { name: 'Correlation', score: 0, max: 10 },
  ];

  if (riskScores.length > 0) {
    const latest = riskScores[0];
    detectorStats[0].score = latest.statistical_contribution;
    detectorStats[1].score = latest.isolation_forest_contribution;
    detectorStats[2].score = latest.clustering_contribution;
    detectorStats[3].score = latest.rules_contribution;
    detectorStats[4].score = latest.correlation_contribution;
  }

  return (
    <div className="space-y-6 max-w-[1600px] mx-auto">
      <div>
        <h2 className="text-xl font-bold text-white tracking-tight flex items-center space-x-2">
          <BarChart2 className="w-5 h-5 text-cyan-400" />
          <span>Detection Analytics</span>
        </h2>
        <p className="text-xs text-slate-400">
          Multi-detector contribution breakdown, evidence distribution, and severity analytics
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Detector Contribution Bar Chart */}
        <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-5 shadow-lg">
          <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300 mb-4">
            Component Contribution to Threat Risk Score (Latest Evaluated)
          </h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={detectorStats}>
                <XAxis dataKey="name" stroke="#566882" fontSize={11} fontFamily="monospace" />
                <YAxis stroke="#566882" fontSize={11} fontFamily="monospace" domain={[0, 25]} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#090e17', borderColor: '#1c2638', fontSize: '11px' }}
                  cursor={{ fill: '#141d2c' }}
                />
                <Bar dataKey="score" fill="#00d2ff" radius={[4, 4, 0, 0]} name="Score Contribution" />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <p className="text-[11px] text-slate-500 font-mono mt-2 text-center">
            Max Limits: Statistical (25), IF (25), Clustering (20), Rules (20), Correlation (10)
          </p>
        </div>

        {/* Severity Distribution Pie Chart */}
        <div className="bg-[#0d131d] border border-[#1c2638] rounded-xl p-5 shadow-lg flex flex-col justify-between">
          <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300 mb-2">
            Evaluated Alerts by Severity
          </h3>
          {severityChartData.length === 0 ? (
            <div className="flex-1 flex items-center justify-center font-mono text-xs text-slate-500">
              Not enough telemetry for this analysis.
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center">
              <ResponsiveContainer width="100%" height="100%">
                <RechartsPie>
                  <Pie
                    data={severityChartData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={80}
                    paddingAngle={4}
                  >
                    {severityChartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#090e17', borderColor: '#1c2638', fontSize: '11px' }}
                  />
                </RechartsPie>
              </ResponsiveContainer>
            </div>
          )}

          <div className="flex items-center justify-center space-x-4 text-xs font-mono">
            {severityChartData.map((item) => (
              <span key={item.name} className="flex items-center space-x-1.5">
                <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.color }} />
                <span className="text-slate-300">{item.name}: {item.value}</span>
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
