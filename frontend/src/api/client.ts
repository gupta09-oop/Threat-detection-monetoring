/**
 * Centralized API Client for Sh4d0w_St4lk3r SOC Frontend.
 * Dispatches real HTTP requests to the backend with error handling.
 */

import type {
  AlertResult,
  AlertStatus,
  CanonicalEvent,
  CaseResult,
  CaseStatus,
  HealthResponse,
  RiskScoreResult,
  TimelineItem,
  SimulationStartRequest,
  SimulationStatusResponse,
  SimulationStopResponse,
  ThreatReportResponse,
} from '../types';

const API_BASE = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8099';

async function fetchJson<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const url = endpoint.startsWith('http') ? endpoint : `${API_BASE}${endpoint}`;
  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options?.headers || {}),
    },
  });

  if (!response.ok) {
    let errorDetail = response.statusText;
    try {
      const errJson = await response.json();
      errorDetail = errJson.detail || JSON.stringify(errJson);
    } catch {
      // ignore
    }
    throw new Error(`API error (${response.status}): ${errorDetail}`);
  }

  return response.json();
}

export const api = {
  // Health
  getHealth: (): Promise<HealthResponse> => fetchJson<HealthResponse>('/health'),

  // Events / Telemetry
  getEvents: (params?: { limit?: number; skip?: number; source_type?: string; user_id?: string }): Promise<CanonicalEvent[]> => {
    const query = new URLSearchParams();
    if (params?.limit) query.set('limit', String(params.limit));
    if (params?.skip) query.set('skip', String(params.skip));
    if (params?.source_type) query.set('source_type', params.source_type);
    if (params?.user_id) query.set('user_id', params.user_id);
    const qs = query.toString();
    return fetchJson<CanonicalEvent[]>(`/api/events${qs ? `?${qs}` : ''}`);
  },

  // Alerts
  getAlerts: (params?: { limit?: number; skip?: number; entity_id?: string; severity?: string; status?: string; case_id?: string }): Promise<AlertResult[]> => {
    const query = new URLSearchParams();
    if (params?.limit) query.set('limit', String(params.limit));
    if (params?.skip) query.set('skip', String(params.skip));
    if (params?.entity_id) query.set('entity_id', params.entity_id);
    if (params?.severity) query.set('severity', params.severity);
    if (params?.status) query.set('status', params.status);
    if (params?.case_id) query.set('case_id', params.case_id);
    const qs = query.toString();
    return fetchJson<AlertResult[]>(`/api/alerts${qs ? `?${qs}` : ''}`);
  },

  getAlertById: (alertId: string): Promise<AlertResult> => fetchJson<AlertResult>(`/api/alerts/${alertId}`),

  updateAlertStatus: (alertId: string, status: AlertStatus, notes?: string): Promise<AlertResult> =>
    fetchJson<AlertResult>(`/api/alerts/${alertId}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status, notes }),
    }),

  // Cases
  getCases: (params?: { limit?: number; skip?: number; entity_id?: string; severity?: string; status?: string }): Promise<CaseResult[]> => {
    const query = new URLSearchParams();
    if (params?.limit) query.set('limit', String(params.limit));
    if (params?.skip) query.set('skip', String(params.skip));
    if (params?.entity_id) query.set('entity_id', params.entity_id);
    if (params?.severity) query.set('severity', params.severity);
    if (params?.status) query.set('status', params.status);
    const qs = query.toString();
    return fetchJson<CaseResult[]>(`/api/cases${qs ? `?${qs}` : ''}`);
  },

  getCaseById: (caseId: string): Promise<CaseResult> => fetchJson<CaseResult>(`/api/cases/${caseId}`),

  updateCaseStatus: (caseId: string, status: CaseStatus, resolutionNotes?: string, assignedTo?: string): Promise<CaseResult> =>
    fetchJson<CaseResult>(`/api/cases/${caseId}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status, resolution_notes: resolutionNotes, assigned_to: assignedTo }),
    }),

  getCaseTimeline: (caseId: string): Promise<TimelineItem[]> => fetchJson<TimelineItem[]>(`/api/cases/${caseId}/timeline`),

  getCaseAlerts: (caseId: string): Promise<AlertResult[]> => fetchJson<AlertResult[]>(`/api/cases/${caseId}/alerts`),

  // Risk Scores
  getRiskResults: (params?: { limit?: number; entity_id?: string; severity?: string }): Promise<RiskScoreResult[]> => {
    const query = new URLSearchParams();
    if (params?.limit) query.set('limit', String(params.limit));
    if (params?.entity_id) query.set('entity_id', params.entity_id);
    if (params?.severity) query.set('severity', params.severity);
    const qs = query.toString();
    return fetchJson<RiskScoreResult[]>(`/api/risk/results${qs ? `?${qs}` : ''}`);
  },

  getEntityRisk: (entityId: string): Promise<RiskScoreResult> => fetchJson<RiskScoreResult>(`/api/risk/${entityId}`),

  getEntityRiskHistory: (entityId: string, limit: number = 20): Promise<RiskScoreResult[]> =>
    fetchJson<RiskScoreResult[]>(`/api/risk/${entityId}/history?limit=${limit}`),

  assignAlert: (alertId: string, analyst: string): Promise<AlertResult> =>
    fetchJson<AlertResult>(`/api/alerts/${alertId}/assign`, {
      method: 'PATCH',
      body: JSON.stringify({ analyst }),
    }),

  addAlertNote: (alertId: string, analyst: string, text: string): Promise<AlertResult> =>
    fetchJson<AlertResult>(`/api/alerts/${alertId}/notes`, {
      method: 'POST',
      body: JSON.stringify({ analyst, text }),
    }),

  resolveAlert: (alertId: string, resolution: string, analyst: string, notes?: string): Promise<AlertResult> =>
    fetchJson<AlertResult>(`/api/alerts/${alertId}/resolve`, {
      method: 'PATCH',
      body: JSON.stringify({ resolution, analyst, notes }),
    }),

  assignCase: (caseId: string, analyst: string): Promise<CaseResult> =>
    fetchJson<CaseResult>(`/api/cases/${caseId}/assign`, {
      method: 'PATCH',
      body: JSON.stringify({ analyst }),
    }),

  addCaseNote: (caseId: string, analyst: string, text: string): Promise<CaseResult> =>
    fetchJson<CaseResult>(`/api/cases/${caseId}/notes`, {
      method: 'POST',
      body: JSON.stringify({ analyst, text }),
    }),

  resolveCase: (caseId: string, resolution: string, analyst: string, notes?: string): Promise<CaseResult> =>
    fetchJson<CaseResult>(`/api/cases/${caseId}/resolve`, {
      method: 'PATCH',
      body: JSON.stringify({ resolution, analyst, notes }),
    }),

  // Live Attack Simulation
  startSimulation: (req: SimulationStartRequest): Promise<SimulationStatusResponse> =>
    fetchJson<SimulationStatusResponse>('/api/simulation/start', {
      method: 'POST',
      body: JSON.stringify(req),
    }),

  getSimulationStatus: (): Promise<SimulationStatusResponse> =>
    fetchJson<SimulationStatusResponse>('/api/simulation/status'),

  stopSimulation: (): Promise<SimulationStopResponse> =>
    fetchJson<SimulationStopResponse>('/api/simulation/stop', {
      method: 'POST',
    }),

  bootstrapSimulation: (): Promise<any> =>
    fetchJson<any>('/api/simulation/bootstrap', {
      method: 'POST',
    }),

  resetDemoState: (): Promise<any> =>
    fetchJson<any>('/api/simulation/reset', {
      method: 'POST',
    }),

  // Threat Intelligence Reports
  getReportableIncidents: (): Promise<{ alerts: any[]; cases: any[] }> =>
    fetchJson<{ alerts: any[]; cases: any[] }>('/api/reports/incidents'),

  generateReport: (incidentType: string, incidentId: string): Promise<ThreatReportResponse> =>
    fetchJson<ThreatReportResponse>('/api/reports/export', {
      method: 'POST',
      body: JSON.stringify({ incident_type: incidentType, incident_id: incidentId }),
    }),
};

