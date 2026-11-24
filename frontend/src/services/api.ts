import {
  AnalyzeProjectResponse,
  AuditConfig,
  SurfaceResponse,
  AuditActivity,
  Finding,
  ReportSummary,
  ReportDossier,
  GlobalStats
} from '../types/audit';

const API_BASE = '';
const USER_ID_KEY = 'stressx_user_id';

export function getOrCreateUserId(): string {
  let uid = localStorage.getItem(USER_ID_KEY);
  if (!uid) {
    uid = 'usr_' + Math.random().toString(36).substring(2, 10) + Date.now().toString(36);
    localStorage.setItem(USER_ID_KEY, uid);
  }
  return uid;
}

export function setCustomUserId(newId: string): void {
  if (newId && newId.trim()) {
    localStorage.setItem(USER_ID_KEY, newId.trim());
  }
}

async function authFetch(url: string, init: RequestInit = {}): Promise<Response> {
  const uid = getOrCreateUserId();
  const headers = new Headers(init.headers || {});
  if (!headers.has('X-User-ID')) {
    headers.set('X-User-ID', uid);
  }
  return fetch(url, { ...init, headers });
}

export async function fetchGlobalStats(): Promise<GlobalStats> {
  const res = await authFetch(`${API_BASE}/api/stats`);
  if (!res.ok) throw new Error('Failed to load global statistics');
  return res.json();
}

export async function fetchReportsList(): Promise<ReportSummary[]> {
  const res = await authFetch(`${API_BASE}/api/reports`);
  if (!res.ok) throw new Error('Failed to load reports');
  return res.json();
}

export async function fetchReportDetails(auditId: string): Promise<ReportDossier> {
  const res = await authFetch(`${API_BASE}/api/reports/${auditId}`);
  if (!res.ok) throw new Error(`Failed to load report dossier for ${auditId}`);
  return res.json();
}

export async function analyzeProject(projectPath: string): Promise<AnalyzeProjectResponse> {
  const res = await authFetch(`${API_BASE}/api/projects/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ project_path: projectPath })
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || 'Target analysis failed');
  }
  return res.json();
}

export async function createAudit(
  projectPath?: string,
  selectedSteps?: number,
  name?: string,
  auditName?: string,
  targetUrl?: string
): Promise<AuditConfig> {
  const res = await authFetch(`${API_BASE}/api/audits`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      project_path: projectPath,
      target_url: targetUrl,
      selected_steps: selectedSteps,
      name: name,
      audit_name: auditName || name
    })
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || 'Audit configuration failed');
  }
  return res.json();
}

export async function startAudit(auditId: string): Promise<AuditConfig> {
  const res = await authFetch(`${API_BASE}/api/audits/${auditId}/start`, {
    method: 'POST'
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || 'Failed to start audit');
  }
  return res.json();
}

export async function stopAudit(auditId: string): Promise<{ status: string; audit_id: string; message: string }> {
  const res = await authFetch(`${API_BASE}/api/audits/${auditId}/stop`, {
    method: 'POST'
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || 'Failed to stop audit');
  }
  return res.json();
}

export async function fetchAuditConfig(auditId: string): Promise<AuditConfig> {
  const res = await authFetch(`${API_BASE}/api/audits/${auditId}`);
  if (!res.ok) throw new Error('Audit not found');
  return res.json();
}

export async function fetchAuditSurface(auditId: string): Promise<SurfaceResponse> {
  const res = await authFetch(`${API_BASE}/api/audits/${auditId}/surface`);
  if (!res.ok) throw new Error('Failed to load attack surface');
  return res.json();
}

export async function fetchAuditActivity(auditId: string): Promise<AuditActivity> {
  const res = await authFetch(`${API_BASE}/api/audits/${auditId}/activity`);
  if (!res.ok) throw new Error('Failed to load audit activity');
  return res.json();
}

export async function fetchAuditFindings(auditId: string): Promise<{ audit_id: string; total: number; findings: Finding[] }> {
  const res = await authFetch(`${API_BASE}/api/audits/${auditId}/findings`);
  if (!res.ok) throw new Error('Failed to load findings');
  return res.json();
}
