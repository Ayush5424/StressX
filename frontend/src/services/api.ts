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

export async function fetchGlobalStats(): Promise<GlobalStats> {
  const res = await fetch(`${API_BASE}/api/stats`);
  if (!res.ok) throw new Error('Failed to load global statistics');
  return res.json();
}

export async function fetchReportsList(): Promise<ReportSummary[]> {
  const res = await fetch(`${API_BASE}/api/reports`);
  if (!res.ok) throw new Error('Failed to load reports');
  return res.json();
}

export async function fetchReportDetails(auditId: string): Promise<ReportDossier> {
  const res = await fetch(`${API_BASE}/api/reports/${auditId}`);
  if (!res.ok) throw new Error(`Failed to load report dossier for ${auditId}`);
  return res.json();
}

export async function analyzeProject(projectPath: string): Promise<AnalyzeProjectResponse> {
  const res = await fetch(`${API_BASE}/api/projects/analyze`, {
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
  projectPath: string,
  selectedSteps?: number,
  name?: string,
  auditName?: string
): Promise<AuditConfig> {
  const res = await fetch(`${API_BASE}/api/audits`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      project_path: projectPath,
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
  const res = await fetch(`${API_BASE}/api/audits/${auditId}/start`, {
    method: 'POST'
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || 'Failed to start audit');
  }
  return res.json();
}

export async function stopAudit(auditId: string): Promise<{ status: string; audit_id: string; message: string }> {
  const res = await fetch(`${API_BASE}/api/audits/${auditId}/stop`, {
    method: 'POST'
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || 'Failed to stop audit');
  }
  return res.json();
}

export async function fetchAuditConfig(auditId: string): Promise<AuditConfig> {
  const res = await fetch(`${API_BASE}/api/audits/${auditId}`);
  if (!res.ok) throw new Error('Audit not found');
  return res.json();
}

export async function fetchAuditSurface(auditId: string): Promise<SurfaceResponse> {
  const res = await fetch(`${API_BASE}/api/audits/${auditId}/surface`);
  if (!res.ok) throw new Error('Failed to load attack surface');
  return res.json();
}

export async function fetchAuditActivity(auditId: string): Promise<AuditActivity> {
  const res = await fetch(`${API_BASE}/api/audits/${auditId}/activity`);
  if (!res.ok) throw new Error('Failed to load audit activity');
  return res.json();
}

export async function fetchAuditFindings(auditId: string): Promise<{ audit_id: string; total: number; findings: Finding[] }> {
  const res = await fetch(`${API_BASE}/api/audits/${auditId}/findings`);
  if (!res.ok) throw new Error('Failed to load findings');
  return res.json();
}
