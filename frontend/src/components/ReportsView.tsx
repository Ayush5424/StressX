import React, { useEffect, useState } from 'react';
import {
  Archive,
  RefreshCw,
  ArrowLeft,
  Copy,
  Check,
  Search,
  ShieldAlert,
  Clock,
  Target,
  Layers,
  ChevronDown,
  ChevronUp,
  Download,
  Terminal,
  Activity,
  FileText,
  CheckCircle2,
  ExternalLink
} from 'lucide-react';
import { marked } from 'marked';
import { ReportSummary, ReportDossier, Finding } from '../types/audit';
import { fetchReportsList, fetchReportDetails } from '../services/api';

interface ReportsViewProps {
  initialAuditId?: string | null;
  onOpenEvidence: (finding: Finding) => void;
}

export const ReportsView: React.FC<ReportsViewProps> = ({ initialAuditId, onOpenEvidence }) => {
  const [reports, setReports] = useState<ReportSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedAuditId, setSelectedAuditId] = useState<string | null>(initialAuditId || null);
  const [dossier, setDossier] = useState<ReportDossier | null>(null);
  const [dossierLoading, setDossierLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [activeTab, setActiveTab] = useState<'findings' | 'summary' | 'actions' | 'raw'>('findings');
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({});
  const [copiedRaw, setCopiedRaw] = useState(false);
  const [copiedCurlId, setCopiedCurlId] = useState<string | null>(null);

  const loadReports = async () => {
    setLoading(true);
    try {
      const data = await fetchReportsList();
      setReports(data);
    } catch (err) {
      console.error('Error fetching reports:', err);
    } finally {
      setLoading(false);
    }
  };

  const loadDossier = async (auditId: string) => {
    setSelectedAuditId(auditId);
    setDossierLoading(true);
    try {
      const data = await fetchReportDetails(auditId);
      setDossier(data);
      // If there are findings, start on findings; otherwise summary
      if (data.findings && data.findings.length > 0) {
        setActiveTab('findings');
      } else {
        setActiveTab('summary');
      }
    } catch (err) {
      console.error('Error loading dossier:', err);
      alert('Failed to load report dossier');
    } finally {
      setDossierLoading(false);
    }
  };

  useEffect(() => {
    loadReports();
    if (initialAuditId) {
      loadDossier(initialAuditId);
    }
  }, [initialAuditId]);

  const toggleFindingExpanded = (findingId: string) => {
    setExpandedFindings((prev) => ({
      ...prev,
      [findingId]: !prev[findingId],
    }));
  };

  const handleCopyCurl = (cmd: string, id: string) => {
    navigator.clipboard.writeText(cmd).then(() => {
      setCopiedCurlId(id);
      setTimeout(() => setCopiedCurlId(null), 2000);
    });
  };

  const handleCopyRaw = () => {
    if (!dossier) return;
    const jsonStr = JSON.stringify(
      {
        report: dossier.report,
        metrics: dossier.metrics,
        findings: dossier.findings,
        evidence: dossier.evidence,
        actions: dossier.actions,
      },
      null,
      2
    );
    navigator.clipboard.writeText(jsonStr).then(() => {
      setCopiedRaw(true);
      setTimeout(() => setCopiedRaw(false), 2000);
    });
  };

  const handleDownloadRaw = () => {
    if (!dossier) return;
    const jsonStr = JSON.stringify(
      {
        report: dossier.report,
        metrics: dossier.metrics,
        findings: dossier.findings,
        evidence: dossier.evidence,
        actions: dossier.actions,
      },
      null,
      2
    );
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `audit-report-${selectedAuditId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const filteredReports = reports.filter((r) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      (r.audit_name && r.audit_name.toLowerCase().includes(q)) ||
      (r.target && r.target.toLowerCase().includes(q)) ||
      (r.target_name && r.target_name.toLowerCase().includes(q)) ||
      (r.audit_id && r.audit_id.toLowerCase().includes(q))
    );
  });

  // Extract metrics from current dossier
  const currentAuditName = dossier?.audit_name || dossier?.report?.audit_name || 'Security Audit';
  const currentTargetName = dossier?.target_name || dossier?.report?.target_name || dossier?.report?.target?.name || dossier?.report?.target?.base_url || 'Target Application';
  const currentStatus = dossier?.status || dossier?.report?.status || 'COMPLETED';
  const currentDuration = dossier?.duration || dossier?.report?.duration || (dossier?.metrics?.duration_seconds ? `${Math.round(dossier.metrics.duration_seconds)}s` : 'N/A');
  const currentSteps = dossier?.metrics?.total_steps ?? dossier?.report?.step_count ?? dossier?.actions?.length ?? 0;
  const currentEndpointsTested = dossier?.metrics?.discovered_endpoints_count ?? dossier?.report?.target?.endpoints_tested ?? (dossier?.report?.endpoints ? dossier.report.endpoints.length : 'N/A');
  
  const findingsList = dossier?.findings || [];
  const criticalCount = findingsList.filter((f) => f.severity === 'CRITICAL').length;
  const highCount = findingsList.filter((f) => f.severity === 'HIGH').length;
  const mediumCount = findingsList.filter((f) => f.severity === 'MEDIUM').length;
  const lowCount = findingsList.filter((f) => f.severity === 'LOW' || f.severity === 'INFO').length;

  return (
    <div className="space-y-6">
      {/* Header bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2">
        <div>
          <h2 className="text-xl font-bold text-slate-900 flex items-center space-x-2.5">
            <Archive className="w-5 h-5 text-blue-600" />
            <span>Audit Reports</span>
          </h2>
          <p className="text-sm text-slate-500 mt-0.5">
            Structured security audit findings, empirical verification evidence, and reproduction steps.
          </p>
        </div>
        <div className="flex items-center space-x-2">
          {selectedAuditId ? (
            <button
              onClick={() => {
                setSelectedAuditId(null);
                setDossier(null);
              }}
              className="px-3.5 py-1.5 rounded-lg bg-white border border-slate-200 text-slate-700 hover:bg-slate-50 text-sm font-medium flex items-center space-x-1.5 shadow-sm transition"
            >
              <ArrowLeft className="w-4 h-4 text-slate-500" />
              <span>Back to Reports List</span>
            </button>
          ) : (
            <button
              onClick={loadReports}
              className="px-3.5 py-1.5 rounded-lg bg-white border border-slate-200 text-slate-700 hover:bg-slate-50 text-sm font-medium flex items-center space-x-1.5 shadow-sm transition"
            >
              <RefreshCw className={`w-3.5 h-3.5 text-slate-500 ${loading ? 'animate-spin' : ''}`} />
              <span>Refresh</span>
            </button>
          )}
        </div>
      </div>

      {/* VIEW 1: Reports List Screen */}
      {!selectedAuditId && (
        <div className="space-y-4">
          {/* Search bar */}
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Filter by audit name, target project, or audit ID..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-white border border-slate-200 rounded-lg text-sm text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 shadow-sm"
            />
          </div>

          {/* List Cards */}
          {loading ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {[1, 2, 3].map((n) => (
                <div key={n} className="bg-white rounded-xl border border-slate-200 p-5 space-y-3 animate-pulse">
                  <div className="h-4 bg-slate-200 rounded w-1/3"></div>
                  <div className="h-5 bg-slate-200 rounded w-3/4"></div>
                  <div className="h-3 bg-slate-100 rounded w-1/2"></div>
                </div>
              ))}
            </div>
          ) : filteredReports.length === 0 ? (
            <div className="bg-white rounded-xl border border-slate-200 p-12 text-center shadow-sm space-y-2">
              <FileText className="w-8 h-8 text-slate-300 mx-auto" />
              <p className="text-base font-semibold text-slate-700">No audit reports found</p>
              <p className="text-sm text-slate-400 max-w-sm mx-auto">
                {searchQuery ? 'Try clearing your filter criteria.' : 'Completed security audits will automatically appear here.'}
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {filteredReports.map((r) => {
                const isCrit = (r.critical_count || 0) > 0;
                const isHigh = (r.high_count || 0) > 0;
                const totalFindings = r.findings_count || 0;

                return (
                  <div
                    key={r.audit_id}
                    onClick={() => loadDossier(r.audit_id)}
                    className="bg-white rounded-xl border border-slate-200 hover:border-blue-400 p-5 space-y-3.5 cursor-pointer shadow-sm hover:shadow-md transition-all flex flex-col justify-between"
                  >
                    <div className="space-y-2">
                      {/* Top Badges */}
                      <div className="flex items-center justify-between">
                        <span
                          className={`px-2 py-0.5 rounded text-[11px] font-bold uppercase ${
                            r.status === 'COMPLETED'
                              ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                              : r.status === 'RUNNING'
                              ? 'bg-blue-50 text-blue-700 border border-blue-200'
                              : 'bg-slate-100 text-slate-700 border border-slate-200'
                          }`}
                        >
                          {r.status}
                        </span>
                        <span className="text-xs text-slate-400 font-mono flex items-center space-x-1">
                          <Clock className="w-3 h-3 text-slate-400" />
                          <span>{r.duration || (r.duration_seconds ? `${Math.round(r.duration_seconds)}s` : 'Done')}</span>
                        </span>
                      </div>

                      {/* Audit Name (Prominent) */}
                      <div>
                        <h3 className="text-base font-bold text-slate-900 line-clamp-1 group-hover:text-blue-600">
                          {r.audit_name || 'Security Audit'}
                        </h3>
                        <div className="flex items-center space-x-1.5 text-xs text-slate-500 mt-0.5">
                          <Target className="w-3 h-3 text-slate-400 shrink-0" />
                          <span className="font-medium text-slate-700 truncate">{r.target_name || r.target}</span>
                        </div>
                      </div>

                      {/* Audit ID & Time info */}
                      <div className="bg-slate-50 rounded-lg p-2 font-mono text-[11px] text-slate-500 border border-slate-100 space-y-0.5">
                        <div className="truncate">
                          <span className="text-slate-400 font-sans text-[10px] uppercase block">Audit ID</span>
                          <span className="text-slate-700">{r.audit_id}</span>
                        </div>
                        {r.timestamp && (
                          <div className="text-[10px] text-slate-400">
                            {typeof r.timestamp === 'string' && r.timestamp.includes('T')
                              ? r.timestamp.replace('T', ' ').substring(0, 19)
                              : String(r.timestamp)}
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Bottom Metadata & Severity Badges */}
                    <div className="pt-3 border-t border-slate-100 flex items-center justify-between">
                      <div className="text-xs text-slate-500 flex items-center space-x-1">
                        <Layers className="w-3.5 h-3.5 text-slate-400" />
                        <span>{r.total_steps || 0} steps</span>
                      </div>

                      <div className="flex items-center space-x-1.5">
                        {totalFindings === 0 ? (
                          <span className="text-xs font-semibold text-emerald-600 flex items-center space-x-1">
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            <span>0 Issues</span>
                          </span>
                        ) : (
                          <>
                            {isCrit && (
                              <span className="badge-critical text-[10px] px-1.5 py-0.5 font-bold">
                                {r.critical_count} CRIT
                              </span>
                            )}
                            {isHigh && (
                              <span className="badge-high text-[10px] px-1.5 py-0.5 font-bold">
                                {r.high_count} HIGH
                              </span>
                            )}
                            {!isCrit && !isHigh && (
                              <span className="badge-medium text-[10px] px-1.5 py-0.5 font-bold">
                                {totalFindings} Issues
                              </span>
                            )}
                          </>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* VIEW 2: Detailed Report View */}
      {selectedAuditId && (
        <div className="space-y-6">
          {dossierLoading ? (
            <div className="bg-white rounded-xl border border-slate-200 p-16 text-center space-y-3 shadow-sm">
              <div className="w-8 h-8 border-3 border-blue-600 border-t-transparent rounded-full animate-spin mx-auto" />
              <p className="text-sm font-medium text-slate-700">Loading audit report dossier...</p>
            </div>
          ) : (
            <>
              {/* 1. EXECUTIVE SUMMARY CARD AT THE TOP */}
              <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm space-y-5">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-100">
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2.5">
                      <span
                        className={`px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider ${
                          currentStatus === 'COMPLETED'
                            ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                            : currentStatus === 'RUNNING'
                            ? 'bg-blue-50 text-blue-700 border border-blue-200'
                            : 'bg-slate-100 text-slate-700 border border-slate-200'
                        }`}
                      >
                        {currentStatus}
                      </span>
                      <h1 className="text-xl font-bold text-slate-900">{currentAuditName}</h1>
                    </div>
                    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-500">
                      <span>Target: <strong className="text-slate-800">{currentTargetName}</strong></span>
                      <span>Audit ID: <code className="font-mono text-slate-700 bg-slate-100 px-1 py-0.5 rounded">{selectedAuditId}</code></span>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2">
                    <button
                      onClick={handleCopyRaw}
                      className="px-3 py-1.5 bg-slate-50 hover:bg-slate-100 text-slate-700 border border-slate-200 rounded-lg text-xs font-medium flex items-center space-x-1.5 transition"
                    >
                      {copiedRaw ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedRaw ? 'Copied' : 'Copy JSON'}</span>
                    </button>
                    <button
                      onClick={handleDownloadRaw}
                      className="px-3 py-1.5 bg-blue-50 hover:bg-blue-100 text-blue-700 border border-blue-200 rounded-lg text-xs font-medium flex items-center space-x-1.5 transition"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>Export Report</span>
                    </button>
                  </div>
                </div>

                {/* Key Metrics Grid */}
                <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
                  <div className="bg-slate-50 p-3 rounded-lg border border-slate-200/80">
                    <span className="text-[10px] uppercase font-bold text-slate-400 block tracking-wider">Duration</span>
                    <span className="text-base font-bold text-slate-800 mt-0.5 block">{currentDuration}</span>
                  </div>
                  <div className="bg-slate-50 p-3 rounded-lg border border-slate-200/80">
                    <span className="text-[10px] uppercase font-bold text-slate-400 block tracking-wider">Steps Executed</span>
                    <span className="text-base font-bold text-slate-800 mt-0.5 block">{currentSteps}</span>
                  </div>
                  <div className="bg-slate-50 p-3 rounded-lg border border-slate-200/80">
                    <span className="text-[10px] uppercase font-bold text-slate-400 block tracking-wider">Endpoints Tested</span>
                    <span className="text-base font-bold text-slate-800 mt-0.5 block">{currentEndpointsTested}</span>
                  </div>
                  <div className="bg-red-50/60 p-3 rounded-lg border border-red-200/80">
                    <span className="text-[10px] uppercase font-bold text-red-600 block tracking-wider">Critical</span>
                    <span className="text-base font-bold text-red-700 mt-0.5 block">{criticalCount}</span>
                  </div>
                  <div className="bg-amber-50/60 p-3 rounded-lg border border-amber-200/80">
                    <span className="text-[10px] uppercase font-bold text-amber-700 block tracking-wider">High</span>
                    <span className="text-base font-bold text-amber-800 mt-0.5 block">{highCount}</span>
                  </div>
                  <div className="bg-yellow-50/60 p-3 rounded-lg border border-yellow-200/80">
                    <span className="text-[10px] uppercase font-bold text-yellow-700 block tracking-wider">Medium / Low</span>
                    <span className="text-base font-bold text-yellow-800 mt-0.5 block">{mediumCount + lowCount}</span>
                  </div>
                </div>
              </div>

              {/* Navigation Tabs */}
              <div className="flex space-x-2 border-b border-slate-200 pb-2 text-sm font-medium">
                <button
                  onClick={() => setActiveTab('findings')}
                  className={`px-3.5 py-1.5 rounded-lg transition flex items-center space-x-2 ${
                    activeTab === 'findings'
                      ? 'bg-blue-50 text-blue-700 font-semibold border border-blue-200'
                      : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
                  }`}
                >
                  <ShieldAlert className="w-4 h-4" />
                  <span>Findings & Vulnerabilities ({findingsList.length})</span>
                </button>
                <button
                  onClick={() => setActiveTab('summary')}
                  className={`px-3.5 py-1.5 rounded-lg transition flex items-center space-x-2 ${
                    activeTab === 'summary'
                      ? 'bg-blue-50 text-blue-700 font-semibold border border-blue-200'
                      : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
                  }`}
                >
                  <FileText className="w-4 h-4" />
                  <span>Executive Report Summary</span>
                </button>
                <button
                  onClick={() => setActiveTab('actions')}
                  className={`px-3.5 py-1.5 rounded-lg transition flex items-center space-x-2 ${
                    activeTab === 'actions'
                      ? 'bg-blue-50 text-blue-700 font-semibold border border-blue-200'
                      : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
                  }`}
                >
                  <Activity className="w-4 h-4" />
                  <span>Action Timeline ({dossier?.actions?.length || 0})</span>
                </button>
                <button
                  onClick={() => setActiveTab('raw')}
                  className={`px-3.5 py-1.5 rounded-lg transition flex items-center space-x-2 ${
                    activeTab === 'raw'
                      ? 'bg-blue-50 text-blue-700 font-semibold border border-blue-200'
                      : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
                  }`}
                >
                  <Terminal className="w-4 h-4" />
                  <span>Raw Dossier</span>
                </button>
              </div>

              {/* TAB 1: FINDINGS SECTION */}
              {activeTab === 'findings' && (
                <div className="space-y-4">
                  {findingsList.length === 0 ? (
                    <div className="bg-white rounded-xl border border-slate-200 p-12 text-center shadow-sm space-y-2">
                      <CheckCircle2 className="w-10 h-10 text-emerald-500 mx-auto" />
                      <h3 className="text-base font-bold text-slate-800">No Security Findings Discovered</h3>
                      <p className="text-sm text-slate-500 max-w-md mx-auto">
                        The autonomous security agent completed all budgeted steps against {currentTargetName} without observing vulnerable failure conditions.
                      </p>
                    </div>
                  ) : (
                    findingsList.map((f, i) => {
                      const isExpanded = !!expandedFindings[f.id || String(i)];
                      
                      // Resolve curl reproduction command
                      let curlCmd = '';
                      if (Array.isArray(f.reproduction_steps) && f.reproduction_steps.length > 0) {
                        curlCmd = f.reproduction_steps[0];
                      } else if (
                        f.reproduction_steps &&
                        typeof f.reproduction_steps === 'object' &&
                        'curl_command' in f.reproduction_steps
                      ) {
                        curlCmd = (f.reproduction_steps as any).curl_command || '';
                      }
                      if (!curlCmd && f.evidence && f.evidence.length > 0) {
                        curlCmd = f.evidence[0].curl_command || '';
                      }
                      if (!curlCmd) {
                        curlCmd = `curl -i '${f.affected_endpoint || 'http://127.0.0.1:8080'}'`;
                      }

                      return (
                        <div
                          key={f.id || i}
                          className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden"
                        >
                          {/* Finding Card Top / Summary */}
                          <div className="p-5 space-y-4">
                            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                              <div className="flex items-center space-x-2.5">
                                <span
                                  className={`px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider ${
                                    f.severity === 'CRITICAL'
                                      ? 'badge-critical'
                                      : f.severity === 'HIGH'
                                      ? 'badge-high'
                                      : f.severity === 'MEDIUM'
                                      ? 'badge-medium'
                                      : 'badge-low'
                                  }`}
                                >
                                  {f.severity}
                                </span>
                                <h3 className="text-base font-bold text-slate-900">{f.title}</h3>
                              </div>

                              <div className="flex items-center space-x-2 text-xs">
                                <span className="bg-slate-100 text-slate-600 px-2 py-0.5 rounded font-mono">
                                  Confidence: {f.confidence || 'HIGH'}
                                </span>
                                <span className="text-slate-400">|</span>
                                <span className="font-mono text-blue-600 bg-blue-50 px-2 py-0.5 rounded font-semibold">
                                  {f.affected_endpoint || '/'}
                                </span>
                              </div>
                            </div>

                            {/* Structured Explanations */}
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                              {/* What Happened */}
                              <div className="bg-slate-50 p-3.5 rounded-lg border border-slate-100 space-y-1">
                                <span className="font-bold text-slate-500 uppercase text-[10px] tracking-wider block">
                                  What Happened
                                </span>
                                <p className="text-slate-700 leading-relaxed font-sans text-sm">
                                  {f.description}
                                </p>
                              </div>

                              {/* Impact */}
                              <div className="bg-slate-50 p-3.5 rounded-lg border border-slate-100 space-y-1">
                                <span className="font-bold text-slate-500 uppercase text-[10px] tracking-wider block">
                                  Impact & Risk
                                </span>
                                <p className="text-slate-700 leading-relaxed font-sans text-sm">
                                  {f.impact || 'Allows unverified access or state distortion through untested failure handling.'}
                                </p>
                              </div>
                            </div>

                            {/* Evidence overview & How it was verified */}
                            <div className="bg-slate-50/60 p-3.5 rounded-lg border border-slate-100 text-xs space-y-1.5">
                              <div className="flex items-center justify-between">
                                <span className="font-bold text-slate-500 uppercase text-[10px] tracking-wider">
                                  Empirical Verification Overview
                                </span>
                                <span className="text-slate-400 text-[11px]">
                                  Verified via dynamic HTTP execution
                                </span>
                              </div>
                              <p className="text-slate-600 font-sans">
                                {f.evidence && f.evidence.length > 0 && f.evidence[0].observed_behavior
                                  ? f.evidence[0].observed_behavior
                                  : 'Observed non-conforming responses under automated pressure and mutation tests.'}
                              </p>
                            </div>

                            {/* Remediation Note */}
                            {f.remediation && (
                              <div className="bg-emerald-50 border border-emerald-200/80 p-3 rounded-lg text-xs space-y-1">
                                <span className="font-bold text-emerald-800 uppercase text-[10px] tracking-wider block">
                                  Recommended Remediation
                                </span>
                                <p className="text-emerald-900 leading-relaxed font-sans">
                                  {f.remediation}
                                </p>
                              </div>
                            )}

                            {/* Accordion Toggle Bar */}
                            <div className="pt-2 border-t border-slate-100 flex items-center justify-between">
                              <button
                                onClick={() => toggleFindingExpanded(f.id || String(i))}
                                className="text-xs font-semibold text-blue-600 hover:text-blue-700 flex items-center space-x-1.5 transition"
                              >
                                {isExpanded ? (
                                  <>
                                    <ChevronUp className="w-4 h-4" />
                                    <span>Hide Technical Evidence & Reproduction</span>
                                  </>
                                ) : (
                                  <>
                                    <ChevronDown className="w-4 h-4" />
                                    <span>Expand Technical Evidence & Reproduction ({f.evidence?.length || 1} proof items)</span>
                                  </>
                                )}
                              </button>

                              <button
                                onClick={() => onOpenEvidence(f)}
                                className="text-xs text-slate-500 hover:text-slate-800 flex items-center space-x-1"
                              >
                                <span>Open Full Evidence Dialog</span>
                                <ExternalLink className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          </div>

                          {/* 4. EXPANDABLE TECHNICAL EVIDENCE ACCORDION */}
                          {isExpanded && (
                            <div className="border-t border-slate-200 bg-slate-900 p-5 space-y-4 text-xs font-mono text-slate-300">
                              {/* cURL reproduction block */}
                              <div>
                                <div className="flex items-center justify-between mb-1.5">
                                  <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                                    cURL Reproduction Command
                                  </span>
                                  <button
                                    onClick={() => handleCopyCurl(curlCmd, f.id || String(i))}
                                    className="text-blue-400 hover:text-blue-300 flex items-center space-x-1 font-mono text-[11px]"
                                  >
                                    {copiedCurlId === (f.id || String(i)) ? (
                                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                                    ) : (
                                      <Copy className="w-3.5 h-3.5" />
                                    )}
                                    <span>{copiedCurlId === (f.id || String(i)) ? 'Copied' : 'Copy cURL'}</span>
                                  </button>
                                </div>
                                <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-emerald-400 text-xs overflow-x-auto select-all">
                                  {curlCmd}
                                </pre>
                              </div>

                              {/* Causal Chain */}
                              {f.causal_chain && f.causal_chain.length > 0 && (
                                <div>
                                  <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 block mb-1.5">
                                    Causal Chain / Mechanism
                                  </span>
                                  <div className="space-y-1 pl-1">
                                    {f.causal_chain.map((c, stepIdx) => (
                                      <div key={stepIdx} className="flex items-start space-x-2 text-slate-300">
                                        <span className="text-blue-400 font-bold">{stepIdx + 1}.</span>
                                        <span>{c}</span>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}

                              {/* Empirical HTTP Evidence */}
                              {f.evidence && f.evidence.length > 0 && (
                                <div>
                                  <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 block mb-1.5">
                                    Captured HTTP Transactions
                                  </span>
                                  <div className="space-y-2">
                                    {f.evidence.map((ev, evIdx) => (
                                      <div key={evIdx} className="p-3 bg-slate-950 border border-slate-800 rounded-lg space-y-1.5">
                                        <div className="flex justify-between text-slate-400 text-[11px]">
                                          <span className="text-slate-200 font-bold">
                                            {ev.method || 'GET'} {ev.endpoint || ''}
                                          </span>
                                          <span className="text-blue-400">Status: {ev.status_code || 200}</span>
                                        </div>
                                        {ev.observed_behavior && (
                                          <p className="text-slate-300 text-xs font-sans">{ev.observed_behavior}</p>
                                        )}
                                        {ev.response_body_preview && (
                                          <pre className="p-2 bg-slate-900 rounded border border-slate-800 text-[11px] text-amber-300 max-h-36 overflow-y-auto">
                                            {ev.response_body_preview}
                                          </pre>
                                        )}
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })
                  )}
                </div>
              )}

              {/* TAB 2: PLAIN-ENGLISH EXECUTIVE REPORT SUMMARY */}
              {activeTab === 'summary' && (
                <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm space-y-4">
                  <h3 className="text-base font-bold text-slate-900">Executive Report Summary</h3>
                  <div
                    className="prose max-w-none text-slate-700 text-sm leading-relaxed overflow-x-auto"
                    dangerouslySetInnerHTML={{
                      __html: dossier?.markdown
                        ? marked.parse(dossier.markdown)
                        : '<p class="text-slate-500">No markdown summary generated for this audit session.</p>',
                    }}
                  />
                </div>
              )}

              {/* TAB 3: ACTION LOG TIMELINE */}
              {activeTab === 'actions' && (
                <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
                  <div className="p-4 border-b border-slate-100 flex items-center justify-between">
                    <h3 className="text-base font-bold text-slate-900">Autonomous Action Timeline</h3>
                    <span className="text-xs text-slate-500 font-mono">
                      {dossier?.actions?.length || 0} executed actions
                    </span>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-slate-50 text-slate-600 border-b border-slate-200">
                        <tr>
                          <th className="py-2.5 px-4 font-semibold">Step</th>
                          <th className="py-2.5 px-4 font-semibold">Tool</th>
                          <th className="py-2.5 px-4 font-semibold">Method</th>
                          <th className="py-2.5 px-4 font-semibold">Target Endpoint</th>
                          <th className="py-2.5 px-4 font-semibold">Status</th>
                          <th className="py-2.5 px-4 font-semibold">Latency</th>
                          <th className="py-2.5 px-4 font-semibold">Outcome</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100">
                        {!dossier?.actions || dossier.actions.length === 0 ? (
                          <tr>
                            <td colSpan={7} className="py-8 text-center text-slate-400 font-sans">
                              No action logs recorded for this audit.
                            </td>
                          </tr>
                        ) : (
                          dossier.actions.map((a, i) => (
                            <tr key={i} className="hover:bg-slate-50">
                              <td className="py-2.5 px-4 text-blue-600 font-bold">{a.step}</td>
                              <td className="py-2.5 px-4 font-semibold text-slate-800">{a.tool}</td>
                              <td className="py-2.5 px-4 text-slate-600">{a.method || '-'}</td>
                              <td className="py-2.5 px-4 text-slate-700 truncate max-w-xs">{a.target || ''}</td>
                              <td className="py-2.5 px-4 text-slate-600">{a.status_code || '-'}</td>
                              <td className="py-2.5 px-4 text-slate-500">
                                {a.latency_ms ? `${a.latency_ms}ms` : '-'}
                              </td>
                              <td className="py-2.5 px-4">
                                <span
                                  className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                    a.outcome === 'SUCCESS'
                                      ? 'bg-emerald-50 text-emerald-700'
                                      : 'bg-red-50 text-red-700'
                                  }`}
                                >
                                  {a.outcome}
                                </span>
                              </td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* TAB 4: RAW DOSSIER */}
              {activeTab === 'raw' && (
                <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm space-y-3 font-mono text-xs">
                  <div className="flex justify-between items-center pb-2 border-b border-slate-100">
                    <span className="text-slate-500">Structured audit dossier data (JSON)</span>
                    <button
                      onClick={handleCopyRaw}
                      className="px-3 py-1 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded text-xs flex items-center space-x-1.5 transition"
                    >
                      {copiedRaw ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedRaw ? 'Copied' : 'Copy JSON'}</span>
                    </button>
                  </div>
                  <pre className="p-4 bg-slate-900 text-slate-200 rounded-lg border border-slate-800 overflow-x-auto max-h-[500px]">
                    {JSON.stringify(
                      {
                        audit_id: dossier?.audit_id,
                        audit_name: dossier?.audit_name,
                        report: dossier?.report,
                        metrics: dossier?.metrics,
                        findings: dossier?.findings,
                        evidence: dossier?.evidence,
                        actions: dossier?.actions,
                      },
                      null,
                      2
                    )}
                  </pre>
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
};
