import React, { useEffect, useState } from 'react';
import { Activity, CheckCircle, ShieldAlert, Folder, PlusCircle, ArrowRight, RefreshCw, Clock } from 'lucide-react';
import { GlobalStats, ReportSummary } from '../types/audit';
import { fetchGlobalStats, fetchReportsList } from '../services/api';

interface DashboardViewProps {
  onStartNewAudit: () => void;
  onViewReport: (auditId: string) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({ onStartNewAudit, onViewReport }) => {
  const [stats, setStats] = useState<GlobalStats>({
    active_audits: 0,
    total_audits: 0,
    total_findings: 0,
    critical_findings: 0,
    unique_projects_tested: 0,
  });
  const [reports, setReports] = useState<ReportSummary[]>([]);
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    setLoading(true);
    try {
      const [statsData, reportsData] = await Promise.all([
        fetchGlobalStats().catch(() => ({
          active_audits: 0,
          total_audits: 0,
          total_findings: 0,
          critical_findings: 0,
          unique_projects_tested: 0,
        })),
        fetchReportsList().catch(() => []),
      ]);
      setStats(statsData);
      setReports(reportsData);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const formatDate = (val: string | number) => {
    if (!val) return 'Recently';
    try {
      const dt = typeof val === 'number' ? new Date(val * 1000) : new Date(val);
      return dt.toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    } catch {
      return String(val);
    }
  };

  return (
    <div className="space-y-6">
      {/* Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="ui-card p-5 bg-white border border-slate-200">
          <div className="flex items-center justify-between text-slate-500 text-xs font-semibold uppercase tracking-wider mb-2">
            <span>Active Audits</span>
            <Activity className="w-4 h-4 text-blue-600" />
          </div>
          {loading ? (
            <div className="h-8 w-16 bg-slate-100 animate-pulse rounded my-1" />
          ) : (
            <div className="text-2xl font-bold text-slate-900">{stats.active_audits}</div>
          )}
          <p className="text-xs text-slate-500 mt-1">Autonomous loops in execution</p>
        </div>

        <div className="ui-card p-5 bg-white border border-slate-200">
          <div className="flex items-center justify-between text-slate-500 text-xs font-semibold uppercase tracking-wider mb-2">
            <span>Total Audits</span>
            <CheckCircle className="w-4 h-4 text-slate-600" />
          </div>
          {loading ? (
            <div className="h-8 w-16 bg-slate-100 animate-pulse rounded my-1" />
          ) : (
            <div className="text-2xl font-bold text-slate-900">{stats.total_audits}</div>
          )}
          <p className="text-xs text-slate-500 mt-1">Completed test evaluations</p>
        </div>

        <div className="ui-card p-5 bg-white border border-slate-200">
          <div className="flex items-center justify-between text-slate-500 text-xs font-semibold uppercase tracking-wider mb-2">
            <span>Confirmed Findings</span>
            <ShieldAlert className="w-4 h-4 text-red-600" />
          </div>
          {loading ? (
            <div className="h-8 w-16 bg-slate-100 animate-pulse rounded my-1" />
          ) : (
            <div className="text-2xl font-bold text-red-600">{stats.total_findings}</div>
          )}
          <p className="text-xs text-slate-500 mt-1">
            <span className="text-red-700 font-semibold">{stats.critical_findings}</span> critical severity
          </p>
        </div>

        <div className="ui-card p-5 bg-white border border-slate-200">
          <div className="flex items-center justify-between text-slate-500 text-xs font-semibold uppercase tracking-wider mb-2">
            <span>Projects Tested</span>
            <Folder className="w-4 h-4 text-slate-600" />
          </div>
          {loading ? (
            <div className="h-8 w-16 bg-slate-100 animate-pulse rounded my-1" />
          ) : (
            <div className="text-2xl font-bold text-slate-900">{stats.unique_projects_tested}</div>
          )}
          <p className="text-xs text-slate-500 mt-1">Distinct target applications</p>
        </div>
      </div>

      {/* Action Banner */}
      <div className="ui-panel p-6 bg-white border border-slate-200 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-slate-900">
            Launch Autonomous Security & Resilience Audit
          </h2>
          <p className="text-sm text-slate-600 mt-1 max-w-2xl">
            Select any target application directory. StressX inspects architecture, formulates targeted attack hypotheses, and tests behavior safely inside an isolated container sandbox.
          </p>
        </div>
        <button
          onClick={onStartNewAudit}
          className="px-4 py-2 rounded-md bg-blue-600 hover:bg-blue-700 text-white font-medium text-sm flex items-center justify-center space-x-2 transition shadow-sm whitespace-nowrap self-start md:self-auto"
        >
          <PlusCircle className="w-4 h-4" />
          <span>Configure New Audit</span>
        </button>
      </div>

      {/* Recent Audits Table / List */}
      <div className="ui-panel bg-white border border-slate-200 overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-700">
              Recent Audits
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">
              History of security audits and completed testing dossiers
            </p>
          </div>
          <button
            onClick={loadData}
            disabled={loading}
            className="text-slate-500 hover:text-slate-700 p-1.5 rounded transition text-xs flex items-center space-x-1"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>

        {loading ? (
          <div className="p-6 space-y-4">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-16 bg-slate-50 border border-slate-100 animate-pulse rounded-md" />
            ))}
          </div>
        ) : reports.length === 0 ? (
          <div className="p-12 text-center text-slate-500 space-y-3">
            <ShieldAlert className="w-8 h-8 text-slate-300 mx-auto" />
            <p className="text-sm">No audits have been executed yet.</p>
            <button
              onClick={onStartNewAudit}
              className="text-xs text-blue-600 hover:underline font-medium"
            >
              Start your first security audit
            </button>
          </div>
        ) : (
          <div className="divide-y divide-slate-100">
            {reports.slice(0, 10).map((rep) => {
              const auditTitle = rep.audit_name || rep.target_name || rep.audit_id;
              const targetDisplay = rep.target_name || rep.target || 'Application';

              return (
                <div
                  key={rep.audit_id}
                  className="px-6 py-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-slate-50 transition"
                >
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      <span className="font-semibold text-slate-900 text-sm">
                        {auditTitle}
                      </span>
                      <span className="text-xs font-mono px-2 py-0.5 bg-slate-100 text-slate-600 rounded border border-slate-200">
                        {rep.audit_id}
                      </span>
                      <span
                        className={`text-xs px-2 py-0.5 rounded font-medium ${
                          rep.status === 'COMPLETED'
                            ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                            : rep.status === 'RUNNING' || rep.status === 'SANDBOXING'
                            ? 'bg-blue-50 text-blue-700 border border-blue-200'
                            : 'bg-slate-100 text-slate-700 border border-slate-200'
                        }`}
                      >
                        {rep.status}
                      </span>
                    </div>

                    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-500">
                      <span>Target: <strong className="text-slate-700 font-medium">{targetDisplay}</strong></span>
                      <span className="flex items-center space-x-1">
                        <Clock className="w-3 h-3 text-slate-400" />
                        <span>{formatDate(rep.timestamp)}</span>
                      </span>
                      {rep.duration && (
                        <span>Duration: {rep.duration}</span>
                      )}
                      <span>Steps: {rep.total_steps}</span>
                    </div>
                  </div>

                  <div className="flex items-center space-x-4 self-end sm:self-center">
                    <div className="flex items-center space-x-1 text-xs font-medium">
                      {rep.findings_count > 0 ? (
                        <div className="flex items-center space-x-1.5">
                          {rep.critical_count > 0 && (
                            <span className="badge-critical px-2 py-0.5 rounded">
                              {rep.critical_count} Critical
                            </span>
                          )}
                          {rep.high_count > 0 && (
                            <span className="badge-high px-2 py-0.5 rounded">
                              {rep.high_count} High
                            </span>
                          )}
                          <span className="text-slate-600">
                            {rep.findings_count} findings
                          </span>
                        </div>
                      ) : (
                        <span className="text-slate-400">0 findings</span>
                      )}
                    </div>

                    <button
                      onClick={() => onViewReport(rep.audit_id)}
                      className="px-3 py-1.5 rounded text-xs font-medium border border-slate-300 hover:border-slate-400 text-slate-700 hover:text-slate-900 bg-white shadow-sm flex items-center space-x-1 transition"
                    >
                      <span>View Report</span>
                      <ArrowRight className="w-3 h-3 text-slate-400" />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};

export default DashboardView;
