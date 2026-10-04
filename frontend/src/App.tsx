import React, { useState } from 'react';
import { Header } from './components/Header';
import { DashboardView } from './components/DashboardView';
import { NewAuditView } from './components/NewAuditView';
import { ActiveAuditView } from './components/ActiveAuditView';
import { ReportsView } from './components/ReportsView';
import { EvidenceModal } from './components/EvidenceModal';
import { AuditConfig, Finding } from './types/audit';

export const App: React.FC = () => {
  const [currentView, setCurrentView] = useState<'dashboard' | 'new-audit' | 'active-audit' | 'reports'>('dashboard');
  const [activeAuditId, setActiveAuditId] = useState<string | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [viewReportId, setViewReportId] = useState<string | null>(null);

  const handleAuditStarted = (config: AuditConfig) => {
    setActiveAuditId(config.audit_id);
    setCurrentView('active-audit');
  };

  const handleViewReport = (auditId: string) => {
    setViewReportId(auditId);
    setCurrentView('reports');
  };

  return (
    <div className="bg-slate-50 text-slate-900 min-h-screen flex flex-col font-sans selection:bg-blue-100 selection:text-blue-900">
      <Header
        currentView={currentView}
        onViewChange={(view) => {
          if (view === 'reports') setViewReportId(null);
          setCurrentView(view as any);
        }}
        hasActiveAudit={!!activeAuditId}
      />

      <main className="flex-1 p-6 max-w-7xl w-full mx-auto space-y-6">
        {currentView === 'dashboard' && (
          <DashboardView
            onStartNewAudit={() => setCurrentView('new-audit')}
            onViewReport={handleViewReport}
          />
        )}

        {currentView === 'new-audit' && (
          <NewAuditView
            onAuditStarted={handleAuditStarted}
            onCancel={() => setCurrentView('dashboard')}
          />
        )}

        {currentView === 'active-audit' && (
          activeAuditId ? (
            <ActiveAuditView
              auditId={activeAuditId}
              onOpenEvidence={(finding) => setSelectedFinding(finding)}
            />
          ) : (
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-12 text-center space-y-4">
              <h3 className="text-lg font-bold text-slate-800">No Active Audit Session</h3>
              <p className="text-sm text-slate-500 max-w-md mx-auto">
                There is currently no audit in progress. Launch a new audit to observe autonomous testing in real time.
              </p>
              <button
                onClick={() => setCurrentView('new-audit')}
                className="px-5 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-semibold text-sm transition shadow-sm"
              >
                Configure New Audit
              </button>
            </div>
          )
        )}

        {currentView === 'reports' && (
          <ReportsView
            initialAuditId={viewReportId}
            onOpenEvidence={(finding) => setSelectedFinding(finding)}
          />
        )}
      </main>

      <EvidenceModal
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />
    </div>
  );
};

export default App;
