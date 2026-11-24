import React, { useState, useEffect } from 'react';
import { Shield, LayoutDashboard, PlusCircle, Activity, FileText, UserCheck } from 'lucide-react';
import { getOrCreateUserId } from '../services/api';

interface HeaderProps {
  currentView: string;
  onViewChange: (view: string) => void;
  hasActiveAudit: boolean;
}

export const Header: React.FC<HeaderProps> = ({ currentView, onViewChange, hasActiveAudit }) => {
  const [userId, setUserId] = useState<string>('');

  useEffect(() => {
    setUserId(getOrCreateUserId());
  }, []);

  const shortId = userId.length > 10 ? `${userId.substring(0, 8)}...` : userId;
  return (
    <header className="border-b border-slate-200 bg-white sticky top-0 z-40 w-full max-w-full shadow-sm">
      <div className="px-3 sm:px-6 py-2.5 sm:py-3 flex items-center justify-between gap-2 max-w-7xl mx-auto w-full">
        <div className="flex items-center space-x-3 sm:space-x-6 min-w-0">
          <div
            className="flex items-center space-x-2 cursor-pointer select-none shrink-0"
            onClick={() => onViewChange('dashboard')}
          >
            <div className="w-7 h-7 sm:w-8 sm:h-8 rounded-md bg-blue-600 flex items-center justify-center text-white shadow-sm shrink-0">
              <Shield className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
            </div>
            <div className="flex items-center space-x-2">
              <span className="text-base sm:text-lg font-bold tracking-tight text-slate-900">
                StressX
              </span>
              <span className="hidden sm:inline-block text-[11px] px-2 py-0.5 font-medium bg-slate-100 text-slate-600 border border-slate-200 rounded">
                Autonomous Security
              </span>
            </div>
          </div>

          <nav className="hidden md:flex items-center space-x-1 pl-4 border-l border-slate-200">
            <button
              onClick={() => onViewChange('dashboard')}
              className={`px-3 py-1.5 rounded-md text-sm font-medium transition flex items-center space-x-1.5 ${
                currentView === 'dashboard'
                  ? 'text-blue-700 bg-blue-50 border border-blue-200'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
              }`}
            >
              <LayoutDashboard className="w-4 h-4" />
              <span>Dashboard</span>
            </button>

            <button
              onClick={() => onViewChange('new-audit')}
              className={`px-3 py-1.5 rounded-md text-sm font-medium transition flex items-center space-x-1.5 ${
                currentView === 'new-audit'
                  ? 'text-blue-700 bg-blue-50 border border-blue-200'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
              }`}
            >
              <PlusCircle className="w-4 h-4" />
              <span>New Audit</span>
            </button>

            <button
              onClick={() => onViewChange('active-audit')}
              className={`px-3 py-1.5 rounded-md text-sm font-medium transition flex items-center space-x-1.5 relative ${
                currentView === 'active-audit'
                  ? 'text-blue-700 bg-blue-50 border border-blue-200'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
              }`}
            >
              <Activity className="w-4 h-4" />
              <span>Live Monitor</span>
              {hasActiveAudit && (
                <span className="w-2 h-2 rounded-full bg-blue-600 live-indicator ml-0.5" />
              )}
            </button>

            <button
              onClick={() => onViewChange('reports')}
              className={`px-3 py-1.5 rounded-md text-sm font-medium transition flex items-center space-x-1.5 ${
                currentView === 'reports'
                  ? 'text-blue-700 bg-blue-50 border border-blue-200'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
              }`}
            >
              <FileText className="w-4 h-4" />
              <span>Reports</span>
            </button>
          </nav>
        </div>

        <div className="flex items-center space-x-2 sm:space-x-3 shrink-0">
          {userId && (
            <div
              className="flex items-center space-x-1 sm:space-x-1.5 px-2 py-1 rounded bg-slate-100 border border-slate-200 text-[10px] sm:text-xs text-slate-600 font-mono"
              title={`Isolated Workspace: ${userId}\nOnly your audits and reports are visible to this session.`}
            >
              <UserCheck className="w-3 h-3 text-emerald-600 shrink-0" />
              <span>{shortId}</span>
            </div>
          )}
          <button
            onClick={() => onViewChange('new-audit')}
            className="px-2.5 sm:px-3.5 py-1 sm:py-1.5 rounded-md text-xs sm:text-sm font-medium bg-blue-600 hover:bg-blue-700 text-white shadow-sm flex items-center space-x-1 sm:space-x-1.5 transition whitespace-nowrap"
          >
            <PlusCircle className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
            <span className="hidden xs:inline">New Audit</span>
            <span className="xs:hidden">New</span>
          </button>
        </div>
      </div>

      {/* Mobile Navigation Tab Row for Small Devices */}
      <nav className="flex md:hidden items-center justify-around border-t border-slate-100 bg-slate-50/80 px-1 py-1 w-full max-w-full overflow-x-hidden">
        <button
          onClick={() => onViewChange('dashboard')}
          className={`flex-1 py-1 rounded text-xs font-medium flex flex-col items-center justify-center space-y-0.5 transition ${
            currentView === 'dashboard' ? 'text-blue-700 font-bold bg-white shadow-xs' : 'text-slate-500'
          }`}
        >
          <LayoutDashboard className="w-3.5 h-3.5" />
          <span className="text-[10px]">Dashboard</span>
        </button>
        <button
          onClick={() => onViewChange('new-audit')}
          className={`flex-1 py-1 rounded text-xs font-medium flex flex-col items-center justify-center space-y-0.5 transition ${
            currentView === 'new-audit' ? 'text-blue-700 font-bold bg-white shadow-xs' : 'text-slate-500'
          }`}
        >
          <PlusCircle className="w-3.5 h-3.5" />
          <span className="text-[10px]">New Audit</span>
        </button>
        <button
          onClick={() => onViewChange('active-audit')}
          className={`flex-1 py-1 rounded text-xs font-medium flex flex-col items-center justify-center space-y-0.5 relative transition ${
            currentView === 'active-audit' ? 'text-blue-700 font-bold bg-white shadow-xs' : 'text-slate-500'
          }`}
        >
          <div className="relative">
            <Activity className="w-3.5 h-3.5" />
            {hasActiveAudit && (
              <span className="w-1.5 h-1.5 rounded-full bg-blue-600 live-indicator absolute -top-0.5 -right-1" />
            )}
          </div>
          <span className="text-[10px]">Monitor</span>
        </button>
        <button
          onClick={() => onViewChange('reports')}
          className={`flex-1 py-1 rounded text-xs font-medium flex flex-col items-center justify-center space-y-0.5 transition ${
            currentView === 'reports' ? 'text-blue-700 font-bold bg-white shadow-xs' : 'text-slate-500'
          }`}
        >
          <FileText className="w-3.5 h-3.5" />
          <span className="text-[10px]">Reports</span>
        </button>
      </nav>
    </header>
  );
};

export default Header;
