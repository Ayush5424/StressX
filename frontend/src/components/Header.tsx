import React from 'react';
import { Shield, LayoutDashboard, PlusCircle, Activity, FileText } from 'lucide-react';

interface HeaderProps {
  currentView: string;
  onViewChange: (view: string) => void;
  hasActiveAudit: boolean;
}

export const Header: React.FC<HeaderProps> = ({ currentView, onViewChange, hasActiveAudit }) => {
  return (
    <header className="border-b border-slate-200 bg-white sticky top-0 z-40 px-6 py-3 flex items-center justify-between shadow-sm">
      <div className="flex items-center space-x-6">
        <div
          className="flex items-center space-x-2.5 cursor-pointer select-none"
          onClick={() => onViewChange('dashboard')}
        >
          <div className="w-8 h-8 rounded-md bg-blue-600 flex items-center justify-center text-white shadow-sm">
            <Shield className="w-4 h-4" />
          </div>
          <div className="flex items-center space-x-2">
            <span className="text-lg font-bold tracking-tight text-slate-900">
              StressX
            </span>
            <span className="text-xs px-2 py-0.5 font-medium bg-slate-100 text-slate-600 border border-slate-200 rounded">
              Autonomous Security Platform
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

      <div className="flex items-center space-x-3">
        <button
          onClick={() => onViewChange('new-audit')}
          className="px-3.5 py-1.5 rounded-md text-sm font-medium bg-blue-600 hover:bg-blue-700 text-white shadow-sm flex items-center space-x-1.5 transition"
        >
          <PlusCircle className="w-4 h-4" />
          <span>New Audit</span>
        </button>
      </div>
    </header>
  );
};

export default Header;
