import React, { useState } from 'react';
import { Target, Search, Sliders, Play, AlertCircle, AlertTriangle, Loader2, ArrowLeft, Globe, Folder } from 'lucide-react';
import { AnalyzeProjectResponse, AuditConfig } from '../types/audit';
import { analyzeProject, createAudit, startAudit } from '../services/api';

interface NewAuditViewProps {
  onAuditStarted: (auditConfig: AuditConfig) => void;
  onCancel: () => void;
}

export const NewAuditView: React.FC<NewAuditViewProps> = ({ onAuditStarted, onCancel }) => {
  const [targetMode, setTargetMode] = useState<'url' | 'directory'>('url');
  const [targetUrl, setTargetUrl] = useState('');
  const [auditName, setAuditName] = useState('');
  const [projectPath, setProjectPath] = useState('');
  const [analyzing, setAnalyzing] = useState(false);
  const [analysis, setAnalysis] = useState<AnalyzeProjectResponse | null>(null);
  const [selectedSteps, setSelectedSteps] = useState(20);
  const [launching, setLaunching] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleAnalyze = async () => {
    if (!projectPath.trim()) {
      setError('Please provide a valid target project directory path.');
      return;
    }
    setError(null);
    setAnalyzing(true);
    setAnalysis(null);

    try {
      const data = await analyzeProject(projectPath.trim());
      setAnalysis(data);
      const rec = data.complexity.recommended_steps || 20;
      setSelectedSteps(rec);
      if (!auditName.trim()) {
        const projTitle = data.project.name || 'Application';
        setAuditName(`${projTitle} Security Audit`);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to inspect target project directory');
    } finally {
      setAnalyzing(false);
    }
  };

  const handleLaunch = async () => {
    setError(null);
    setLaunching(true);

    try {
      let config: AuditConfig;
      if (targetMode === 'url') {
        if (!targetUrl.trim()) {
          setError('Please provide a valid running application URL.');
          setLaunching(false);
          return;
        }
        const finalName = auditName.trim() || `Live App (${targetUrl.replace(/^https?:\/\//, '')}) Security Audit`;
        config = await createAudit(
          undefined,
          selectedSteps,
          'Live Target Application',
          finalName,
          targetUrl.trim()
        );
      } else {
        if (!analysis) {
          setError('Please inspect the project directory first.');
          setLaunching(false);
          return;
        }
        const finalName = auditName.trim() || `${analysis.project.name || 'Target'} Security Audit`;
        config = await createAudit(
          analysis.project.path,
          selectedSteps,
          analysis.project.name,
          finalName
        );
      }

      await startAudit(config.audit_id);
      onAuditStarted(config);
    } catch (err: any) {
      setError(err.message || 'Failed to initialize audit');
      setLaunching(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <button
            onClick={onCancel}
            className="text-xs text-slate-500 hover:text-slate-800 flex items-center space-x-1 mb-2 font-medium"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Back to Dashboard</span>
          </button>
          <h2 className="text-xl font-bold text-slate-900 flex items-center space-x-2">
            <Target className="w-5 h-5 text-blue-600" />
            <span>Configure Security Audit</span>
          </h2>
          <p className="text-sm text-slate-500 mt-1">
            Specify a user-facing audit name, select the target codebase, and calibrate the attack-step budget.
          </p>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-md bg-red-50 border border-red-200 text-red-700 text-sm flex items-start space-x-2">
          <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" />
          <div className="flex-1">
            <div className="font-semibold">Configuration Error</div>
            <div className="mt-0.5 text-xs text-red-600">{error}</div>
          </div>
        </div>
      )}

      {/* Target Directory & Audit Name Form */}
      <div className="ui-panel p-6 bg-white border border-slate-200 space-y-5">
        <div>
          <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-1.5">
            Audit Mode
          </label>
          <div className="grid grid-cols-2 gap-3">
            <button
              type="button"
              onClick={() => setTargetMode('url')}
              className={`p-3 rounded-lg border text-left flex items-start space-x-3 transition ${
                targetMode === 'url'
                  ? 'border-blue-600 bg-blue-50/50 text-blue-900'
                  : 'border-slate-200 hover:border-slate-300 text-slate-700'
              }`}
            >
              <Globe className={`w-5 h-5 mt-0.5 ${targetMode === 'url' ? 'text-blue-600' : 'text-slate-400'}`} />
              <div>
                <div className="font-semibold text-sm">Live Running Application</div>
                <div className="text-xs text-slate-500 mt-0.5">Test apps running in IntelliJ, VS Code, or localhost</div>
              </div>
            </button>

            <button
              type="button"
              onClick={() => setTargetMode('directory')}
              className={`p-3 rounded-lg border text-left flex items-start space-x-3 transition ${
                targetMode === 'directory'
                  ? 'border-blue-600 bg-blue-50/50 text-blue-900'
                  : 'border-slate-200 hover:border-slate-300 text-slate-700'
              }`}
            >
              <Folder className={`w-5 h-5 mt-0.5 ${targetMode === 'directory' ? 'text-blue-600' : 'text-slate-400'}`} />
              <div>
                <div className="font-semibold text-sm">Docker Sandbox Build</div>
                <div className="text-xs text-slate-500 mt-0.5">Build and isolate a local project directory in Docker</div>
              </div>
            </button>
          </div>
        </div>

        <div>
          <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-1.5">
            Audit Name <span className="text-red-500">*</span>
          </label>
          <input
            type="text"
            value={auditName}
            onChange={(e) => setAuditName(e.target.value)}
            placeholder="e.g. Procurement API Security Audit"
            className="w-full px-3.5 py-2 rounded-md bg-white border border-slate-300 text-slate-900 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500 transition shadow-sm"
          />
          <p className="text-xs text-slate-400 mt-1">
            User-facing name identifying this assessment in reports and activity feeds.
          </p>
        </div>

        {targetMode === 'url' ? (
          <div>
            <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-1.5">
              Live Target Base URL <span className="text-red-500">*</span>
            </label>
            <input
              type="text"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="e.g. https://my-app.onrender.com or https://abc-123.ngrok-free.app"
              className="w-full px-3.5 py-2 rounded-md bg-white border border-slate-300 text-slate-900 font-mono text-sm focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500 transition shadow-sm"
            />
            {targetUrl.match(/(localhost|127\.0\.0\.1|0\.0\.0\.0)/i) && typeof window !== 'undefined' && !['localhost', '127.0.0.1'].includes(window.location.hostname) && (
              <div className="mt-2.5 p-3 rounded-md bg-amber-50 border border-amber-200 text-amber-900 text-xs flex items-start space-x-2">
                <AlertTriangle className="w-4 h-4 shrink-0 text-amber-600 mt-0.5" />
                <div>
                  <span className="font-semibold">Cloud Deployment Notice:</span> Since StressX is deployed in the cloud on Render, it cannot connect directly to your personal computer's <code>localhost</code>.
                  <div className="mt-1 text-amber-800">
                    To audit an app running on your computer, expose your local port using a free tunnel (e.g. run <code className="bg-amber-100 px-1 py-0.5 rounded font-mono">npx ngrok http 8080</code>) and paste the public <code className="bg-amber-100 px-1 py-0.5 rounded font-mono">https://...ngrok-free.app</code> URL here, or enter a deployed public URL.
                  </div>
                </div>
              </div>
            )}
            <p className="text-xs text-slate-400 mt-1">
              StressX connects directly to your live running backend without needing Docker.
            </p>
          </div>
        ) : (
          <div>
            <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-1.5">
              Local Target Project Directory <span className="text-red-500">*</span>
            </label>
            <div className="flex flex-col sm:flex-row gap-2.5">
              <input
                type="text"
                value={projectPath}
                onChange={(e) => setProjectPath(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleAnalyze()}
                placeholder="e.g. C:\projects\payment-api or /path/to/target"
                className="flex-1 px-3.5 py-2 rounded-md bg-white border border-slate-300 text-slate-900 font-mono text-sm focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500 transition shadow-sm"
              />
              <button
                onClick={handleAnalyze}
                disabled={analyzing}
                className="px-4 py-2 rounded-md bg-slate-900 hover:bg-slate-800 text-white font-medium text-sm flex items-center justify-center space-x-2 transition shadow-sm disabled:opacity-50"
              >
                {analyzing ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin text-blue-400" />
                    <span>Analyzing...</span>
                  </>
                ) : (
                  <>
                    <Search className="w-4 h-4" />
                    <span>Inspect Target</span>
                  </>
                )}
              </button>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              StressX validates build descriptors (pom.xml, package.json, docker-compose.yml) and enumerates surfaces.
            </p>
          </div>
        )}

        {targetMode === 'url' && (
          <div className="pt-2 border-t border-slate-100 flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Sliders className="w-4 h-4 text-slate-500" />
              <span className="text-xs font-semibold text-slate-700">Attack Step Budget:</span>
              <span className="text-xs font-bold text-blue-600 font-mono">{selectedSteps} steps</span>
            </div>
            <input
              type="range"
              min="5"
              max="50"
              step="1"
              value={selectedSteps}
              onChange={(e) => setSelectedSteps(Number(e.target.value))}
              className="w-48 accent-blue-600"
            />
            <button
              onClick={handleLaunch}
              disabled={launching}
              className="px-5 py-2.5 rounded-md bg-blue-600 hover:bg-blue-700 text-white font-semibold text-sm flex items-center space-x-2 transition shadow-sm disabled:opacity-50"
            >
              {launching ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Launching Audit...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-white" />
                  <span>Launch Live Audit</span>
                </>
              )}
            </button>
          </div>
        )}
      </div>

      {/* Analysis Results & Budget Calibration */}
      {analysis && (
        <div className="space-y-6">
          <div className="ui-panel p-6 bg-white border border-slate-200 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <div>
                <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wider">
                  Architectural Complexity Profile
                </h3>
                <p className="text-xs text-slate-500">
                  Target: <strong className="text-slate-700">{analysis.project.name}</strong> ({analysis.project.framework || 'Generic Framework'})
                </p>
              </div>
              <span
                className={`text-xs px-2.5 py-1 rounded font-bold uppercase ${
                  analysis.complexity.level === 'VERY_HIGH' || analysis.complexity.level === 'HIGH'
                    ? 'badge-high'
                    : analysis.complexity.level === 'MEDIUM'
                    ? 'badge-medium'
                    : 'badge-low'
                }`}
              >
                {analysis.complexity.level} Complexity (Score: {analysis.complexity.score}/100)
              </span>
            </div>

            {/* Component Metrics */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="p-3 bg-slate-50 rounded border border-slate-100">
                <div className="text-xs text-slate-500 font-medium">Estimated Endpoints</div>
                <div className="text-xl font-bold text-slate-900 mt-0.5">
                  {analysis.complexity.endpoints_estimated}
                </div>
              </div>

              <div className="p-3 bg-slate-50 rounded border border-slate-100">
                <div className="text-xs text-slate-500 font-medium">Mutation Routes</div>
                <div className="text-xl font-bold text-slate-900 mt-0.5">
                  {analysis.complexity.mutation_routes_estimated}
                </div>
              </div>

              <div className="p-3 bg-slate-50 rounded border border-slate-100">
                <div className="text-xs text-slate-500 font-medium">Data Stores</div>
                <div className="text-xl font-bold text-slate-900 mt-0.5">
                  {analysis.complexity.databases_detected.length}
                </div>
              </div>

              <div className="p-3 bg-slate-50 rounded border border-slate-100">
                <div className="text-xs text-slate-500 font-medium">Recommended Steps</div>
                <div className="text-xl font-bold text-blue-600 mt-0.5">
                  {analysis.complexity.recommended_steps}
                </div>
              </div>
            </div>

            {/* Analysis Reasons */}
            {analysis.complexity.reasons && analysis.complexity.reasons.length > 0 && (
              <div className="space-y-1.5 pt-1">
                <div className="text-xs font-semibold text-slate-700">Detection Findings:</div>
                <ul className="text-xs text-slate-600 space-y-1 pl-4 list-disc">
                  {analysis.complexity.reasons.map((r, idx) => (
                    <li key={idx}>{r}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          {/* Budget Calibration Slider */}
          <div className="ui-panel p-6 bg-white border border-slate-200 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wider flex items-center space-x-1.5">
                  <Sliders className="w-4 h-4 text-blue-600" />
                  <span>Calibrate Attack-Step Budget</span>
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Adaptive ceiling governing how many reasoning and testing steps StressX can execute.
                </p>
              </div>
              <div className="flex items-center space-x-2">
                <span className="text-2xl font-bold font-mono text-slate-900">{selectedSteps}</span>
                <span className="text-xs text-slate-500 font-medium">steps</span>
              </div>
            </div>

            <div className="space-y-2">
              <input
                type="range"
                min={analysis.complexity.min_steps || 5}
                max={Math.max(50, analysis.complexity.max_steps_allowed || 40)}
                value={selectedSteps}
                onChange={(e) => setSelectedSteps(parseInt(e.target.value, 10))}
                className="w-full h-2 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-blue-600"
              />
              <div className="flex justify-between text-xs text-slate-400 font-mono">
                <span>Min: {analysis.complexity.min_steps || 5}</span>
                <span className="text-blue-600 font-semibold">Recommended: {analysis.complexity.recommended_steps}</span>
                <span>Max: {analysis.complexity.max_steps_allowed || 50}</span>
              </div>
            </div>

            <div className="pt-4 border-t border-slate-100 flex items-center justify-end space-x-3">
              <button
                onClick={onCancel}
                className="px-4 py-2 rounded-md border border-slate-300 text-slate-700 hover:bg-slate-50 text-sm font-medium transition"
              >
                Cancel
              </button>
              <button
                onClick={handleLaunch}
                disabled={launching}
                className="px-5 py-2 rounded-md bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold flex items-center space-x-2 transition shadow-sm disabled:opacity-50"
              >
                {launching ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin text-white" />
                    <span>Deploying Target Sandbox...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 fill-current" />
                    <span>Launch Audit</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default NewAuditView;
