import React, { useEffect, useState, useRef, useCallback } from 'react';
import {
  ShieldCheck,
  Square,
  Lightbulb,
  ExternalLink,
  Layers,
  AlertCircle,
  Loader2,
  Radio
} from 'lucide-react';
import {
  AuditConfig,
  AuditEvent,
  EndpointSurface,
  AuditActivity,
  Finding
} from '../types/audit';
import {
  fetchAuditSurface,
  fetchAuditActivity,
  fetchAuditFindings,
  stopAudit
} from '../services/api';

interface ActiveAuditViewProps {
  auditId: string;
  onOpenEvidence: (finding: Finding) => void;
}

export const ActiveAuditView: React.FC<ActiveAuditViewProps> = ({ auditId, onOpenEvidence }) => {
  const [config, setConfig] = useState<AuditConfig | null>(null);
  const [status, setStatus] = useState<string>('INITIALIZING');
  const [currentStep, setCurrentStep] = useState<number>(0);
  const [maxSteps, setMaxSteps] = useState<number>(25);
  const [phase, setPhase] = useState<string>('INITIALIZING');
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [surface, setSurface] = useState<EndpointSurface[]>([]);
  const [surfaceFilter, setSurfaceFilter] = useState<string>('all');
  const [activity, setActivity] = useState<AuditActivity | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [stopping, setStopping] = useState<boolean>(false);
  const [sandboxStage, setSandboxStage] = useState<string>('Preparing isolated environment...');
  const [sandboxProgressPct, setSandboxProgressPct] = useState<number>(10);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const streamEndRef = useRef<HTMLDivElement>(null);

  // Incremental data synchronizer
  const refreshState = useCallback(async () => {
    try {
      const [surfData, actData, findData] = await Promise.all([
        fetchAuditSurface(auditId).catch(() => ({ endpoints: [] })),
        fetchAuditActivity(auditId).catch(() => null),
        fetchAuditFindings(auditId).catch(() => ({ findings: [] }))
      ]);
      setSurface(surfData.endpoints || []);
      if (actData) {
        setActivity(actData);
        if (actData.step) setCurrentStep(actData.step);
        if (actData.max_steps) setMaxSteps(actData.max_steps);
        if (actData.phase) setPhase(actData.phase);
      }
      setFindings(findData.findings || []);
    } catch (err) {
      console.error('Error refreshing audit state:', err);
    }
  }, [auditId]);

  useEffect(() => {
    // Immediate config load
    fetch(`/api/audits/${auditId}`)
      .then((res) => (res.ok ? res.json() : null))
      .then((cfg: AuditConfig | null) => {
        if (cfg) {
          setConfig(cfg);
          setMaxSteps(cfg.selected_steps || cfg.max_steps || 25);
          setStatus(cfg.status);
          if (cfg.phase) setPhase(cfg.phase);
        }
      })
      .catch((err) => console.error('Failed to load initial audit config:', err));

    refreshState();

    // SSE EventSource Connection
    const es = new EventSource(`/api/audits/${auditId}/events`);

    es.onmessage = (e) => {
      try {
        const ev: AuditEvent = JSON.parse(e.data);
        setEvents((prev) => [...prev, ev]);

        if (ev.event_type === 'AUDIT_STARTED') {
          setStatus('INITIALIZING');
        } else if (ev.event_type === 'STATUS_CHANGED') {
          if (ev.data.status) setStatus(ev.data.status);
          if (ev.data.status === 'RUNNING') setPhase('RECON');
        } else if (ev.event_type === 'SANDBOX_PROGRESS') {
          if (ev.data.detail || ev.summary) {
            setSandboxStage(ev.data.detail || ev.summary);
          }
          if (ev.data.progress_pct !== undefined) {
            setSandboxProgressPct(ev.data.progress_pct);
          }
        } else if (ev.event_type === 'SANDBOX_STARTED') {
          setSandboxStage('Sandbox ready. Target active.');
          setSandboxProgressPct(100);
        } else if (ev.event_type === 'PHASE_CHANGED') {
          setPhase(ev.data.to_phase || phase);
        } else if (ev.event_type === 'STEP_COMPLETED') {
          setCurrentStep(ev.data.step || currentStep);
          if (ev.data.max_steps) setMaxSteps(ev.data.max_steps);
        } else if (ev.event_type === 'ENDPOINT_DISCOVERED') {
          refreshState();
        } else if (ev.event_type === 'FINDING_CONFIRMED') {
          refreshState();
        } else if (ev.event_type === 'AUDIT_COMPLETED') {
          setStatus('COMPLETED');
          refreshState();
        } else if (ev.event_type === 'AUDIT_STOPPED') {
          setStatus('STOPPED');
          setStopping(false);
          refreshState();
        } else if (ev.event_type === 'AUDIT_FAILED') {
          setStatus('FAILED');
          setErrorMessage(ev.data.error || ev.summary || 'Audit execution failed');
        }
      } catch (err) {
        console.error('Error parsing SSE event:', err);
      }
    };

    es.onerror = () => {
      // EventSource reconnects automatically
    };

    return () => {
      es.close();
    };
  }, [auditId, refreshState, phase, currentStep]);

  // Auto-scroll event stream smoothly
  useEffect(() => {
    streamEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [events.length]);

  const handleStop = async () => {
    if (!window.confirm('Are you sure you want to stop this audit? Evidence collected so far will be saved.')) {
      return;
    }
    setStopping(true);
    try {
      await stopAudit(auditId);
    } catch (err: any) {
      alert('Error requesting audit stop: ' + (err.message || 'Unknown error'));
      setStopping(false);
    }
  };

  const progressPct = Math.min(100, Math.round((currentStep / Math.max(1, maxSteps)) * 100));

  const filteredSurface = surface.filter((ep) => {
    if (surfaceFilter === 'all') return true;
    return ep.status === surfaceFilter;
  });

  const auditTitle = config?.audit_name || 'Autonomous Security Audit';
  const targetName = config?.target_name || config?.project_name || 'Target Application';

  const isSandboxing = status === 'INITIALIZING' || status === 'SANDBOXING';

  return (
    <div className="space-y-6">
      {/* Top Header Card */}
      <div className="ui-panel p-6 bg-white border border-slate-200 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2 text-xs text-slate-500 mb-1">
            <Radio className="w-3.5 h-3.5 text-blue-600" />
            <span className="font-semibold uppercase tracking-wider">Live Monitor</span>
            <span>&bull;</span>
            <span className="font-mono text-slate-600">{auditId}</span>
          </div>
          <h1 className="text-xl font-bold text-slate-900">{auditTitle}</h1>
          <p className="text-xs text-slate-500 mt-1">
            Target: <strong className="text-slate-700 font-medium">{targetName}</strong>
            {config?.target_url && (
              <span className="ml-2 font-mono text-slate-400">({config.target_url})</span>
            )}
          </p>
        </div>

        <div className="flex items-center space-x-3 self-start md:self-auto">
          {/* Status Badge */}
          <div
            className={`px-3 py-1.5 rounded text-xs font-semibold flex items-center space-x-2 ${
              status === 'RUNNING'
                ? 'bg-blue-50 text-blue-700 border border-blue-200'
                : status === 'INITIALIZING' || status === 'SANDBOXING'
                ? 'bg-amber-50 text-amber-700 border border-amber-200'
                : status === 'COMPLETED'
                ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                : 'bg-slate-100 text-slate-700 border border-slate-200'
            }`}
          >
            {(status === 'RUNNING' || status === 'INITIALIZING' || status === 'SANDBOXING') && (
              <span className="w-2 h-2 rounded-full bg-blue-600 live-indicator" />
            )}
            <span>{status}</span>
          </div>

          {status === 'RUNNING' && (
            <button
              onClick={handleStop}
              disabled={stopping}
              className="px-3.5 py-1.5 rounded text-xs font-medium bg-red-50 hover:bg-red-100 text-red-700 border border-red-200 flex items-center space-x-1.5 transition disabled:opacity-50"
            >
              <Square className="w-3.5 h-3.5 fill-current" />
              <span>{stopping ? 'Stopping...' : 'Stop Audit'}</span>
            </button>
          )}
        </div>
      </div>

      {/* Error Banner if Failed */}
      {errorMessage && (
        <div className="p-4 rounded-md bg-red-50 border border-red-200 text-red-800 text-sm flex items-start space-x-3">
          <AlertCircle className="w-5 h-5 text-red-600 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <div className="font-bold text-red-900">Audit Launch Encountered an Error</div>
            <div className="text-xs text-red-700">{errorMessage}</div>
          </div>
        </div>
      )}

      {/* Asynchronous Sandbox Launch Progress Card */}
      {isSandboxing && (
        <div className="ui-panel p-6 bg-white border border-amber-200 shadow-sm space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Loader2 className="w-5 h-5 text-amber-600 animate-spin" />
              <div>
                <h3 className="text-sm font-bold text-slate-900">
                  Preparing Target Sandbox Environment
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">{sandboxStage}</p>
              </div>
            </div>
            <span className="text-xs font-bold font-mono text-amber-700">
              {sandboxProgressPct}%
            </span>
          </div>

          <div className="w-full bg-slate-100 h-2 rounded-full overflow-hidden">
            <div
              className="bg-amber-500 h-full rounded-full transition-all duration-300"
              style={{ width: `${sandboxProgressPct}%` }}
            />
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1 text-xs text-slate-500">
            <div className="flex items-center space-x-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
              <span>Analyzing build</span>
            </div>
            <div className="flex items-center space-x-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
              <span>Building target</span>
            </div>
            <div className="flex items-center space-x-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
              <span>Starting container</span>
            </div>
            <div className="flex items-center space-x-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
              <span>Checking health</span>
            </div>
          </div>
        </div>
      )}

      {/* Progress & Phase Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="ui-card p-4 bg-white border border-slate-200">
          <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1">
            Audit Progress
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-slate-900">
              {currentStep} / {maxSteps}
            </span>
            <span className="text-xs text-slate-500">steps ({progressPct}%)</span>
          </div>
          <div className="w-full bg-slate-100 h-2 rounded-full mt-2 overflow-hidden">
            <div
              className="bg-blue-600 h-full rounded-full transition-all duration-300"
              style={{ width: `${progressPct}%` }}
            />
          </div>
        </div>

        <div className="ui-card p-4 bg-white border border-slate-200">
          <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1">
            Current Phase
          </div>
          <div className="text-2xl font-bold text-slate-900 uppercase tracking-tight">
            {phase}
          </div>
          <p className="text-xs text-slate-500 mt-1">Autonomous reasoning cycle</p>
        </div>

        <div className="ui-card p-4 bg-white border border-slate-200">
          <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1">
            Confirmed Findings
          </div>
          <div className="text-2xl font-bold text-red-600 font-mono">
            {findings.length}
          </div>
          <p className="text-xs text-slate-500 mt-1">Empirically verified vulnerabilities</p>
        </div>
      </div>

      {/* AI Activity & Attack Surface Split */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: AI Reasoning Activity */}
        <div className="ui-panel bg-white border border-slate-200 flex flex-col h-[480px]">
          <div className="px-5 py-3.5 border-b border-slate-200 flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Lightbulb className="w-4 h-4 text-amber-600" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700">
                AI Cognitive Reasoning
              </h3>
            </div>
            <span className="text-xs text-slate-400">Step {currentStep}</span>
          </div>

          <div className="p-5 flex-1 overflow-y-auto space-y-4">
            {activity?.current_hypothesis ? (
              <div className="p-4 rounded-md bg-slate-50 border border-slate-200 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-blue-700 uppercase">
                    Active Hypothesis
                  </span>
                  <span className="text-xs font-mono text-slate-500">
                    {activity.current_hypothesis.category}
                  </span>
                </div>
                <p className="text-sm text-slate-800 font-medium">
                  {activity.current_hypothesis.description}
                </p>
                {activity.current_hypothesis.target_endpoint && (
                  <div className="text-xs text-slate-500 font-mono">
                    Target: {activity.current_hypothesis.target_endpoint}
                  </div>
                )}
              </div>
            ) : (
              <div className="p-4 rounded-md bg-slate-50 border border-slate-200 text-xs text-slate-500 text-center">
                {isSandboxing ? 'Sandbox initializing...' : 'Formulating next security hypothesis...'}
              </div>
            )}

            {activity?.last_tool && (
              <div className="space-y-1.5">
                <div className="text-xs font-semibold text-slate-700 uppercase tracking-wider">
                  Latest Action Executed
                </div>
                <div className="p-3 bg-slate-50 border border-slate-200 rounded text-xs space-y-1">
                  <div className="font-mono text-slate-800">
                    Tool: <strong className="text-blue-700">{activity.last_tool}</strong>
                  </div>
                  {activity.last_target && (
                    <div className="font-mono text-slate-600 truncate">
                      Target: {activity.last_target}
                    </div>
                  )}
                  {activity.last_summary && (
                    <div className="text-slate-600 mt-1">{activity.last_summary}</div>
                  )}
                </div>
              </div>
            )}

            {/* Event Timeline */}
            <div className="space-y-1.5">
              <div className="text-xs font-semibold text-slate-700 uppercase tracking-wider">
                Event Stream
              </div>
              <div className="space-y-2 font-mono text-xs">
                {events.slice(-15).map((ev, i) => (
                  <div key={i} className="p-2 rounded bg-slate-50 border border-slate-100 flex items-start space-x-2">
                    <span className="text-slate-400 text-[10px] shrink-0 mt-0.5">
                      {new Date(ev.timestamp).toLocaleTimeString()}
                    </span>
                    <span className="text-slate-700 flex-1">{ev.summary || ev.event_type}</span>
                  </div>
                ))}
                <div ref={streamEndRef} />
              </div>
            </div>
          </div>
        </div>

        {/* Right: Attack Surface & Discovered Endpoints */}
        <div className="ui-panel bg-white border border-slate-200 flex flex-col h-[480px]">
          <div className="px-5 py-3.5 border-b border-slate-200 flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Layers className="w-4 h-4 text-blue-600" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700">
                Attack Surface Surface ({surface.length})
              </h3>
            </div>

            <div className="flex items-center space-x-1 text-xs">
              {(['all', 'testing', 'tested', 'discovered'] as const).map((filter) => (
                <button
                  key={filter}
                  onClick={() => setSurfaceFilter(filter)}
                  className={`px-2 py-0.5 rounded capitalize transition ${
                    surfaceFilter === filter
                      ? 'bg-blue-600 text-white font-medium'
                      : 'text-slate-500 hover:text-slate-800 hover:bg-slate-100'
                  }`}
                >
                  {filter}
                </button>
              ))}
            </div>
          </div>

          <div className="p-4 flex-1 overflow-y-auto space-y-2">
            {filteredSurface.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-400">
                {isSandboxing ? 'Target sandbox initializing...' : 'No endpoints matching filter.'}
              </div>
            ) : (
              filteredSurface.map((ep, idx) => (
                <div
                  key={idx}
                  className="px-3 py-2 rounded bg-slate-50 border border-slate-200 flex items-center justify-between text-xs font-mono"
                >
                  <span className="text-slate-800 truncate mr-2">{ep.endpoint}</span>
                  <span
                    className={`px-2 py-0.5 rounded text-[11px] font-sans font-medium uppercase shrink-0 ${
                      ep.status === 'testing'
                        ? 'status-testing'
                        : ep.status === 'tested'
                        ? 'status-tested'
                        : ep.status === 'invalid'
                        ? 'status-invalid'
                        : 'status-discovered'
                    }`}
                  >
                    {ep.status}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Confirmed Vulnerability Findings Section */}
      <div className="ui-panel bg-white border border-slate-200">
        <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <ShieldCheck className="w-5 h-5 text-red-600" />
            <h3 className="text-sm font-bold text-slate-900 uppercase tracking-wider">
              Empirically Verified Security Findings ({findings.length})
            </h3>
          </div>
        </div>

        {findings.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-400">
            No security vulnerabilities confirmed yet. Testing is active.
          </div>
        ) : (
          <div className="divide-y divide-slate-100">
            {findings.map((f) => (
              <div key={f.id} className="p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4 hover:bg-slate-50 transition">
                <div className="space-y-1 flex-1">
                  <div className="flex items-center space-x-2">
                    <span
                      className={`text-xs px-2 py-0.5 rounded font-bold uppercase ${
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
                    <span className="font-bold text-slate-900 text-sm">{f.title}</span>
                  </div>

                  <p className="text-xs text-slate-600 line-clamp-2">{f.description}</p>

                  <div className="flex items-center space-x-4 text-xs text-slate-400 font-mono pt-1">
                    {f.affected_endpoint && <span>Endpoint: {f.affected_endpoint}</span>}
                    <span>Category: {f.category}</span>
                  </div>
                </div>

                <button
                  onClick={() => onOpenEvidence(f)}
                  className="px-3 py-1.5 rounded text-xs font-medium border border-slate-300 hover:border-slate-400 text-slate-700 bg-white shadow-sm flex items-center space-x-1 transition shrink-0"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                  <span>Inspect Evidence</span>
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default ActiveAuditView;
