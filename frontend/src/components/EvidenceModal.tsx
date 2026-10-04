import React, { useState } from 'react';
import { X, Copy, Check } from 'lucide-react';
import { Finding } from '../types/audit';

interface EvidenceModalProps {
  finding: Finding | null;
  onClose: () => void;
}

export const EvidenceModal: React.FC<EvidenceModalProps> = ({ finding, onClose }) => {
  const [copied, setCopied] = useState(false);

  if (!finding) return null;

  // Resolve curl reproduction command
  let curlCmd = '';
  if (Array.isArray(finding.reproduction_steps) && finding.reproduction_steps.length > 0) {
    curlCmd = finding.reproduction_steps[0];
  } else if (
    finding.reproduction_steps &&
    typeof finding.reproduction_steps === 'object' &&
    'curl_command' in finding.reproduction_steps
  ) {
    curlCmd = (finding.reproduction_steps as any).curl_command || '';
  }
  if (!curlCmd && finding.evidence && finding.evidence.length > 0) {
    curlCmd = finding.evidence[0].curl_command || '';
  }
  if (!curlCmd) {
    curlCmd = `curl -i '${finding.affected_endpoint || 'http://127.0.0.1:8080'}'`;
  }

  const handleCopy = () => {
    navigator.clipboard.writeText(curlCmd).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-sm">
      <div className="bg-white border border-slate-200 rounded-2xl max-w-3xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="p-5 border-b border-slate-200 flex items-center justify-between bg-slate-50/70">
          <div className="flex items-center space-x-3">
            <span
              className={`px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider ${
                finding.severity === 'CRITICAL'
                  ? 'badge-critical'
                  : finding.severity === 'HIGH'
                  ? 'badge-high'
                  : finding.severity === 'MEDIUM'
                  ? 'badge-medium'
                  : 'badge-low'
              }`}
            >
              {finding.severity}
            </span>
            <h3 className="text-base font-bold text-slate-900">{finding.title}</h3>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-600 p-1.5 rounded-lg hover:bg-slate-100 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-5 text-xs text-slate-700">
          {/* Endpoint & Category */}
          <div className="grid grid-cols-2 gap-3 font-mono">
            <div className="bg-slate-50 p-3 rounded-lg border border-slate-200">
              <span className="text-slate-400 block text-[10px] uppercase font-sans font-bold">Affected Endpoint</span>
              <span className="text-blue-600 font-semibold text-sm">
                {finding.affected_endpoint || '/'}
              </span>
            </div>
            <div className="bg-slate-50 p-3 rounded-lg border border-slate-200">
              <span className="text-slate-400 block text-[10px] uppercase font-sans font-bold">Category</span>
              <span className="text-slate-800 font-semibold text-sm">{finding.category}</span>
            </div>
          </div>

          {/* Description */}
          <div>
            <span className="font-semibold text-slate-500 uppercase tracking-wider block mb-1 text-[11px]">
              Description
            </span>
            <p className="text-slate-700 leading-relaxed font-sans text-sm">{finding.description}</p>
          </div>

          {/* Causal Chain */}
          {finding.causal_chain && finding.causal_chain.length > 0 && (
            <div>
              <span className="font-semibold text-slate-500 uppercase tracking-wider block mb-2 text-[11px]">
                Causal Chain & Failure Mechanism
              </span>
              <div className="space-y-1.5 pl-2 font-mono">
                {finding.causal_chain.map((c, i) => (
                  <div key={i} className="flex items-start space-x-2 text-slate-700">
                    <span className="text-blue-600 font-bold">{i + 1}.</span>
                    <span>{c}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Reproduction Command */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <span className="font-semibold text-slate-500 uppercase tracking-wider text-[11px]">
                Reproducible Verification Command
              </span>
              <button
                onClick={handleCopy}
                className="text-blue-600 hover:text-blue-700 font-mono text-[11px] flex items-center space-x-1"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied!' : 'Copy cURL'}</span>
              </button>
            </div>
            <pre className="p-3 bg-slate-900 border border-slate-800 rounded-lg text-emerald-400 font-mono text-xs overflow-x-auto select-all">
              {curlCmd}
            </pre>
          </div>

          {/* Observed Empirical Evidence */}
          <div>
            <span className="font-semibold text-slate-500 uppercase tracking-wider block mb-1.5 text-[11px]">
              Observed Empirical HTTP Evidence
            </span>
            <div className="space-y-3 font-mono">
              {finding.evidence && finding.evidence.length > 0 ? (
                finding.evidence.map((ev, i) => (
                  <div key={i} className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-2">
                    <div className="flex justify-between text-slate-600 text-[11px]">
                      <span className="font-semibold">
                        {ev.method || 'GET'} {ev.endpoint || ''}
                      </span>
                      <span className="text-blue-600 font-bold">Status: {ev.status_code || 200}</span>
                    </div>
                    {ev.observed_behavior && (
                      <p className="text-slate-700 text-xs font-sans">{ev.observed_behavior}</p>
                    )}
                    {ev.response_body_preview && (
                      <pre className="p-2 bg-slate-900 rounded border border-slate-800 text-[11px] text-amber-300 max-h-32 overflow-y-auto">
                        {ev.response_body_preview}
                      </pre>
                    )}
                  </div>
                ))
              ) : (
                <div className="text-slate-500 font-sans">Verified via runtime empirical test assertions.</div>
              )}
            </div>
          </div>

          {/* Remediation */}
          <div className="bg-emerald-50 border border-emerald-200 p-4 rounded-xl space-y-1">
            <span className="font-semibold text-emerald-800 uppercase tracking-wider text-[11px]">
              Recommended Remediation
            </span>
            <p className="text-slate-700 leading-relaxed font-sans text-xs">
              {finding.remediation || 'Inspect endpoint handling and enforce strict boundary validation.'}
            </p>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-slate-200 bg-slate-50 flex justify-end">
          <button
            onClick={onClose}
            className="px-5 py-2 rounded-lg bg-slate-200 hover:bg-slate-300 text-slate-800 font-medium text-xs transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
