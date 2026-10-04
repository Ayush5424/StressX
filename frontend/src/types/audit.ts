export type ComplexityLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'VERY_HIGH';

export type AuditStatus = 
  | 'CONFIGURED' 
  | 'INITIALIZING' 
  | 'SANDBOXING' 
  | 'RUNNING' 
  | 'PAUSED' 
  | 'STOPPING' 
  | 'STOPPED' 
  | 'COMPLETED' 
  | 'FAILED';

export type AuditPhase = 
  | 'RECON' 
  | 'HYPOTHESIS' 
  | 'TEST' 
  | 'OBSERVE' 
  | 'VERIFY' 
  | 'EVIDENCE' 
  | 'COMPLETE';

export type AuditEventType = 
  | 'AUDIT_STARTED'
  | 'PROJECT_ANALYZED'
  | 'COMPLEXITY_CALCULATED'
  | 'SANDBOX_STARTED'
  | 'ENDPOINT_DISCOVERED'
  | 'HYPOTHESIS_CREATED'
  | 'TOOL_STARTED'
  | 'TOOL_COMPLETED'
  | 'OBSERVATION_CREATED'
  | 'FINDING_CONFIRMED'
  | 'FINDING_UPDATED'
  | 'PHASE_CHANGED'
  | 'STEP_COMPLETED'
  | 'AUDIT_COMPLETED'
  | 'AUDIT_STOPPED'
  | 'AUDIT_FAILED'
  | 'STATUS_CHANGED'
  | 'SANDBOX_PROGRESS'
  | 'SANDBOX_CLEANED';

export interface TargetComplexity {
  level: ComplexityLevel;
  score: number;
  recommended_steps: number;
  min_steps: number;
  max_steps_allowed: number;
  endpoints_estimated: number;
  mutation_routes_estimated: number;
  controllers_count: number;
  services_count: number;
  workers_count: number;
  databases_detected: string[];
  caches_detected: string[];
  queues_detected: string[];
  has_compose: boolean;
  has_auth_surface: boolean;
  has_operator_surface: boolean;
  reasons: string[];
}

export interface ProjectAnalysis {
  name: string;
  path: string;
  type: string;
  framework?: string;
  build_tool?: string;
  detected_port?: number;
  is_multi_service: boolean;
  services: string[];
  primary_service?: string;
  dockerfile: boolean;
  compose_file: boolean;
  service_types?: Record<string, string>;
}

export interface AnalyzeProjectResponse {
  project: ProjectAnalysis;
  complexity: TargetComplexity;
}

export interface AuditConfig {
  audit_id: string;
  audit_name: string;
  target_name?: string;
  target_path: string;
  target_url?: string;
  project_name: string;
  complexity?: TargetComplexity;
  recommended_steps: number;
  selected_steps: number;
  max_steps: number;
  step_budget?: number;
  steps_completed?: number;
  status: AuditStatus;
  phase?: AuditPhase;
  created_at?: string;
  started_at?: string;
  completed_at?: string;
  duration?: string;
  duration_seconds?: number;
  findings_count?: number;
  highest_severity?: string;
  severity_breakdown?: Record<string, number>;
}

export interface AuditEvent {
  audit_id: string;
  event_type: AuditEventType;
  timestamp: string;
  data: Record<string, any>;
  summary: string;
}

export interface EvidenceItem {
  id: string;
  description: string;
  endpoint?: string;
  method?: string;
  status_code?: number;
  curl_command?: string;
  observed_behavior?: string;
  response_body_preview?: string;
  causal_chain?: string[];
  verified: boolean;
}

export interface Finding {
  id: string;
  title: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  affected_endpoint?: string;
  description: string;
  impact?: string;
  remediation?: string;
  causal_chain?: string[];
  reproduction_steps?: string[] | { curl_command?: string };
  evidence?: EvidenceItem[];
  evidence_count?: number;
}

export interface EndpointSurface {
  endpoint: string;
  status: 'discovered' | 'testing' | 'tested' | 'invalid';
  method?: string;
  last_tested?: string;
}

export interface SurfaceResponse {
  audit_id: string;
  total: number;
  discovered_count: number;
  testing_count: number;
  tested_count: number;
  invalid_count: number;
  endpoints: EndpointSurface[];
}

export interface AuditActivity {
  active: boolean;
  audit_id: string;
  step: number;
  max_steps: number;
  phase: AuditPhase;
  current_hypothesis?: {
    id: string;
    category: string;
    target_endpoint?: string;
    description: string;
    confidence: string;
    status: string;
    security_question?: string;
  };
  last_tool?: string;
  last_target?: string;
  last_summary?: string;
  insights?: string[];
  repetition_prevented?: number;
  total_hypotheses?: number;
  total_findings?: number;
}

export interface ActionRecord {
  step: number;
  tool: string;
  method?: string;
  target?: string;
  status_code?: number;
  latency_ms?: number;
  outcome: string;
  summary?: string;
}

export interface ReportSummary {
  audit_id: string;
  audit_name: string;
  target_name?: string;
  timestamp: string | number;
  target: string;
  status: string;
  total_steps: number;
  duration?: string;
  duration_seconds: number;
  findings_count: number;
  critical_count: number;
  high_count: number;
  medium_count?: number;
  low_count?: number;
  highest_severity?: string;
  has_markdown: boolean;
}

export interface ReportDossier {
  audit_id: string;
  audit_name?: string;
  target_name?: string;
  duration?: string;
  status?: string;
  report?: any;
  metrics?: any;
  findings?: Finding[];
  evidence?: any;
  actions?: ActionRecord[];
  markdown?: string;
}

export interface GlobalStats {
  active_audits: number;
  total_audits: number;
  total_findings: number;
  critical_findings: number;
  unique_projects_tested: number;
}
