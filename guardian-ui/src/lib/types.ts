export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "SAFE";
export type Verdict = "SAFE" | "UNSAFE";
export type RuntimeStatus =
  | "BLOCKED"
  | "ALERT"
  | "CONTENT_RISK"
  | "CAPABILITY_RISK"
  | "TIMEOUT"
  | "ERROR"
  | "INCOMPLETE"
  | "PASSED";

export interface StaticFinding {
  rule_id: string;
  title: string;
  severity: Severity;
  file_path: string;
  line_number: number;
  description: string;
  snippet?: string;
}

export interface SkillPrescanResult {
  skill_name: string;
  skill_path: string;
  findings: StaticFinding[];
  findings_count: number;
  max_severity: Severity;
  is_safe: boolean;
  analyzers_used: string[];
  scan_duration: number;
  safety_confidence: number;
  safety_verdict: Verdict;
  llm_reason: string;
}

export interface RuntimeResult {
  skill: string;
  folder: string;
  status: RuntimeStatus;
  elapsed_sec: number;
  blacklist_hits: number;
  blocks: number;
  content_risks: number;
  capability_indicators: string[];
  agent_crashed: boolean;
  retries_used: number;
  early_stopped: boolean;
  low_risk_alert: boolean;
  details: string[];
  log_lines: LogLine[];
}

export interface LogLine {
  timestamp: string;
  level: "info" | "warn" | "error" | "guardian" | "system";
  content: string;
}

export interface RemediationSuggestion {
  skill_name: string;
  finding_title: string;
  severity: Severity;
  description: string;
  code_before: string;
  code_after: string;
  explanation: string;
}

export type StageStatus = "pending" | "running" | "completed" | "error";

export interface PipelineState {
  stage1: StageStatus;
  stage2: StageStatus;
  stage3: StageStatus;
  prescan_results: Record<string, SkillPrescanResult>;
  runtime_results: RuntimeResult[];
  verify_results: RuntimeResult[];
  remediations: RemediationSuggestion[];
}