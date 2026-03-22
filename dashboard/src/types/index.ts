export type CampaignStatus = 'planning' | 'active' | 'paused' | 'completed' | 'aborted'
export type PhaseStatus = 'pending' | 'in_progress' | 'completed' | 'skipped'
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface Campaign {
  id: string
  name: string
  status: CampaignStatus
  scope: string[]
  progress: CampaignProgress
  phase_count: number
  finding_count: number
  created_at: string
  updated_at: string
}

export interface CampaignDetail extends Campaign {
  phases: Phase[]
  rules_of_engagement: RulesOfEngagement
}

export interface CampaignProgress {
  total_phases: number
  completed: number
  in_progress: number
  pending: number
  skipped: number
  progress_pct: number
  findings: number
}

export interface Phase {
  id: string
  type: string
  name: string
  status: PhaseStatus
  tasks: number
  findings: number
}

export interface Finding {
  id: string
  title: string
  severity: Severity
  cvss: number | null
  cve_ids: string[]
  att_ck_ids: string[]
  description: string
  remediation: string
}

export interface Task {
  id: string
  tool: string
  target: string
  status: string
  att_ck_id: string | null
  started_at: string | null
  completed_at: string | null
}

export interface ToolInfo {
  name: string
  description: string
  binary: string
  available: boolean
  binary_path: string | null
  att_ck_ids: string[]
}

export interface AgentInfo {
  role: string
  provider: string
  model: string | null
  enabled: boolean
}

export interface ProviderInfo {
  name: string
  type: string
  model: string
  has_api_key: boolean
  enabled: boolean
}

export interface AgentResult {
  agent: string
  content: string
  model: string
  provider: string
  success: boolean
  error?: string
}

export interface RulesOfEngagement {
  scope: string[]
  exclusions: string[]
  testing_window: string | null
  max_severity: Severity
  notes: string
}
