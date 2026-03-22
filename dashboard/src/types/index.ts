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

// --- Intelligence Graph types ---

export type EntityType = 'person' | 'host' | 'domain' | 'credential' | 'email' | 'organization' | 'service' | 'network' | 'certificate'

export interface GraphEntity {
  id: string
  entity_type: EntityType
  name: string
  properties: Record<string, unknown>
  confidence: number
  sources: string[]
  campaign_id: string
  created_at: string
  updated_at: string
}

export interface GraphRelationship {
  id: string
  source_id: string
  target_id: string
  rel_type: string
  properties: Record<string, unknown>
  confidence: number
  sources: string[]
}

export interface GraphData {
  nodes: GraphEntity[]
  edges: GraphRelationship[]
  node_count: number
  edge_count: number
}

export interface SubjectProfile {
  id: string
  entity_id: string
  campaign_id: string
  emails: string[]
  social_accounts: Record<string, string>
  organizational_role: string
  department: string
  reporting_chain: string[]
  digital_footprint: Record<string, unknown>
  communication_style: string
  interests: string[]
  susceptibility_scores: Record<string, number>
  recommended_pretexts: Array<Record<string, unknown>>
  behavioral_predictions: Array<Record<string, unknown>>
  updated_at: string
}

export interface ScenarioResult {
  scenario_name: string
  attack_vector: string
  pretext: string
  success_rate: number
  avg_response_time: string
  common_failure_modes: string[]
  sample_interactions: Array<Record<string, unknown>>
  confidence_interval: [number, number]
}

export interface SimulationResult {
  id: string
  subject_id: string
  campaign_id: string
  scenarios: ScenarioResult[]
  overall_susceptibility: number
  best_approach: Record<string, unknown>
  report: string
  confidence: number
  simulated_at: string
}
