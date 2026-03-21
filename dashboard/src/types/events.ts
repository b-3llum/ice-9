export type EventType =
  | 'tool_start'
  | 'tool_output'
  | 'tool_complete'
  | 'tool_error'
  | 'phase_start'
  | 'phase_plan'
  | 'phase_task_start'
  | 'phase_task_complete'
  | 'phase_complete'
  | 'ai_request'
  | 'ai_chunk'
  | 'ai_response'
  | 'auto_phase_select'
  | 'auto_complete'
  | 'finding_new'

export interface Ice9Event {
  type: EventType
  timestamp: string
  campaign_id: string | null
  phase_id: string | null
  data: Record<string, unknown>
}
