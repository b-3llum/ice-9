import { api } from './client'
import type { Campaign, CampaignDetail, Finding, Task, ToolInfo, AgentInfo, ProviderInfo, AgentResult } from '../types'

export const campaignApi = {
  list: (status?: string) =>
    api.get<Campaign[]>(`/campaigns${status ? `?status=${status}` : ''}`),

  get: (id: string) =>
    api.get<CampaignDetail>(`/campaigns/${id}`),

  create: (data: { name: string; scope: string[]; description?: string }) =>
    api.post<Campaign>('/campaigns', data),

  transition: (id: string, status: string) =>
    api.put<Campaign>(`/campaigns/${id}/status`, { status }),

  delete: (id: string) =>
    api.delete<{ deleted: boolean }>(`/campaigns/${id}`),

  getFindings: (id: string) =>
    api.get<Finding[]>(`/campaigns/${id}/findings`),

  getPhaseTask: (campaignId: string, phaseType: string) =>
    api.get<Task[]>(`/campaigns/${campaignId}/phases/${phaseType}/tasks`),

  getPhaseFindings: (campaignId: string, phaseType: string) =>
    api.get<Finding[]>(`/campaigns/${campaignId}/phases/${phaseType}/findings`),

  // AI endpoints
  aiPlan: (id: string) =>
    api.post<{ plan: string }>(`/campaigns/${id}/ai/plan`),

  aiAnalyze: (id: string) =>
    api.post<{ results: AgentResult[]; synthesis: string }>(`/campaigns/${id}/ai/analyze`),

  aiAsk: (id: string, prompt: string, agent = 'coordinator') =>
    api.post<AgentResult>(`/campaigns/${id}/ai/ask`, { prompt, agent }),

  aiAuto: (id: string, maxPhases = 5) =>
    api.post<{
      phases_executed: string[]
      phases_skipped: string[]
      total_findings: number
      ai_plan: string
      ai_synthesis: string
      stopped_reason: string
    }>(`/campaigns/${id}/ai/auto`, { max_phases: maxPhases }),

  // Phase run endpoint (runs in API process for live events)
  runPhase: (id: string, phaseType: string) =>
    api.post<{ status: string; message: string; phase_type: string }>(
      `/campaigns/${id}/phases/${phaseType}/run`
    ),

  getRunningPhase: (id: string) =>
    api.get<{ running: string | null }>(`/campaigns/${id}/phases/running`),
}

export const toolApi = {
  list: () => api.get<ToolInfo[]>('/tools'),
}

export const aiApi = {
  agents: () => api.get<AgentInfo[]>('/ai/agents'),
  providers: () => api.get<ProviderInfo[]>('/ai/providers'),
}
