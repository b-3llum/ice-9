import { api } from './client'
import type { GraphData, GraphEntity, GraphRelationship, SubjectProfile, SimulationResult } from '../types'

export const intelApi = {
  // Graph endpoints
  getGraph: (campaignId: string) =>
    api.get<GraphData>(`/campaigns/${campaignId}/graph`),

  getEntities: (campaignId: string, params?: {
    entity_type?: string
    search?: string
    min_confidence?: number
  }) => {
    const qs = new URLSearchParams()
    if (params?.entity_type) qs.set('entity_type', params.entity_type)
    if (params?.search) qs.set('search', params.search)
    if (params?.min_confidence) qs.set('min_confidence', String(params.min_confidence))
    const query = qs.toString()
    return api.get<GraphEntity[]>(`/campaigns/${campaignId}/graph/entities${query ? `?${query}` : ''}`)
  },

  getEntity: (campaignId: string, entityId: string) =>
    api.get<GraphEntity & { relationships: GraphRelationship[] }>(
      `/campaigns/${campaignId}/graph/entities/${entityId}`
    ),

  enrichEntity: (campaignId: string, entityId: string) =>
    api.post<GraphEntity>(`/campaigns/${campaignId}/graph/entities/${entityId}/enrich`),

  getRelationships: (campaignId: string, entityId?: string) => {
    const qs = entityId ? `?entity_id=${entityId}` : ''
    return api.get<GraphRelationship[]>(`/campaigns/${campaignId}/graph/relationships${qs}`)
  },

  extractEntities: (campaignId: string) =>
    api.post<{ entities_extracted: number; relationships_extracted: number }>(
      `/campaigns/${campaignId}/graph/extract`
    ),

  // Subject endpoints
  getSubjects: (campaignId: string) =>
    api.get<SubjectProfile[]>(`/campaigns/${campaignId}/subjects`),

  getSubject: (campaignId: string, subjectId: string) =>
    api.get<SubjectProfile & { entity: GraphEntity | null }>(
      `/campaigns/${campaignId}/subjects/${subjectId}`
    ),

  createProfile: (campaignId: string, entityId: string) =>
    api.post<SubjectProfile>(`/campaigns/${campaignId}/subjects/${entityId}/profile`),

  simulate: (campaignId: string, subjectId: string, params?: {
    num_simulations?: number
    scenarios?: string[]
  }) =>
    api.post<SimulationResult>(
      `/campaigns/${campaignId}/subjects/${subjectId}/simulate`,
      params || {}
    ),
}
