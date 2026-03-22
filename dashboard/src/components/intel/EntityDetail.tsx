import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { intelApi } from '../../api/intel'
import type { GraphEntity } from '../../types'
import RelationshipList from './RelationshipList'

interface Props {
  campaignId: string
  entity: GraphEntity
  onClose: () => void
}

export default function EntityDetail({ campaignId, entity, onClose }: Props) {
  const queryClient = useQueryClient()

  const { data: detail } = useQuery({
    queryKey: ['entity', campaignId, entity.id],
    queryFn: () => intelApi.getEntity(campaignId, entity.id),
  })

  const enrichMutation = useMutation({
    mutationFn: () => intelApi.enrichEntity(campaignId, entity.id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['entity', campaignId, entity.id] })
      queryClient.invalidateQueries({ queryKey: ['graph', campaignId] })
    },
  })

  const profileMutation = useMutation({
    mutationFn: () => intelApi.createProfile(campaignId, entity.id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['subjects', campaignId] })
    },
  })

  return (
    <div className="fixed right-0 top-0 h-full w-96 bg-gray-900 border-l border-gray-700 shadow-xl z-40 overflow-y-auto">
      <div className="p-4">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-100">{entity.name}</h3>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white text-xl leading-none"
          >
            &times;
          </button>
        </div>

        <div className="space-y-4">
          <div>
            <span className="text-xs uppercase text-gray-500">Type</span>
            <div className="text-gray-200 capitalize">{entity.entity_type}</div>
          </div>

          <div>
            <span className="text-xs uppercase text-gray-500">Confidence</span>
            <div className="flex items-center gap-2">
              <div className="flex-1 bg-gray-700 rounded-full h-2">
                <div
                  className="bg-blue-500 rounded-full h-2"
                  style={{ width: `${entity.confidence * 100}%` }}
                />
              </div>
              <span className="text-gray-300 text-sm">
                {Math.round(entity.confidence * 100)}%
              </span>
            </div>
          </div>

          <div>
            <span className="text-xs uppercase text-gray-500">Sources</span>
            <div className="flex gap-1 mt-1 flex-wrap">
              {entity.sources.map(s => (
                <span key={s} className="bg-gray-700 text-gray-300 text-xs px-2 py-0.5 rounded">
                  {s}
                </span>
              ))}
            </div>
          </div>

          {Object.keys(entity.properties).length > 0 && (
            <div>
              <span className="text-xs uppercase text-gray-500">Properties</span>
              <div className="bg-gray-800 rounded p-2 mt-1 text-xs text-gray-300 space-y-1">
                {Object.entries(entity.properties).map(([k, v]) => (
                  <div key={k} className="flex justify-between">
                    <span className="text-gray-500">{k}</span>
                    <span className="text-gray-200 truncate ml-2 max-w-48">
                      {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="flex gap-2 pt-2">
            <button
              onClick={() => enrichMutation.mutate()}
              disabled={enrichMutation.isPending}
              className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm px-3 py-1.5 rounded"
            >
              {enrichMutation.isPending ? 'Enriching...' : 'Enrich'}
            </button>
            {entity.entity_type === 'person' && (
              <button
                onClick={() => profileMutation.mutate()}
                disabled={profileMutation.isPending}
                className="bg-purple-600 hover:bg-purple-700 disabled:opacity-50 text-white text-sm px-3 py-1.5 rounded"
              >
                {profileMutation.isPending ? 'Profiling...' : 'Create Profile'}
              </button>
            )}
          </div>

          {detail?.relationships && detail.relationships.length > 0 && (
            <RelationshipList relationships={detail.relationships} />
          )}
        </div>
      </div>
    </div>
  )
}
