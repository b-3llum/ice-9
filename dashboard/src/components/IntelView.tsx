import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { campaignApi } from '../api/campaigns'
import { intelApi } from '../api/intel'
import IntelGraph from './graph/IntelGraph'
import SubjectProfileComponent from './subjects/SubjectProfile'
import type { SubjectProfile } from '../types'

export default function IntelView() {
  const { id } = useParams<{ id: string }>()
  const queryClient = useQueryClient()
  const [selectedSubject, setSelectedSubject] = useState<SubjectProfile | null>(null)

  const { data: campaign } = useQuery({
    queryKey: ['campaign', id],
    queryFn: () => campaignApi.get(id!),
    enabled: !!id,
  })

  const { data: subjects } = useQuery({
    queryKey: ['subjects', id],
    queryFn: () => intelApi.getSubjects(id!),
    enabled: !!id,
    refetchInterval: 15000,
  })

  const extractMutation = useMutation({
    mutationFn: () => intelApi.extractEntities(id!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['graph', id] })
    },
  })

  if (!id) return <div className="text-gray-400">No campaign selected.</div>

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-2xl font-bold">Intelligence Graph</h1>
          {campaign && (
            <span className="text-gray-500 text-sm">{campaign.name}</span>
          )}
        </div>
        <button
          onClick={() => extractMutation.mutate()}
          disabled={extractMutation.isPending}
          className="bg-gray-700 hover:bg-gray-600 disabled:opacity-50 text-gray-200 text-sm px-4 py-2 rounded"
        >
          {extractMutation.isPending ? 'Extracting...' : 'Extract Entities'}
        </button>
      </div>

      {extractMutation.isSuccess && extractMutation.data && (
        <div className="bg-green-900/20 border border-green-800 rounded px-4 py-2 mb-4 text-sm text-green-300">
          Extracted {extractMutation.data.entities_extracted} entities and{' '}
          {extractMutation.data.relationships_extracted} relationships.
        </div>
      )}

      <IntelGraph campaignId={id} />

      {/* Subject profiles section */}
      {subjects && subjects.length > 0 && (
        <div className="mt-8">
          <h2 className="text-lg font-semibold mb-4">Subject Profiles</h2>
          <div className="grid grid-cols-3 gap-4 mb-4">
            {subjects.map(subject => (
              <button
                key={subject.id}
                onClick={() => setSelectedSubject(subject)}
                className={`text-left bg-ice-900 rounded-lg p-4 border transition-colors ${
                  selectedSubject?.id === subject.id
                    ? 'border-blue-500'
                    : 'border-gray-700 hover:border-gray-500'
                }`}
              >
                <div className="font-medium text-gray-200">
                  {subject.organizational_role || 'Unknown'}
                </div>
                <div className="text-gray-500 text-xs mt-0.5">
                  {subject.department || 'No department'}
                </div>
                <div className="text-gray-500 text-xs mt-1">
                  {subject.emails.length} email(s)
                  {Object.keys(subject.susceptibility_scores).length > 0 && (
                    <> · SE scored</>
                  )}
                </div>
              </button>
            ))}
          </div>

          {selectedSubject && (
            <SubjectProfileComponent
              campaignId={id}
              profile={selectedSubject}
            />
          )}
        </div>
      )}
    </div>
  )
}
