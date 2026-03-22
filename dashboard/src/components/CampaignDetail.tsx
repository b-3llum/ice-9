import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { campaignApi } from '../api/campaigns'
import { CampaignStatusBadge } from './StatusBadge'
import PhaseTimeline from './PhaseTimeline'
import FindingsTable from './FindingsTable'
import AIChat from './AIChat'
import ActivityFeed from './ActivityFeed'

export default function CampaignDetail() {
  const { id } = useParams<{ id: string }>()

  const { data: campaign, isLoading } = useQuery({
    queryKey: ['campaign', id],
    queryFn: () => campaignApi.get(id!),
    enabled: !!id,
    refetchInterval: 5000,
  })

  const { data: findings } = useQuery({
    queryKey: ['findings', id],
    queryFn: () => campaignApi.getFindings(id!),
    enabled: !!id,
    refetchInterval: 10000,
  })

  if (isLoading || !campaign) return <div className="text-gray-400">Loading...</div>

  return (
    <div>
      <div className="flex items-center gap-4 mb-6">
        <h1 className="text-2xl font-bold">{campaign.name}</h1>
        <CampaignStatusBadge status={campaign.status} />
        <span className="text-gray-500 text-sm">{campaign.id.slice(0, 8)}</span>
        <Link
          to={`/campaigns/${campaign.id}/intel`}
          className="ml-auto bg-gray-700 hover:bg-gray-600 text-gray-200 text-sm px-4 py-1.5 rounded"
        >
          Intel Graph
        </Link>
      </div>

      <div className="grid grid-cols-4 gap-4 mb-6">
        <div className="bg-ice-900 rounded p-4">
          <div className="text-gray-400 text-xs uppercase">Progress</div>
          <div className="text-2xl font-bold">{campaign.progress.progress_pct}%</div>
          <div className="text-gray-500 text-xs">
            {campaign.progress.completed}/{campaign.progress.total_phases} phases
          </div>
        </div>
        <div className="bg-ice-900 rounded p-4">
          <div className="text-gray-400 text-xs uppercase">Findings</div>
          <div className="text-2xl font-bold">{campaign.finding_count}</div>
        </div>
        <div className="bg-ice-900 rounded p-4">
          <div className="text-gray-400 text-xs uppercase">Scope</div>
          <div className="text-sm text-gray-300 mt-1">{campaign.scope.join(', ') || '—'}</div>
        </div>
        <div className="bg-ice-900 rounded p-4">
          <div className="text-gray-400 text-xs uppercase">Created</div>
          <div className="text-sm text-gray-300 mt-1">
            {new Date(campaign.created_at).toLocaleString()}
          </div>
        </div>
      </div>

      <PhaseTimeline phases={campaign.phases} campaignId={campaign.id} />

      <div className="mt-6 mb-6">
        <h2 className="text-lg font-semibold mb-2">Live Activity</h2>
        <ActivityFeed campaignId={campaign.id} />
      </div>

      {findings && <FindingsTable findings={findings} />}

      <div className="mt-8">
        <AIChat campaignId={campaign.id} />
      </div>
    </div>
  )
}
