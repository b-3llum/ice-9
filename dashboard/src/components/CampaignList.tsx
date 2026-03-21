import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { campaignApi } from '../api/campaigns'
import { CampaignStatusBadge } from './StatusBadge'

export default function CampaignList() {
  const { data: campaigns, isLoading, error } = useQuery({
    queryKey: ['campaigns'],
    queryFn: () => campaignApi.list(),
  })

  if (isLoading) return <div className="text-gray-400">Loading campaigns...</div>
  if (error) return <div className="text-red-400">Error: {(error as Error).message}</div>

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Campaigns</h1>
      {!campaigns?.length ? (
        <p className="text-gray-500">No campaigns yet.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700 text-gray-400 text-left">
                <th className="py-2 pr-4">Name</th>
                <th className="py-2 pr-4">Status</th>
                <th className="py-2 pr-4">Scope</th>
                <th className="py-2 pr-4">Progress</th>
                <th className="py-2 pr-4">Findings</th>
                <th className="py-2">Created</th>
              </tr>
            </thead>
            <tbody>
              {campaigns.map((c) => (
                <tr key={c.id} className="border-b border-gray-800 hover:bg-gray-800/50">
                  <td className="py-3 pr-4">
                    <Link to={`/campaigns/${c.id}`} className="text-blue-400 hover:underline font-medium">
                      {c.name}
                    </Link>
                    <span className="text-gray-600 text-xs ml-2">{c.id.slice(0, 8)}</span>
                  </td>
                  <td className="py-3 pr-4">
                    <CampaignStatusBadge status={c.status} />
                  </td>
                  <td className="py-3 pr-4 text-gray-400 max-w-xs truncate">
                    {c.scope.join(', ') || '—'}
                  </td>
                  <td className="py-3 pr-4">
                    <div className="flex items-center gap-2">
                      <div className="w-24 bg-gray-700 rounded-full h-2">
                        <div
                          className="bg-green-500 h-2 rounded-full"
                          style={{ width: `${c.progress.progress_pct}%` }}
                        />
                      </div>
                      <span className="text-gray-400 text-xs">{c.progress.progress_pct}%</span>
                    </div>
                  </td>
                  <td className="py-3 pr-4 text-gray-300">{c.finding_count}</td>
                  <td className="py-3 text-gray-500 text-xs">
                    {new Date(c.created_at).toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
