import { useQuery } from '@tanstack/react-query'
import { aiApi } from '../api/campaigns'

export default function AIPanel() {
  const { data: agents, isLoading: agentsLoading } = useQuery({
    queryKey: ['ai-agents'],
    queryFn: () => aiApi.agents(),
  })

  const { data: providers, isLoading: providersLoading } = useQuery({
    queryKey: ['ai-providers'],
    queryFn: () => aiApi.providers(),
  })

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">AI Agent Team</h1>

      <div className="grid grid-cols-2 gap-6">
        <div>
          <h2 className="text-lg font-semibold mb-3">Agents</h2>
          {agentsLoading ? (
            <p className="text-gray-400">Loading...</p>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700 text-gray-400 text-left">
                  <th className="py-2 pr-4">Role</th>
                  <th className="py-2 pr-4">Provider</th>
                  <th className="py-2 pr-4">Model</th>
                  <th className="py-2">Status</th>
                </tr>
              </thead>
              <tbody>
                {agents?.map((a) => (
                  <tr key={a.role} className="border-b border-gray-800">
                    <td className="py-2 pr-4 font-medium text-cyan-400 capitalize">
                      {a.role.replace('_', ' ')}
                    </td>
                    <td className="py-2 pr-4 text-gray-400">{a.provider}</td>
                    <td className="py-2 pr-4 text-gray-500 text-xs font-mono">
                      {a.model || 'default'}
                    </td>
                    <td className="py-2">
                      {a.enabled ? (
                        <span className="text-green-400 text-xs">enabled</span>
                      ) : (
                        <span className="text-red-400 text-xs">disabled</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div>
          <h2 className="text-lg font-semibold mb-3">LLM Providers</h2>
          {providersLoading ? (
            <p className="text-gray-400">Loading...</p>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700 text-gray-400 text-left">
                  <th className="py-2 pr-4">Provider</th>
                  <th className="py-2 pr-4">Type</th>
                  <th className="py-2 pr-4">Model</th>
                  <th className="py-2 pr-4">API Key</th>
                  <th className="py-2">Status</th>
                </tr>
              </thead>
              <tbody>
                {providers?.map((p) => (
                  <tr key={p.name} className="border-b border-gray-800">
                    <td className="py-2 pr-4 font-medium text-blue-400">{p.name}</td>
                    <td className="py-2 pr-4 text-gray-400">{p.type}</td>
                    <td className="py-2 pr-4 text-gray-500 text-xs font-mono">{p.model || '—'}</td>
                    <td className="py-2 pr-4">
                      {p.has_api_key ? (
                        <span className="text-green-400 text-xs">configured</span>
                      ) : (
                        <span className="text-yellow-400 text-xs">missing</span>
                      )}
                    </td>
                    <td className="py-2">
                      {p.enabled ? (
                        <span className="text-green-400 text-xs">enabled</span>
                      ) : (
                        <span className="text-red-400 text-xs">disabled</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  )
}
