import { useQuery } from '@tanstack/react-query'
import { toolApi } from '../api/campaigns'

export default function ToolsList() {
  const { data: tools, isLoading } = useQuery({
    queryKey: ['tools'],
    queryFn: () => toolApi.list(),
  })

  if (isLoading) return <div className="text-gray-400">Loading tools...</div>

  const available = tools?.filter((t) => t.available) ?? []
  const missing = tools?.filter((t) => !t.available) ?? []

  return (
    <div>
      <h1 className="text-2xl font-bold mb-4">Registered Tools</h1>
      <div className="mb-4 flex gap-4 text-sm">
        <span className="text-green-400">{available.length} available</span>
        <span className="text-red-400">{missing.length} missing</span>
      </div>

      {missing.length > 0 && missing.length === (tools?.length ?? 0) && (
        <div className="mb-4 p-3 rounded border border-yellow-700 bg-yellow-900/20 text-yellow-300 text-sm">
          All tools are missing. The API server's <code className="bg-gray-800 px-1 rounded">$PATH</code> may
          not include your tool directories. Add <code className="bg-gray-800 px-1 rounded">tool_paths</code> to{' '}
          <code className="bg-gray-800 px-1 rounded">ice9.yaml</code> or restart the API from a shell with the
          correct environment.
        </div>
      )}

      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-gray-700 text-gray-400 text-left">
            <th className="py-2 pr-4">Name</th>
            <th className="py-2 pr-4">Binary</th>
            <th className="py-2 pr-4">Status</th>
            <th className="py-2 pr-4">ATT&CK IDs</th>
            <th className="py-2">Description</th>
          </tr>
        </thead>
        <tbody>
          {tools?.map((t) => (
            <tr key={t.name} className="border-b border-gray-800">
              <td className="py-2 pr-4 font-medium text-blue-400">{t.name}</td>
              <td className="py-2 pr-4 font-mono text-xs">
                {t.available ? (
                  <span className="text-gray-300" title={t.binary_path ?? t.binary}>
                    {t.binary_path ?? t.binary}
                  </span>
                ) : (
                  <span className="text-gray-500">{t.binary}</span>
                )}
              </td>
              <td className="py-2 pr-4">
                {t.available ? (
                  <span className="text-green-400 text-xs">✓ available</span>
                ) : (
                  <span className="text-red-400 text-xs">✗ not in $PATH</span>
                )}
              </td>
              <td className="py-2 pr-4 text-gray-500 text-xs">
                {t.att_ck_ids.slice(0, 3).join(', ')}
              </td>
              <td className="py-2 text-gray-400 max-w-md truncate">{t.description}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
