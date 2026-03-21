import { useQuery } from '@tanstack/react-query'
import { toolApi } from '../api/campaigns'

export default function ToolsList() {
  const { data: tools, isLoading } = useQuery({
    queryKey: ['tools'],
    queryFn: () => toolApi.list(),
  })

  if (isLoading) return <div className="text-gray-400">Loading tools...</div>

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Registered Tools</h1>
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-gray-700 text-gray-400 text-left">
            <th className="py-2 pr-4">Name</th>
            <th className="py-2 pr-4">Binary</th>
            <th className="py-2 pr-4">Available</th>
            <th className="py-2 pr-4">ATT&CK IDs</th>
            <th className="py-2">Description</th>
          </tr>
        </thead>
        <tbody>
          {tools?.map((t) => (
            <tr key={t.name} className="border-b border-gray-800">
              <td className="py-2 pr-4 font-medium text-blue-400">{t.name}</td>
              <td className="py-2 pr-4 text-gray-400 font-mono text-xs">{t.binary}</td>
              <td className="py-2 pr-4">
                {t.available ? (
                  <span className="text-green-400 text-xs">available</span>
                ) : (
                  <span className="text-red-400 text-xs">missing</span>
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
