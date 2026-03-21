import { useState } from 'react'
import type { Finding, Severity } from '../types'
import SeverityBadge from './SeverityBadge'

const severityOrder: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
}

export default function FindingsTable({ findings }: { findings: Finding[] }) {
  const [filter, setFilter] = useState<Severity | 'all'>('all')

  const filtered = findings
    .filter((f) => filter === 'all' || f.severity === filter)
    .sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity])

  return (
    <div>
      <div className="flex items-center gap-4 mb-4">
        <h2 className="text-lg font-semibold">Findings ({findings.length})</h2>
        <div className="flex gap-1">
          {(['all', 'critical', 'high', 'medium', 'low', 'info'] as const).map((s) => (
            <button
              key={s}
              onClick={() => setFilter(s)}
              className={`px-2 py-0.5 rounded text-xs ${
                filter === s ? 'bg-gray-600 text-white' : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
              }`}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      {!filtered.length ? (
        <p className="text-gray-500 text-sm">No findings match the filter.</p>
      ) : (
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-700 text-gray-400 text-left">
              <th className="py-2 pr-4">Severity</th>
              <th className="py-2 pr-4">Title</th>
              <th className="py-2 pr-4">CVSS</th>
              <th className="py-2 pr-4">CVEs</th>
              <th className="py-2">ATT&CK</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((f) => (
              <tr key={f.id} className="border-b border-gray-800 hover:bg-gray-800/50">
                <td className="py-2 pr-4">
                  <SeverityBadge severity={f.severity} />
                </td>
                <td className="py-2 pr-4 text-gray-200">{f.title}</td>
                <td className="py-2 pr-4 text-gray-400">{f.cvss ?? '—'}</td>
                <td className="py-2 pr-4 text-gray-400 text-xs">
                  {f.cve_ids.join(', ') || '—'}
                </td>
                <td className="py-2 text-gray-400 text-xs">
                  {f.att_ck_ids.join(', ') || '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
