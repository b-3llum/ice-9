import type { Phase } from '../types'
import { PhaseStatusBadge } from './StatusBadge'

const statusColor: Record<string, string> = {
  pending: 'border-gray-600',
  in_progress: 'border-blue-500 bg-blue-900/20',
  completed: 'border-green-500 bg-green-900/20',
  skipped: 'border-gray-700 opacity-50',
}

export default function PhaseTimeline({ phases }: { phases: Phase[] }) {
  return (
    <div className="mb-6">
      <h2 className="text-lg font-semibold mb-3">ATT&CK Phase Timeline</h2>
      <div className="flex gap-1 overflow-x-auto pb-2">
        {phases.map((phase) => (
          <div
            key={phase.id}
            className={`flex-shrink-0 border rounded px-3 py-2 min-w-[120px] ${statusColor[phase.status]}`}
          >
            <div className="text-xs text-gray-500">{phase.type}</div>
            <div className="text-sm font-medium truncate">{phase.name}</div>
            <div className="mt-1 flex items-center gap-2">
              <PhaseStatusBadge status={phase.status} />
            </div>
            {(phase.tasks > 0 || phase.findings > 0) && (
              <div className="mt-1 text-xs text-gray-500">
                {phase.tasks} tasks / {phase.findings} findings
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
