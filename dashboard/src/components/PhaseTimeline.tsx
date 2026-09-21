import { useState } from 'react'
import type { Phase } from '../types'
import { PhaseStatusBadge } from './StatusBadge'
import { campaignApi } from '../api/campaigns'

const statusColor: Record<string, string> = {
  pending: 'border-gray-600',
  in_progress: 'border-blue-500 bg-blue-900/20',
  completed: 'border-green-500 bg-green-900/20',
  skipped: 'border-gray-700 opacity-50',
}

// Map ATT&CK IDs to friendly names for the run API
const phaseTypeMap: Record<string, string> = {
  TA0043: 'recon',
  TA0042: 'resource_dev',
  TA0001: 'initial_access',
  TA0002: 'execution',
  TA0003: 'persistence',
  TA0004: 'priv_esc',
  TA0005: 'defense_evasion',
  TA0006: 'credential_access',
  TA0007: 'discovery',
  TA0008: 'lateral_movement',
  TA0009: 'collection',
  TA0010: 'exfiltration',
  TA0040: 'impact',
}

interface Props {
  phases: Phase[]
  campaignId: string
}

export default function PhaseTimeline({ phases, campaignId }: Props) {
  const [runningPhase, setRunningPhase] = useState<string | null>(null)

  const handleRun = async (phase: Phase) => {
    const friendlyName = phaseTypeMap[phase.type]
    if (!friendlyName) return
    setRunningPhase(phase.type)
    try {
      await campaignApi.runPhase(campaignId, friendlyName)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to start phase'
      alert(msg)
    } finally {
      // Always clear, so the other phases' Run buttons re-enable even on success.
      setRunningPhase(null)
    }
  }

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
            {phase.status === 'pending' && (
              <button
                onClick={() => handleRun(phase)}
                disabled={runningPhase !== null}
                className="mt-1 text-xs px-2 py-0.5 rounded bg-red-600 hover:bg-red-500 disabled:opacity-40 disabled:cursor-not-allowed text-white"
              >
                {runningPhase === phase.type ? 'Starting...' : 'Run'}
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
