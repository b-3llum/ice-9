import type { CampaignStatus, PhaseStatus } from '../types'

const campaignColors: Record<CampaignStatus, string> = {
  planning: 'bg-blue-900 text-blue-300',
  active: 'bg-green-900 text-green-300',
  paused: 'bg-yellow-900 text-yellow-300',
  completed: 'bg-gray-700 text-gray-300',
  aborted: 'bg-red-900 text-red-300',
}

const phaseColors: Record<PhaseStatus, string> = {
  pending: 'bg-gray-700 text-gray-400',
  in_progress: 'bg-blue-900 text-blue-300',
  completed: 'bg-green-900 text-green-300',
  skipped: 'bg-gray-800 text-gray-500',
}

export function CampaignStatusBadge({ status }: { status: CampaignStatus }) {
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${campaignColors[status]}`}>
      {status}
    </span>
  )
}

export function PhaseStatusBadge({ status }: { status: PhaseStatus }) {
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${phaseColors[status]}`}>
      {status.replace('_', ' ')}
    </span>
  )
}
