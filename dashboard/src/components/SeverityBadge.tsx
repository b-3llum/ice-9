import type { Severity } from '../types'

const colors: Record<Severity, string> = {
  critical: 'bg-red-700 text-white',
  high: 'bg-orange-700 text-white',
  medium: 'bg-yellow-700 text-white',
  low: 'bg-blue-700 text-white',
  info: 'bg-gray-600 text-gray-200',
}

export default function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${colors[severity]}`}>
      {severity}
    </span>
  )
}
