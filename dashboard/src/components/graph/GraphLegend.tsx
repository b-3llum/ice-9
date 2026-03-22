const LEGEND_ITEMS = [
  { type: 'person', color: '#3b82f6' },
  { type: 'host', color: '#22c55e' },
  { type: 'domain', color: '#a855f7' },
  { type: 'credential', color: '#ef4444' },
  { type: 'email', color: '#f59e0b' },
  { type: 'organization', color: '#06b6d4' },
  { type: 'service', color: '#6366f1' },
  { type: 'network', color: '#14b8a6' },
  { type: 'certificate', color: '#ec4899' },
]

export default function GraphLegend() {
  return (
    <div className="flex gap-4 mt-2 text-xs text-gray-400">
      {LEGEND_ITEMS.map(item => (
        <div key={item.type} className="flex items-center gap-1.5">
          <span
            className="w-2.5 h-2.5 rounded-full inline-block"
            style={{ backgroundColor: item.color }}
          />
          {item.type}
        </div>
      ))}
    </div>
  )
}
