import type { EntityType } from '../../types'

const ALL_TYPES: EntityType[] = [
  'person', 'host', 'domain', 'credential', 'email',
  'organization', 'service', 'network', 'certificate',
]

interface Props {
  search: string
  onSearchChange: (v: string) => void
  filters: Set<EntityType>
  onFiltersChange: (v: Set<EntityType>) => void
  nodeCount: number
  edgeCount: number
}

export default function GraphControls({
  search, onSearchChange, filters, onFiltersChange, nodeCount, edgeCount,
}: Props) {
  const toggleFilter = (type: EntityType) => {
    const next = new Set(filters)
    if (next.has(type)) {
      next.delete(type)
    } else {
      next.add(type)
    }
    onFiltersChange(next)
  }

  return (
    <div className="flex items-center gap-4 mb-3">
      <input
        type="text"
        placeholder="Search entities..."
        value={search}
        onChange={e => onSearchChange(e.target.value)}
        className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm text-gray-200 w-64"
      />

      <div className="flex gap-1.5 flex-wrap">
        {ALL_TYPES.map(type => (
          <button
            key={type}
            onClick={() => toggleFilter(type)}
            className={`text-xs px-2 py-0.5 rounded border ${
              filters.has(type)
                ? 'border-gray-600 text-gray-500 line-through'
                : 'border-gray-500 text-gray-300'
            }`}
          >
            {type}
          </button>
        ))}
      </div>

      <span className="text-gray-500 text-xs ml-auto">
        {nodeCount} nodes / {edgeCount} edges
      </span>
    </div>
  )
}
