import type { GraphRelationship } from '../../types'

interface Props {
  relationships: GraphRelationship[]
}

export default function RelationshipList({ relationships }: Props) {
  return (
    <div>
      <span className="text-xs uppercase text-gray-500">
        Relationships ({relationships.length})
      </span>
      <div className="space-y-1 mt-1">
        {relationships.map(rel => (
          <div key={rel.id} className="bg-gray-800 rounded px-3 py-2 text-xs">
            <div className="flex items-center gap-2">
              <span className="text-gray-400 font-mono">{rel.source_id.slice(0, 6)}</span>
              <span className="text-blue-400">{rel.rel_type.replace(/_/g, ' ')}</span>
              <span className="text-gray-400 font-mono">{rel.target_id.slice(0, 6)}</span>
            </div>
            <div className="text-gray-500 mt-0.5">
              {Math.round(rel.confidence * 100)}% confidence
              {rel.sources.length > 0 && ` · ${rel.sources.join(', ')}`}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
