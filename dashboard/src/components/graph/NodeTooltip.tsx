interface Props {
  node: {
    name: string
    entity_type: string
    confidence: number
    sources: string[]
  }
  x: number
  y: number
}

export default function NodeTooltip({ node, x, y }: Props) {
  return (
    <div
      className="fixed pointer-events-none bg-gray-800 border border-gray-600 rounded px-3 py-2 shadow-lg z-50 text-sm"
      style={{ left: x + 12, top: y - 10 }}
    >
      <div className="font-medium text-gray-100">{node.name}</div>
      <div className="text-gray-400 text-xs mt-0.5">
        {node.entity_type} &middot; {Math.round(node.confidence * 100)}% confidence
      </div>
      {node.sources.length > 0 && (
        <div className="text-gray-500 text-xs mt-0.5">
          via {node.sources.join(', ')}
        </div>
      )}
    </div>
  )
}
