interface Props {
  scores: Record<string, number>
}

export default function SusceptibilityRadar({ scores }: Props) {
  const entries = Object.entries(scores)
  if (entries.length === 0) return null

  // Render as horizontal bar chart (simpler than SVG radar, works everywhere)
  return (
    <div className="space-y-2">
      {entries.map(([vector, score]) => (
        <div key={vector}>
          <div className="flex justify-between text-xs mb-0.5">
            <span className="text-gray-300 capitalize">{vector.replace(/_/g, ' ')}</span>
            <span className={score >= 0.7 ? 'text-red-400' : score >= 0.4 ? 'text-yellow-400' : 'text-green-400'}>
              {Math.round(score * 100)}%
            </span>
          </div>
          <div className="bg-gray-700 rounded-full h-2">
            <div
              className={`rounded-full h-2 transition-all ${
                score >= 0.7 ? 'bg-red-500' : score >= 0.4 ? 'bg-yellow-500' : 'bg-green-500'
              }`}
              style={{ width: `${score * 100}%` }}
            />
          </div>
        </div>
      ))}
    </div>
  )
}
