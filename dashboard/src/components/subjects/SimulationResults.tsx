import { useState } from 'react'
import type { SimulationResult } from '../../types'

interface Props {
  result: SimulationResult
}

export default function SimulationResults({ result }: Props) {
  const [expandedScenario, setExpandedScenario] = useState<string | null>(null)

  return (
    <div className="space-y-4">
      {/* Overall score */}
      <div className="flex items-center gap-4 bg-gray-800 rounded p-3">
        <div>
          <div className="text-xs text-gray-500">Overall Susceptibility</div>
          <div className={`text-2xl font-bold ${
            result.overall_susceptibility >= 0.7 ? 'text-red-400' :
            result.overall_susceptibility >= 0.4 ? 'text-yellow-400' : 'text-green-400'
          }`}>
            {Math.round(result.overall_susceptibility * 100)}%
          </div>
        </div>
        <div>
          <div className="text-xs text-gray-500">Confidence</div>
          <div className="text-lg text-gray-300">{Math.round(result.confidence * 100)}%</div>
        </div>
        {result.best_approach.scenario && (
          <div className="ml-auto text-right">
            <div className="text-xs text-gray-500">Best Attack</div>
            <div className="text-sm text-gray-200">{String(result.best_approach.scenario)}</div>
            <div className="text-xs text-green-400">
              {Math.round(Number(result.best_approach.success_rate || 0) * 100)}% success
            </div>
          </div>
        )}
      </div>

      {/* Scenario breakdown */}
      <div className="space-y-2">
        {result.scenarios.map(scenario => (
          <div key={scenario.scenario_name} className="bg-gray-800 rounded overflow-hidden">
            <button
              className="w-full text-left px-3 py-2 flex items-center justify-between hover:bg-gray-750"
              onClick={() => setExpandedScenario(
                expandedScenario === scenario.scenario_name ? null : scenario.scenario_name
              )}
            >
              <div>
                <span className="text-gray-200 text-sm">{scenario.scenario_name}</span>
                <span className="text-gray-500 text-xs ml-2">({scenario.attack_vector})</span>
              </div>
              <div className="flex items-center gap-3">
                <div className={`text-sm font-medium ${
                  scenario.success_rate >= 0.7 ? 'text-red-400' :
                  scenario.success_rate >= 0.4 ? 'text-yellow-400' : 'text-green-400'
                }`}>
                  {Math.round(scenario.success_rate * 100)}%
                </div>
                <span className="text-gray-500 text-xs">
                  CI: [{Math.round(scenario.confidence_interval[0] * 100)}%
                  , {Math.round(scenario.confidence_interval[1] * 100)}%]
                </span>
              </div>
            </button>

            {expandedScenario === scenario.scenario_name && (
              <div className="px-3 pb-3 border-t border-gray-700 pt-2 space-y-2">
                {scenario.avg_response_time && (
                  <div className="text-xs text-gray-400">
                    Avg response time: {scenario.avg_response_time}
                  </div>
                )}

                {scenario.common_failure_modes.length > 0 && (
                  <div>
                    <div className="text-xs text-gray-500 mb-1">Failure modes:</div>
                    <ul className="text-xs text-gray-400 space-y-0.5">
                      {scenario.common_failure_modes.map((mode, i) => (
                        <li key={i}>- {mode}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {scenario.sample_interactions.length > 0 && (
                  <div>
                    <div className="text-xs text-gray-500 mb-1">Sample interactions:</div>
                    {scenario.sample_interactions.map((interaction, i) => (
                      <div key={i} className="bg-gray-900 rounded p-2 text-xs text-gray-300 mb-1">
                        <span className={`font-medium ${
                          interaction.outcome === 'success' ? 'text-red-400' : 'text-green-400'
                        }`}>
                          [{String(interaction.outcome).toUpperCase()}]
                        </span>
                        {' '}{String(interaction.summary || '')}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Report */}
      {result.report && (
        <div>
          <h5 className="text-xs text-gray-500 uppercase mb-2">Assessment Report</h5>
          <div className="bg-gray-800 rounded p-3 text-sm text-gray-300 whitespace-pre-wrap">
            {result.report}
          </div>
        </div>
      )}
    </div>
  )
}
