import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { intelApi } from '../../api/intel'
import SimulationResults from './SimulationResults'
import type { SimulationResult } from '../../types'

interface Props {
  campaignId: string
  profileId: string
}

export default function SimulationPanel({ campaignId, profileId }: Props) {
  const queryClient = useQueryClient()
  const [numSims, setNumSims] = useState(50)
  const [result, setResult] = useState<SimulationResult | null>(null)

  const simMutation = useMutation({
    mutationFn: () => intelApi.simulate(campaignId, profileId, {
      num_simulations: numSims,
    }),
    onSuccess: (data) => {
      setResult(data)
      queryClient.invalidateQueries({ queryKey: ['subjects', campaignId] })
    },
  })

  return (
    <div className="bg-ice-900 rounded-lg p-4 border border-gray-700">
      <h4 className="text-sm font-semibold text-gray-400 uppercase mb-3">
        Behavioral Simulation
      </h4>

      <div className="flex items-center gap-3 mb-4">
        <label className="text-xs text-gray-400">Simulations:</label>
        <input
          type="number"
          value={numSims}
          onChange={e => setNumSims(Number(e.target.value))}
          min={1}
          max={500}
          className="bg-gray-800 border border-gray-600 rounded px-2 py-1 text-sm text-gray-200 w-20"
        />
        <button
          onClick={() => simMutation.mutate()}
          disabled={simMutation.isPending}
          className="bg-red-600 hover:bg-red-700 disabled:opacity-50 text-white text-sm px-4 py-1.5 rounded"
        >
          {simMutation.isPending ? 'Running...' : 'Run Simulation'}
        </button>
      </div>

      {simMutation.isPending && (
        <div className="text-gray-400 text-sm animate-pulse">
          Running Monte Carlo simulations... This may take a moment.
        </div>
      )}

      {simMutation.isError && (
        <div className="text-red-400 text-sm">
          Simulation failed: {simMutation.error?.message}
        </div>
      )}

      {result && <SimulationResults result={result} />}
    </div>
  )
}
