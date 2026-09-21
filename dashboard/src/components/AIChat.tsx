import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { campaignApi } from '../api/campaigns'

interface Message {
  role: 'user' | 'agent'
  agent?: string
  content: string
}

export default function AIChat({ campaignId }: { campaignId: string }) {
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [selectedAgent, setSelectedAgent] = useState('coordinator')

  const appendError = (err: unknown, agent: string) => {
    const msg = err instanceof Error ? err.message : 'Request failed'
    setMessages((prev) => [...prev, { role: 'agent', agent, content: `Error: ${msg}` }])
  }

  const askMutation = useMutation({
    mutationFn: (prompt: string) => campaignApi.aiAsk(campaignId, prompt, selectedAgent),
    onSuccess: (result) => {
      setMessages((prev) => [
        ...prev,
        {
          role: 'agent',
          agent: result.agent,
          content: result.success ? result.content : `Error: ${result.error}`,
        },
      ])
    },
    onError: (err) => appendError(err, selectedAgent),
  })

  const planMutation = useMutation({
    mutationFn: () => campaignApi.aiPlan(campaignId),
    onSuccess: (result) => {
      setMessages((prev) => [
        ...prev,
        { role: 'agent', agent: 'coordinator', content: result.plan },
      ])
    },
    onError: (err) => appendError(err, 'coordinator'),
  })

  const analyzeMutation = useMutation({
    mutationFn: () => campaignApi.aiAnalyze(campaignId),
    onSuccess: (result) => {
      setMessages((prev) => [
        ...prev,
        { role: 'agent', agent: 'team', content: result.synthesis || 'No synthesis available.' },
      ])
    },
    onError: (err) => appendError(err, 'team'),
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!input.trim()) return
    setMessages((prev) => [...prev, { role: 'user', content: input }])
    askMutation.mutate(input)
    setInput('')
  }

  const isLoading = askMutation.isPending || planMutation.isPending || analyzeMutation.isPending

  return (
    <div className="bg-ice-900 rounded-lg p-4">
      <div className="flex items-center gap-4 mb-4">
        <h2 className="text-lg font-semibold">AI Assistant</h2>
        <button
          onClick={() => planMutation.mutate()}
          disabled={isLoading}
          className="px-3 py-1 bg-blue-700 hover:bg-blue-600 rounded text-xs disabled:opacity-50"
        >
          Generate Plan
        </button>
        <button
          onClick={() => analyzeMutation.mutate()}
          disabled={isLoading}
          className="px-3 py-1 bg-green-700 hover:bg-green-600 rounded text-xs disabled:opacity-50"
        >
          Analyze Findings
        </button>
      </div>

      <div className="space-y-3 max-h-96 overflow-y-auto mb-4">
        {messages.map((msg, i) => (
          <div
            key={i}
            className={`rounded p-3 text-sm ${
              msg.role === 'user'
                ? 'bg-gray-800 text-gray-200'
                : 'bg-gray-800/50 border border-gray-700'
            }`}
          >
            {msg.agent && (
              <div className="text-cyan-400 text-xs font-medium mb-1 uppercase">
                {msg.agent}
              </div>
            )}
            <div className="whitespace-pre-wrap">{msg.content.slice(0, 3000)}</div>
          </div>
        ))}
        {isLoading && <div className="text-gray-500 text-sm">AI is thinking...</div>}
      </div>

      <form onSubmit={handleSubmit} className="flex gap-2">
        <select
          value={selectedAgent}
          onChange={(e) => setSelectedAgent(e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-sm text-gray-300"
        >
          <option value="coordinator">Coordinator</option>
          <option value="recon_analyst">Recon Analyst</option>
          <option value="exploit_researcher">Exploit Researcher</option>
          <option value="social_engineer">Social Engineer</option>
          <option value="report_writer">Report Writer</option>
          <option value="code_analyst">Code Analyst</option>
        </select>
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Ask an agent..."
          className="flex-1 bg-gray-800 border border-gray-700 rounded px-3 py-1 text-sm text-gray-200 placeholder-gray-500"
          disabled={isLoading}
        />
        <button
          type="submit"
          disabled={isLoading || !input.trim()}
          className="px-4 py-1 bg-red-700 hover:bg-red-600 rounded text-sm disabled:opacity-50"
        >
          Send
        </button>
      </form>
    </div>
  )
}
