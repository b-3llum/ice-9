import { useEffect, useRef } from 'react'
import { useEventStream } from '../hooks/useEventStream'
import type { Ice9Event } from '../types/events'

const EVENT_STYLES: Record<string, { icon: string; color: string }> = {
  tool_start:          { icon: '⚡', color: 'text-cyan-400' },
  tool_output:         { icon: '  ', color: 'text-gray-500' },
  tool_complete:       { icon: '✓ ', color: 'text-green-400' },
  tool_error:          { icon: '✗ ', color: 'text-red-400' },
  phase_start:         { icon: '▶ ', color: 'text-blue-400' },
  phase_plan:          { icon: '📋', color: 'text-blue-300' },
  phase_task_start:    { icon: '→ ', color: 'text-cyan-300' },
  phase_task_complete: { icon: '✓ ', color: 'text-green-300' },
  phase_complete:      { icon: '✅', color: 'text-green-500' },
  ai_request:          { icon: '🤖', color: 'text-purple-400' },
  ai_chunk:            { icon: '  ', color: 'text-purple-300' },
  ai_response:         { icon: '💬', color: 'text-purple-400' },
  auto_phase_select:   { icon: '🎯', color: 'text-yellow-400' },
  auto_complete:       { icon: '🏁', color: 'text-yellow-300' },
  finding_new:         { icon: '🔍', color: 'text-red-400' },
}

function formatEvent(event: Ice9Event): string {
  const d = event.data
  switch (event.type) {
    case 'tool_start':
      return `Running ${d.tool} → ${d.target}`
    case 'tool_output':
      return `${d.tool}: ${(d.lines as string[])?.slice(-1)[0] || '...'}`
    case 'tool_complete':
      return `${d.tool} completed (${(d.duration as number)?.toFixed(1)}s)`
    case 'tool_error':
      return `${d.tool} failed (rc=${d.return_code})`
    case 'phase_start':
      return `Phase started: ${d.name}`
    case 'phase_plan':
      return `Planned ${d.task_count} tasks for ${d.phase}`
    case 'phase_task_start':
      return `[${d.task_num}/${d.total_tasks}] ${d.tool} → ${d.target}`
    case 'phase_task_complete':
      return `[${d.task_num}/${d.total_tasks}] ${d.tool} ${d.success ? '✓' : '✗'} (${(d.duration as number)?.toFixed(1)}s)`
    case 'phase_complete':
      return `Phase complete: ${d.phase} — ${d.findings} findings`
    case 'ai_request':
      return `${d.agent} thinking (${d.model})...`
    case 'ai_chunk':
      return `${(d.tokens as string)?.slice(0, 80)}`
    case 'ai_response':
      return `${d.agent} responded (${d.content_length} chars)`
    case 'auto_phase_select':
      return d.action === 'generating_plan'
        ? 'AI generating engagement plan...'
        : `AI selected: ${d.phase} (${d.tactic_id})`
    case 'auto_complete':
      return `Autopilot complete — ${(d.phases_executed as string[])?.length || 0} phases, ${d.total_findings} findings`
    case 'finding_new':
      return `New finding [${d.severity}]: ${d.title}`
    default:
      return JSON.stringify(d).slice(0, 100)
  }
}

function formatTime(ts: string): string {
  try {
    return new Date(ts).toLocaleTimeString()
  } catch {
    return ''
  }
}

interface ActivityFeedProps {
  campaignId?: string
  maxHeight?: string
}

export default function ActivityFeed({ campaignId, maxHeight = '400px' }: ActivityFeedProps) {
  const { events, connected, clearEvents } = useEventStream(campaignId)
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [events.length])

  // Filter out ai_chunk noise for the feed (too verbose)
  const displayEvents = events.filter(e => e.type !== 'ai_chunk')

  return (
    <div className="bg-gray-900 border border-gray-700 rounded-lg">
      <div className="flex items-center justify-between px-4 py-2 border-b border-gray-700">
        <div className="flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full ${connected ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`} />
          <span className="text-sm font-mono text-gray-400">
            {connected ? 'Live' : 'Disconnected'}
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-gray-500">{events.length} events</span>
          <button
            onClick={clearEvents}
            className="text-xs text-gray-500 hover:text-gray-300"
          >
            Clear
          </button>
        </div>
      </div>

      <div
        className="overflow-y-auto font-mono text-sm"
        style={{ maxHeight }}
      >
        {displayEvents.length === 0 ? (
          <div className="px-4 py-8 text-center text-gray-600">
            Waiting for activity...
          </div>
        ) : (
          <div className="divide-y divide-gray-800">
            {displayEvents.map((event, i) => {
              const style = EVENT_STYLES[event.type] || { icon: '•', color: 'text-gray-400' }
              return (
                <div key={i} className="px-4 py-1.5 flex items-start gap-2 hover:bg-gray-800/50">
                  <span className="text-xs text-gray-600 w-20 shrink-0 pt-0.5">
                    {formatTime(event.timestamp)}
                  </span>
                  <span className="w-5 shrink-0">{style.icon}</span>
                  <span className={`${style.color} break-all`}>
                    {formatEvent(event)}
                  </span>
                </div>
              )
            })}
          </div>
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}
