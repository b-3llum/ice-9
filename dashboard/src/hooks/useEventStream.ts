import { useEffect, useRef, useState, useCallback } from 'react'
import type { Ice9Event } from '../types/events'

const MAX_EVENTS = 100

export function useEventStream(campaignId?: string) {
  const [events, setEvents] = useState<Ice9Event[]>([])
  const [connected, setConnected] = useState(false)
  const esRef = useRef<EventSource | null>(null)

  const clearEvents = useCallback(() => setEvents([]), [])

  useEffect(() => {
    const params = campaignId ? `?campaign_id=${campaignId}` : ''
    const url = `/api/events/stream${params}`
    const es = new EventSource(url)
    esRef.current = es

    es.onopen = () => setConnected(true)
    es.onerror = () => setConnected(false)

    // Listen to all event types via generic handler
    const handler = (e: MessageEvent) => {
      try {
        const event: Ice9Event = JSON.parse(e.data)
        setEvents(prev => {
          const next = [...prev, event]
          return next.length > MAX_EVENTS ? next.slice(-MAX_EVENTS) : next
        })
      } catch {
        // ignore parse errors
      }
    }

    // Register for each event type
    const types = [
      'tool_start', 'tool_output', 'tool_complete', 'tool_error',
      'phase_start', 'phase_plan', 'phase_task_start', 'phase_task_complete', 'phase_complete',
      'ai_request', 'ai_chunk', 'ai_response',
      'auto_phase_select', 'auto_complete',
      'finding_new',
    ]
    for (const t of types) {
      es.addEventListener(t, handler)
    }
    // Also handle generic messages
    es.onmessage = handler

    return () => {
      es.close()
      esRef.current = null
      setConnected(false)
    }
  }, [campaignId])

  return { events, connected, clearEvents }
}
