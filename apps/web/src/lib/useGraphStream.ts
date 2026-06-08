import { useEffect, useRef, useCallback } from 'react'
import { getWsApiBaseUrl } from './apiBase'
import type { GraphNode, GraphEdge } from './types'

interface GraphDelta {
  type: 'delta' | 'connected'
  added_nodes?: GraphNode[]
  added_edges?: GraphEdge[]
  updated_nodes?: GraphNode[]
  assessment_id?: string
}

interface UseGraphStreamOptions {
  assessmentId: string | undefined
  enabled: boolean
  onDelta: (delta: GraphDelta) => void
  onThreatAlert: (message: string) => void
}

export function useGraphStream({ assessmentId, enabled, onDelta, onThreatAlert }: UseGraphStreamOptions) {
  const wsRef = useRef<WebSocket | null>(null)
  const pingInterval = useRef<ReturnType<typeof setInterval> | null>(null)

  const connect = useCallback(() => {
    if (!assessmentId || !enabled) return
    const base = getWsApiBaseUrl()
    const ws = new WebSocket(`${base}/graph/${assessmentId}/stream`)
    wsRef.current = ws

    ws.onmessage = (event) => {
      try {
        const data: GraphDelta = JSON.parse(event.data)
        if (data.type === 'delta') {
          onDelta(data)
          if (data.added_edges?.some(e => e.connects_to_tier0)) {
            onThreatAlert(`New attack path detected: ${data.added_edges?.[0]?.edge_type}`)
          }
        }
      } catch { /* ignore parse errors */ }
    }

    ws.onclose = () => {
      wsRef.current = null
      if (pingInterval.current) clearInterval(pingInterval.current)
      if (enabled) setTimeout(connect, 5000)
    }

    ws.onopen = () => {
      pingInterval.current = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) ws.send('ping')
      }, 30000)
    }
  }, [assessmentId, enabled, onDelta, onThreatAlert])

  useEffect(() => {
    if (enabled) {
      connect()
    } else {
      wsRef.current?.close()
      wsRef.current = null
    }
    return () => {
      wsRef.current?.close()
      if (pingInterval.current) clearInterval(pingInterval.current)
    }
  }, [enabled, connect])
}
