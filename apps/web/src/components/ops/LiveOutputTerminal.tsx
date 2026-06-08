'use client'

import { useEffect, useRef } from 'react'
import type { FitAddon as XTermFitAddon } from '@xterm/addon-fit'
import type { Terminal as XTermTerminal } from '@xterm/xterm'
import { getApiBaseUrl, getWsApiBaseUrl } from '@/lib/apiBase'

interface LiveOutputTerminalProps {
  jobId: string
  wsBaseUrl?: string
  wsPath?: string
  outputPath?: string
}

export default function LiveOutputTerminal({
  jobId,
  wsBaseUrl,
  wsPath = '/ops/ws/jobs',
  outputPath = '/ops/jobs',
}: LiveOutputTerminalProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const termRef = useRef<XTermTerminal | null>(null)
  const wsRef = useRef<WebSocket | null>(null)

  useEffect(() => {
    if (!containerRef.current) return

    let terminal: XTermTerminal
    let fitAddon: XTermFitAddon

    const init = async () => {
      const { Terminal } = await import('@xterm/xterm')
      const { FitAddon } = await import('@xterm/addon-fit')
      await import('@xterm/xterm/css/xterm.css')

      terminal = new Terminal({
        theme: {
          background: '#000',
          foreground: '#c8c0f0',
          cursor: '#7c3aed',
          selectionBackground: 'rgba(124,58,237,0.3)',
          black: '#0a0a0f',
          brightBlack: '#3d3560',
          red: '#ff4d6d',
          brightRed: '#ff6b8a',
          green: '#39d98a',
          brightGreen: '#57efaa',
          yellow: '#ffd166',
          brightYellow: '#ffe599',
          blue: '#7c3aed',
          brightBlue: '#a78bfa',
          magenta: '#d946ef',
          brightMagenta: '#e879f9',
          cyan: '#22d3ee',
          brightCyan: '#67e8f9',
          white: '#c8c0f0',
          brightWhite: '#f0ecff',
        },
        fontFamily: 'JetBrains Mono, monospace',
        fontSize: 13,
        lineHeight: 1.4,
        cursorBlink: true,
        convertEol: true,
      })

      fitAddon = new FitAddon()
      terminal.loadAddon(fitAddon)
      terminal.open(containerRef.current!)
      fitAddon.fit()
      termRef.current = terminal

      terminal.writeln('\x1b[35m[AdByG0d]\x1b[0m Connecting to job stream...')

      const resolvedWsBaseUrl = getWsApiBaseUrl(wsBaseUrl)
      const wsUrl = new URL(`${resolvedWsBaseUrl}${wsPath}/${jobId}`)
      
      const ws = new WebSocket(wsUrl.toString())
      wsRef.current = ws
      let gotDone = false

      ws.onopen = () => {
        terminal.writeln('\x1b[32m[+]\x1b[0m Connected.')
      }

      ws.onmessage = (evt) => {
        try {
          const data = JSON.parse(evt.data)
          if (data.done) {
            gotDone = true
            const code = data.exit_code ?? 0
            const color = code === 0 ? '\x1b[32m' : '\x1b[31m'
            terminal.writeln(`\n${color}[*] Job completed — exit code ${code}\x1b[0m`)
            return
          }
          if (data.error) {
            terminal.writeln(`\x1b[31m[!] ${data.error}\x1b[0m`)
            return
          }
          if (data.stream === 'loot') {
            terminal.writeln(`\n\x1b[36m╔══ LOOT: ${data.loot_type ?? 'data'} ══╗\x1b[0m`)
            for (const chunk of (data.data ?? '').split('\n')) {
              terminal.writeln(`\x1b[93m${chunk}\x1b[0m`)
            }
            terminal.writeln('\x1b[36m╚══════════════════╝\x1b[0m')
            return
          }
          const prefix = data.stream === 'stderr' ? '\x1b[33m' : ''
          const reset = prefix ? '\x1b[0m' : ''
          terminal.writeln(`${prefix}${data.line ?? ''}${reset}`)
        } catch {
          terminal.writeln(evt.data)
        }
      }

      ws.onerror = () => {
        terminal.writeln('\x1b[31m[!] WebSocket error\x1b[0m')
      }

      ws.onclose = async () => {
        if (gotDone) {
          terminal.writeln('\x1b[90m[~] Stream closed\x1b[0m')
          return
        }
        // Job was already done before WS connected — replay stored output
        terminal.writeln('\x1b[90m[~] Fetching stored output...\x1b[0m')
        try {
          const outputUrl = `${getApiBaseUrl()}${outputPath}/${jobId}/output`
          const resp = await fetch(outputUrl, {
            headers: { 'X-Requested-With': 'XMLHttpRequest' },
            credentials: 'include',
          })
          if (resp.ok) {
            const lines: Array<{ stream: string; line: string }> = await resp.json()
            for (const l of lines) {
              const prefix = l.stream === 'stderr' ? '\x1b[33m' : ''
              const reset = prefix ? '\x1b[0m' : ''
              terminal.writeln(`${prefix}${l.line}${reset}`)
            }
            terminal.writeln('\x1b[90m[~] End of stored output\x1b[0m')
          } else {
            terminal.writeln('\x1b[90m[~] No stored output found\x1b[0m')
          }
        } catch {
          terminal.writeln('\x1b[90m[~] Could not fetch stored output\x1b[0m')
        }
      }

      const ro = new ResizeObserver(() => fitAddon.fit())
      ro.observe(containerRef.current!)
      return () => ro.disconnect()
    }

    const cleanup = init()

    return () => {
      wsRef.current?.close()
      termRef.current?.dispose()
      cleanup.then(fn => fn?.())
    }
  }, [jobId, wsBaseUrl, outputPath, wsPath])

  return (
    <div
      ref={containerRef}
      className="h-full w-full min-h-[300px] rounded-lg bg-black p-1"
    />
  )
}
