'use client'

import { copyText } from '@/lib/clipboard'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import { Play, Square, Copy, RefreshCw } from 'lucide-react'
import { useState } from 'react'
import { connectivityApi, type ConnectivityProfile } from '@/lib/connectivityApi'

function TunnelViz({ mode, isActive }: { mode: string; isActive: boolean }) {
  return (
    <div className="flex items-center justify-between gap-3 p-4 rounded-xl border border-white/5 bg-black/40 mb-4">
      <div className="text-center flex-shrink-0">
        <div className="w-10 h-10 rounded-xl flex items-center justify-center text-lg mx-auto mb-1.5"
          style={{ background: '#22d3ee12', border: '1px solid #22d3ee25' }}>🖥</div>
        <div className="text-[7px] font-mono text-white/30 tracking-wider">ATTACKER</div>
        <div className="text-[8px] font-mono text-cyan-400/60">127.0.0.1</div>
      </div>

      <div className="flex-1 relative">
        <div className="h-[2px] rounded-full" style={{ background: isActive ? 'linear-gradient(90deg,#22d3ee,#34d399)' : '#ffffff10' }} />
        {isActive && (
          <>
            <motion.div
              className="absolute top-1/2 -translate-y-1/2 w-2 h-2 rounded-full"
              style={{ background: '#22d3ee', boxShadow: '0 0 6px #22d3ee' }}
              animate={{ left: ['5%', '45%'] }}
              transition={{ repeat: Infinity, duration: 1.2, ease: 'linear' }}
            />
            <motion.div
              className="absolute top-1/2 -translate-y-1/2 w-2 h-2 rounded-full"
              style={{ background: '#34d399', boxShadow: '0 0 6px #34d399' }}
              animate={{ left: ['50%', '90%'] }}
              transition={{ repeat: Infinity, duration: 1.2, ease: 'linear', delay: 0.6 }}
            />
          </>
        )}
        <div className="text-center text-[7px] font-mono text-white/20 mt-1.5">{mode}</div>
      </div>

      <div className="text-center flex-shrink-0">
        <div
          className="w-10 h-10 rounded-xl flex items-center justify-center text-lg mx-auto mb-1.5"
          style={{
            background: isActive ? '#34d39912' : '#ffffff06',
            border: `1px solid ${isActive ? '#34d39925' : '#ffffff10'}`,
          }}
        >🏢</div>
        <div className="text-[7px] font-mono text-white/30 tracking-wider">TARGET DC</div>
        <div className="text-[8px] font-mono" style={{ color: isActive ? '#34d39970' : '#ffffff30' }}>
          {isActive ? 'REACHABLE' : 'UNKNOWN'}
        </div>
      </div>
    </div>
  )
}

export function ControlTab({ profile }: { profile: ConnectivityProfile }) {
  const qc = useQueryClient()
  const [copied, setCopied] = useState(false)
  const mode = profile.mode
  const cfg = profile.config as Record<string, unknown>

  const chiselStatusQ = useQuery({
    queryKey: ['chisel-status', profile.id],
    queryFn: () => connectivityApi.chiselStatus(profile.id),
    enabled: mode === 'CHISEL',
    refetchInterval: 3000,
  })
  const chiselStartMut = useMutation({
    mutationFn: () => connectivityApi.chiselStart(profile.id),
    onSuccess: () => chiselStatusQ.refetch(),
  })
  const chiselStopMut = useMutation({
    mutationFn: () => connectivityApi.chiselStop(profile.id),
    onSuccess: () => chiselStatusQ.refetch(),
  })

  const ligoloStatusQ = useQuery({
    queryKey: ['ligolo-status', profile.id],
    queryFn: () => connectivityApi.ligoloStatus(profile.id),
    enabled: mode === 'LIGOLO',
    refetchInterval: 4000,
  })
  const ligoloStartMut = useMutation({
    mutationFn: () => connectivityApi.ligoloStart(profile.id),
    onSuccess: () => ligoloStatusQ.refetch(),
  })
  const ligoloStopMut = useMutation({
    mutationFn: () => connectivityApi.ligoloStop(profile.id),
    onSuccess: () => ligoloStatusQ.refetch(),
  })
  const [newRoute, setNewRoute] = useState('')
  const addRouteMut = useMutation({
    mutationFn: (cidr: string) => connectivityApi.ligoloAddRoute(profile.id, cidr),
    onSuccess: () => { setNewRoute(''); ligoloStatusQ.refetch() },
  })

  const tunnelStatusQ = useQuery({
    queryKey: ['tunnel-status', profile.id],
    queryFn: () => connectivityApi.tunnelStatus(profile.id),
    enabled: mode === 'MANAGED_SSH_SOCKS',
    refetchInterval: 5000,
    retry: false,
  })
  const [sshPassword, setSshPassword] = useState('')
  const tunnelStartMut = useMutation({
    mutationFn: () => connectivityApi.tunnelStart(profile.id, sshPassword || undefined),
    onSuccess: () => { tunnelStatusQ.refetch(); qc.invalidateQueries({ queryKey: ['connectivity-profiles'] }) },
  })
  const tunnelStopMut = useMutation({
    mutationFn: () => connectivityApi.tunnelStop(profile.id),
    onSuccess: () => { tunnelStatusQ.refetch(); qc.invalidateQueries({ queryKey: ['connectivity-profiles'] }) },
  })

  if (mode === 'DIRECT') {
    return (
      <div className="space-y-4">
        <TunnelViz mode="DIRECT" isActive={profile.status === 'ONLINE'} />
        <div className="rounded-xl border border-cyan-500/15 bg-cyan-500/5 p-4 font-mono text-xs text-cyan-400/60">
          Direct mode requires no tunnel management. AdByG0d connects directly to the DC IP. Use the Probe tab to verify connectivity.
        </div>
        <div className="grid grid-cols-2 gap-3 text-[9px] font-mono">
          <div className="rounded-lg border border-white/5 p-3">
            <div className="text-white/30 mb-1 tracking-widest">TARGET DOMAIN</div>
            <div className="text-white/70">{String(cfg.target_domain || '—')}</div>
          </div>
          <div className="rounded-lg border border-white/5 p-3">
            <div className="text-white/30 mb-1 tracking-widest">DC IP</div>
            <div className="text-white/70">{String(cfg.dc_ip || '—')}</div>
          </div>
        </div>
      </div>
    )
  }

  if (mode === 'SOCKS5') {
    return (
      <div className="space-y-4">
        <TunnelViz mode="SOCKS5" isActive={profile.status === 'ONLINE'} />
        <div className="rounded-xl border border-purple-500/15 bg-purple-500/5 p-4 font-mono text-xs text-purple-400/60">
          SOCKS5 mode uses an existing external proxy. Ensure your proxy is running at the configured host:port before probing.
        </div>
        <div className="grid grid-cols-2 gap-3 text-[9px] font-mono">
          <div className="rounded-lg border border-white/5 p-3">
            <div className="text-white/30 mb-1 tracking-widest">PROXY HOST</div>
            <div className="text-white/70">{String(cfg.proxy_host || '—')}</div>
          </div>
          <div className="rounded-lg border border-white/5 p-3">
            <div className="text-white/30 mb-1 tracking-widest">PROXY PORT</div>
            <div className="text-white/70">{String(cfg.proxy_port || '—')}</div>
          </div>
        </div>
      </div>
    )
  }

  if (mode === 'CHISEL') {
    const s = chiselStatusQ.data
    const isRunning = s?.running ?? false
    const clientCmd = s?.client_cmd_template ?? (cfg.client_cmd_template as string | undefined)
    const endpoint = isRunning ? `socks5://127.0.0.1:${cfg.socks_port ?? 1080}` : null

    const copy = (text: string) => {
      copyText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }

    return (
      <div className="space-y-4">
        <TunnelViz mode="CHISEL" isActive={isRunning} />
        <div className="flex items-center justify-between px-4 py-2.5 rounded-xl border" style={{ borderColor: isRunning ? '#f59e0b30' : '#ffffff08', background: isRunning ? '#f59e0b08' : '#ffffff04' }}>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full" style={{ background: isRunning ? '#f59e0b' : '#ffffff25', boxShadow: isRunning ? '0 0 6px #f59e0b' : undefined }} />
            <span className="font-mono text-xs" style={{ color: isRunning ? '#f59e0b' : '#ffffff40' }}>
              {isRunning ? `RUNNING — PID ${s?.pid ?? '?'} — PORT ${s?.port ?? cfg.server_port}` : 'STOPPED'}
            </span>
          </div>
          {endpoint && (
            <button onClick={() => copy(endpoint)} className="flex items-center gap-1 font-mono text-[9px] text-white/30 hover:text-white/60 transition-colors">
              <Copy className="w-3 h-3" />
              {copied ? 'COPIED' : endpoint}
            </button>
          )}
        </div>
        <div className="flex gap-3">
          <button
            onClick={() => chiselStartMut.mutate()}
            disabled={isRunning || chiselStartMut.isPending}
            className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-xl border font-mono font-bold text-sm transition-all disabled:opacity-30"
            style={{ background: '#34d39910', borderColor: '#34d39930', color: '#34d399' }}
          >
            {chiselStartMut.isPending ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            START SERVER
          </button>
          <button
            onClick={() => chiselStopMut.mutate()}
            disabled={!isRunning || chiselStopMut.isPending}
            className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-xl border font-mono font-bold text-sm transition-all disabled:opacity-30"
            style={{ background: '#f4717110', borderColor: '#f4717130', color: '#f47171' }}
          >
            {chiselStopMut.isPending ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Square className="w-4 h-4" />}
            STOP SERVER
          </button>
        </div>
        {clientCmd && (
          <div>
            <div className="text-[8px] font-mono text-amber-500/40 tracking-widest uppercase mb-1.5">CLIENT COMMAND — Run on jump host:</div>
            <div className="relative group rounded-xl border border-amber-500/20 bg-amber-500/5 p-3">
              <code className="text-[10px] font-mono text-amber-300/80 break-all">{clientCmd}</code>
              <button
                onClick={() => copy(clientCmd)}
                className="absolute top-2 right-2 p-1.5 rounded opacity-0 group-hover:opacity-100 transition-opacity"
                style={{ background: '#f59e0b20' }}
              >
                <Copy className="w-3 h-3 text-amber-400" />
              </button>
            </div>
          </div>
        )}
      </div>
    )
  }

  if (mode === 'LIGOLO') {
    const s = ligoloStatusQ.data
    const isRunning = s?.running ?? false
    return (
      <div className="space-y-4">
        <TunnelViz mode="LIGOLO (TUN)" isActive={isRunning} />
        <div className="flex items-center justify-between px-4 py-2.5 rounded-xl border" style={{ borderColor: isRunning ? '#34d39930' : '#ffffff08', background: isRunning ? '#34d39908' : '#ffffff04' }}>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full" style={{ background: isRunning ? '#34d399' : '#ffffff25', boxShadow: isRunning ? '0 0 6px #34d399' : undefined }} />
            <span className="font-mono text-xs" style={{ color: isRunning ? '#34d399' : '#ffffff40' }}>
              {isRunning ? `RUNNING — PID ${s?.pid ?? '?'} — PORT ${s?.port ?? cfg.proxy_port} — TUN: ${s?.tun_interface}` : 'STOPPED'}
            </span>
          </div>
        </div>
        <div className="flex gap-3">
          <button onClick={() => ligoloStartMut.mutate()} disabled={isRunning || ligoloStartMut.isPending}
            className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-xl border font-mono font-bold text-sm disabled:opacity-30 transition-all"
            style={{ background: '#34d39910', borderColor: '#34d39930', color: '#34d399' }}>
            {ligoloStartMut.isPending ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            START PROXY
          </button>
          <button onClick={() => ligoloStopMut.mutate()} disabled={!isRunning || ligoloStopMut.isPending}
            className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-xl border font-mono font-bold text-sm disabled:opacity-30 transition-all"
            style={{ background: '#f4717110', borderColor: '#f4717130', color: '#f47171' }}>
            {ligoloStopMut.isPending ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Square className="w-4 h-4" />}
            STOP PROXY
          </button>
        </div>
        {isRunning && (
          <div>
            <div className="text-[8px] font-mono text-emerald-500/40 tracking-widest uppercase mb-2">ROUTED NETWORKS</div>
            <div className="flex gap-2 mb-2">
              <input
                value={newRoute}
                onChange={e => setNewRoute(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && newRoute && addRouteMut.mutate(newRoute)}
                placeholder="10.10.0.0/24"
                className="flex-1 bg-black/60 border border-emerald-500/20 rounded-lg px-3 py-1.5 font-mono text-sm text-white/70 placeholder-white/15 focus:outline-none focus:border-emerald-400/40"
              />
              <button
                onClick={() => newRoute && addRouteMut.mutate(newRoute)}
                disabled={!newRoute || addRouteMut.isPending}
                className="px-3 py-1.5 rounded-lg border font-mono text-xs font-bold disabled:opacity-40 transition-all"
                style={{ background: '#34d39910', borderColor: '#34d39930', color: '#34d399' }}
              >
                + ADD
              </button>
            </div>
            <div className="space-y-1.5">
              {(s?.routes ?? []).map(r => (
                <div key={r} className="flex items-center px-3 py-1.5 rounded-lg border" style={{ borderColor: '#34d39920', background: '#34d39908' }}>
                  <span className="font-mono text-xs text-emerald-300/70 flex-1">{r}</span>
                  <span className="text-[9px] font-mono text-emerald-400/30">via {String(cfg.tun_interface ?? 'ligolo')}</span>
                </div>
              ))}
              {!s?.routes?.length && (
                <div className="text-[10px] font-mono text-white/20 px-3 py-2">No routes added yet.</div>
              )}
            </div>
          </div>
        )}
      </div>
    )
  }

  if (mode === 'MANAGED_SSH_SOCKS') {
    const session = tunnelStatusQ.data
    const isActive = session?.status === 'ACTIVE'
    const endpoint = session?.tunnel_endpoint

    return (
      <div className="space-y-4">
        <TunnelViz mode="SSH -D SOCKS" isActive={isActive ?? false} />
        <div className="flex items-center justify-between px-4 py-2.5 rounded-xl border"
          style={{ borderColor: isActive ? '#38bdf830' : '#ffffff08', background: isActive ? '#38bdf808' : '#ffffff04' }}>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full" style={{ background: isActive ? '#38bdf8' : '#ffffff25', boxShadow: isActive ? '0 0 6px #38bdf8' : undefined }} />
            <span className="font-mono text-xs" style={{ color: isActive ? '#38bdf8' : '#ffffff40' }}>
              {isActive
                ? `ACTIVE — PID ${session?.process_pid ?? '?'} — ${session?.local_host}:${session?.local_port}`
                : session?.status === 'FAILED' ? `FAILED: ${session.error_summary?.slice(0, 60) ?? 'unknown error'}`
                : 'STOPPED'}
            </span>
          </div>
          {endpoint && (
            <span className="font-mono text-[9px] text-white/30">{endpoint}</span>
          )}
        </div>
        {cfg.auth_method === 'password_dev' && (
          <div>
            <div className="text-[8px] font-mono text-white/30 tracking-widest uppercase mb-1">SSH PASSWORD</div>
            <input
              type="password"
              value={sshPassword}
              onChange={e => setSshPassword(e.target.value)}
              placeholder="Password for jumpbox (not stored)"
              className="w-full bg-black/60 border border-sky-500/20 rounded-xl px-4 py-2 font-mono text-sm text-white/70 placeholder-white/15 focus:outline-none focus:border-sky-400/40"
            />
          </div>
        )}
        <div className="flex gap-3">
          <button onClick={() => tunnelStartMut.mutate()} disabled={isActive || tunnelStartMut.isPending}
            className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-xl border font-mono font-bold text-sm disabled:opacity-30 transition-all"
            style={{ background: '#34d39910', borderColor: '#34d39930', color: '#34d399' }}>
            {tunnelStartMut.isPending ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            START TUNNEL
          </button>
          <button onClick={() => tunnelStopMut.mutate()} disabled={!isActive || tunnelStopMut.isPending}
            className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-xl border font-mono font-bold text-sm disabled:opacity-30 transition-all"
            style={{ background: '#f4717110', borderColor: '#f4717130', color: '#f47171' }}>
            {tunnelStopMut.isPending ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Square className="w-4 h-4" />}
            STOP TUNNEL
          </button>
        </div>
        {session?.sanitized_command_preview && (
          <div>
            <div className="text-[8px] font-mono text-sky-500/40 tracking-widest uppercase mb-1.5">SSH COMMAND PREVIEW</div>
            <div className="rounded-xl border border-sky-500/15 bg-sky-500/5 p-3 font-mono text-[10px] text-sky-300/70 break-all">
              {session.sanitized_command_preview}
            </div>
          </div>
        )}
      </div>
    )
  }

  return <div className="text-sm font-mono text-white/30 p-4">No tunnel management available for {mode}.</div>
}
