'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Shield, Target, Globe, Cpu, Users, RotateCcw, Edit2, Check, X } from 'lucide-react'
import { sessionApi, type AuthLevel, type SessionUpdateRequest } from '@/lib/sessionApi'
import { cn } from '@/lib/utils'

const MONO = { fontFamily: 'JetBrains Mono, monospace' }

const AUTH_COLORS: Record<AuthLevel, string> = {
  anon:         '#64748b',
  authenticated:'#60a5fa',
  local_admin:  '#fbbf24',
  domain_admin: '#f97316',
  da_forest:    '#ef4444',
  system:       '#a855f7',
}

const AUTH_LABELS: Record<AuthLevel, string> = {
  anon:         'ANON',
  authenticated:'AUTH',
  local_admin:  'LOCAL_ADMIN',
  domain_admin: 'DOMAIN_ADMIN',
  da_forest:    'DA_FOREST',
  system:       'SYSTEM',
}

const AUTH_LEVELS: AuthLevel[] = ['anon','authenticated','local_admin','domain_admin','da_forest','system']

function InlineEdit({ value, onSave, placeholder }: { value: string | null; onSave: (v: string) => void; placeholder: string }) {
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState(value ?? '')

  if (editing) return (
    <span className="flex items-center gap-1">
      <input
        autoFocus
        value={draft}
        onChange={e => setDraft(e.target.value)}
        onKeyDown={e => { if (e.key === 'Enter') { onSave(draft); setEditing(false) } if (e.key === 'Escape') setEditing(false) }}
        className="w-28 rounded border border-cyan-500/40 bg-black/60 px-1.5 py-0.5 text-[10px] text-cyan-300 outline-none"
        style={MONO}
        placeholder={placeholder}
      />
      <button onClick={() => { onSave(draft); setEditing(false) }} className="text-green-400 hover:text-green-300"><Check className="h-3 w-3" /></button>
      <button onClick={() => setEditing(false)} className="text-red-400 hover:text-red-300"><X className="h-3 w-3" /></button>
    </span>
  )

  return (
    <button onClick={() => { setDraft(value ?? ''); setEditing(true) }} className="group flex items-center gap-1">
      <span className={cn('text-[10px]', value ? 'text-zinc-200' : 'text-zinc-600 italic')} style={MONO}>
        {value ?? placeholder}
      </span>
      <Edit2 className="h-2.5 w-2.5 text-zinc-600 opacity-0 group-hover:opacity-100 transition-opacity" />
    </button>
  )
}

export function SessionBar() {
  const qc = useQueryClient()
  const { data: session } = useQuery({
    queryKey: ['session'],
    queryFn: sessionApi.get,
    refetchInterval: 15_000,
  })

  const updateMut = useMutation({
    mutationFn: (body: SessionUpdateRequest) => sessionApi.update(body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['session'] }),
  })

  const resetMut = useMutation({
    mutationFn: sessionApi.reset,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['session'] }),
  })

  if (!session) return null

  const authColor = AUTH_COLORS[session.auth_level]

  return (
    <div
      className="sticky top-0 z-50 flex items-center gap-4 border-b border-white/5 bg-black/90 px-4 py-1.5 backdrop-blur-md"
      style={{ fontSize: 10 }}
    >
      <div className="flex items-center gap-1.5">
        <Shield className="h-3 w-3" style={{ color: authColor }} />
        <select
          value={session.auth_level}
          onChange={e => updateMut.mutate({ auth_level: e.target.value as AuthLevel })}
          className="border-0 bg-transparent font-bold uppercase tracking-wider outline-none"
          style={{ ...MONO, color: authColor, fontSize: 10 }}
        >
          {AUTH_LEVELS.map(lvl => (
            <option key={lvl} value={lvl} style={{ background: '#0a0a0a', color: AUTH_COLORS[lvl] }}>
              {AUTH_LABELS[lvl]}
            </option>
          ))}
        </select>
      </div>

      <div className="h-3 w-px bg-white/10" />

      <div className="flex items-center gap-1.5">
        <Target className="h-3 w-3 text-zinc-500" />
        <InlineEdit value={session.target_ip} placeholder="target IP" onSave={v => updateMut.mutate({ target_ip: v })} />
      </div>

      <div className="flex items-center gap-1.5">
        <Globe className="h-3 w-3 text-zinc-500" />
        <InlineEdit value={session.domain} placeholder="domain" onSave={v => updateMut.mutate({ domain: v })} />
      </div>

      <div className="h-3 w-px bg-white/10" />

      <div className="flex items-center gap-3 text-zinc-400">
        <span className="flex items-center gap-1"><Cpu className="h-3 w-3" /><span style={MONO}>{session.machines_owned}</span><span className="text-zinc-600 ml-0.5">owned</span></span>
        <span className="flex items-center gap-1"><Users className="h-3 w-3" /><span style={MONO}>{session.users_owned}</span><span className="text-zinc-600 ml-0.5">users</span></span>
        <span><span style={MONO}>{session.commands_run}</span><span className="text-zinc-600"> cmds</span></span>
        <span><span style={MONO}>{session.findings_count}</span><span className="text-zinc-600"> findings</span></span>
      </div>

      <div className="ml-auto">
        <button
          onClick={() => resetMut.mutate()}
          disabled={resetMut.isPending}
          className="flex items-center gap-1 rounded border border-white/10 bg-white/[0.03] px-2 py-0.5 text-zinc-500 hover:border-red-500/30 hover:text-red-400 transition-colors"
        >
          <RotateCcw className="h-2.5 w-2.5" />
          <span>reset</span>
        </button>
      </div>
    </div>
  )
}
