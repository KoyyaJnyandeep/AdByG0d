'use client'

import { copyText } from '@/lib/clipboard'
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import { Copy, KeyRound, Play, Square } from 'lucide-react'
import { connectivityApi, type ConnectivityProfile } from '@/lib/connectivityApi'
import { PanelShell, ConfigField, CInput, SaveBar } from './shared'

const REDACTED = '***REDACTED***'
const visibleSecret = (value: unknown) => typeof value === 'string' && value !== REDACTED ? value : ''

function saveErrorMessage(error: unknown): string | null {
  if (!error) return null
  const detail = (error as { response?: { data?: { detail?: unknown } } }).response?.data?.detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) {
    return detail
      .map((item) => {
        if (typeof item === 'string') return item
        if (item && typeof item === 'object' && 'msg' in item) return String(item.msg)
        return null
      })
      .filter(Boolean)
      .join('; ')
  }
  if (error instanceof Error) return error.message
  return 'Failed to save profile'
}

export function ChiselConfig({
  profile, onSaved, onCancel,
}: {
  profile: ConnectivityProfile | null
  onSaved: (p: ConnectivityProfile) => void
  onCancel: () => void
}) {
  const qc = useQueryClient()
  const cfg = (profile?.config ?? {}) as Record<string, unknown>
  const [name, setName] = useState(profile?.name ?? 'Chisel Tunnel')
  const [serverPort, setServerPort] = useState(String(cfg.server_port ?? '8080'))
  const [socksPort, setSocksPort] = useState(String(cfg.socks_port ?? '1080'))
  const [authToken, setAuthToken] = useState(visibleSecret(cfg.auth_token))
  const [notes, setNotes] = useState(profile?.notes ?? '')
  const [copied, setCopied] = useState(false)
  const [targetDomain, setTargetDomain] = useState(String(cfg.target_domain ?? ''))
  const [dcIp, setDcIp] = useState(String(cfg.dc_ip ?? ''))
  const [dcHostname, setDcHostname] = useState(String(cfg.dc_hostname ?? ''))
  const [dnsServer, setDnsServer] = useState(String(cfg.dns_server ?? ''))
  const [baseDn, setBaseDn] = useState(String(cfg.base_dn ?? ''))
  const [targetSubnets, setTargetSubnets] = useState(String((cfg.target_subnets as string[] | undefined)?.join(', ') ?? ''))
  const hasTargetData = !!(cfg.target_domain || cfg.dc_ip || cfg.dc_hostname || cfg.dns_server || cfg.base_dn || (cfg.target_subnets as string[] | undefined)?.length)
  const [showTarget, setShowTarget] = useState(hasTargetData)

  const { data: status, refetch: refetchStatus } = useQuery({
    queryKey: ['chisel-status', profile?.id],
    queryFn: () => connectivityApi.chiselStatus(profile!.id),
    enabled: !!profile && profile.mode === 'CHISEL',
    refetchInterval: 3000,
  })

  const saveMut = useMutation({
    mutationFn: () => {
      const config: Record<string, unknown> = {
        server_port: parseInt(serverPort, 10),
        socks_port: parseInt(socksPort, 10),
        ...(targetDomain && { target_domain: targetDomain }),
        ...(dcIp && { dc_ip: dcIp }),
        ...(dcHostname && { dc_hostname: dcHostname }),
        ...(dnsServer && { dns_server: dnsServer }),
        ...(baseDn && { base_dn: baseDn }),
        ...(targetSubnets && { target_subnets: targetSubnets.split(',').map(s => s.trim()).filter(Boolean) }),
      }
      if (authToken) config.auth_token = authToken
      return profile
        ? connectivityApi.updateProfile(profile.id, { name, config, notes: notes || undefined })
        : connectivityApi.createProfile({ name, mode: 'CHISEL', config, notes: notes || undefined })
    },
    onSuccess: (p) => { qc.invalidateQueries({ queryKey: ['connectivity-profiles'] }); onSaved(p) },
  })

  const startMut = useMutation({
    mutationFn: () => connectivityApi.chiselStart(profile!.id),
    onSuccess: () => refetchStatus(),
  })

  const stopMut = useMutation({
    mutationFn: () => connectivityApi.chiselStop(profile!.id),
    onSuccess: () => refetchStatus(),
  })

  const clearTokenMut = useMutation({
    mutationFn: () => connectivityApi.updateProfile(profile!.id, { config: { auth_token: null } }),
    onSuccess: (p) => {
      setAuthToken('')
      qc.invalidateQueries({ queryKey: ['connectivity-profiles'] })
      onSaved(p)
      refetchStatus()
    },
  })

  const rawClientCmd = status?.client_cmd_template ?? (cfg.client_cmd_template as string | undefined)
  const clientCmd = rawClientCmd && rawClientCmd !== REDACTED ? rawClientCmd : undefined

  const copyCmd = () => {
    if (clientCmd) {
      copyText(clientCmd)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  return (
    <PanelShell title="CHISEL TUNNEL" color="#f59e0b">
      <div className="p-3 rounded-xl bg-amber-500/5 border border-amber-500/10 text-xs font-mono text-amber-400/60">
        AdByG0d spawns <code className="text-amber-300/80">chisel server --reverse --socks5</code>. Run the generated client command on your jump host.
      </div>
      <ConfigField label="Profile Name">
        <CInput value={name} onChange={setName} placeholder="e.g. Chisel via Jump01" />
      </ConfigField>
      <div className="grid grid-cols-2 gap-3">
        <ConfigField label="Server Port" hint="chisel server listens here">
          <CInput value={serverPort} onChange={setServerPort} type="number" />
        </ConfigField>
        <ConfigField label="SOCKS5 Port" hint="local SOCKS5 proxy port">
          <CInput value={socksPort} onChange={setSocksPort} type="number" />
        </ConfigField>
      </div>
      <ConfigField label="Auth Token" hint="optional — leave blank for no auth">
        <CInput value={authToken} onChange={setAuthToken} placeholder={cfg.auth_token === REDACTED ? 'Stored token unchanged' : 'secret-token'} />
      </ConfigField>
      {profile && cfg.auth_token === REDACTED && (
        <button
          type="button"
          onClick={() => clearTokenMut.mutate()}
          disabled={clearTokenMut.isPending}
          className="flex items-center justify-center gap-2 rounded-xl border border-amber-500/25 bg-amber-500/5 px-3 py-2 text-xs font-mono text-amber-300/70 transition-all hover:bg-amber-500/10 disabled:opacity-40"
        >
          <KeyRound className="h-3.5 w-3.5" />
          {clearTokenMut.isPending ? 'CLEARING TOKEN...' : 'CLEAR STORED TOKEN'}
        </button>
      )}
      <ConfigField label="Notes">
        <CInput value={notes} onChange={setNotes} />
      </ConfigField>
      {/* Target Details */}
      <div className="border-t border-white/5 pt-4">
        <button
          type="button"
          onClick={() => setShowTarget(v => !v)}
          className="flex items-center gap-2 text-xs font-mono text-white/30 hover:text-white/60 transition-colors tracking-widest uppercase"
        >
          <span>{showTarget ? '▼' : '▶'}</span>
          TARGET DETAILS (Optional)
        </button>
        {showTarget && (
          <div className="mt-4 space-y-3">
            <div className="text-[11px] font-mono text-white/20 mb-2">
              Store DC details here to make this a reusable connection profile.
            </div>
            <ConfigField label="Target Domain">
              <CInput value={targetDomain} onChange={setTargetDomain} placeholder="corp.local" />
            </ConfigField>
            <div className="grid grid-cols-2 gap-3">
              <ConfigField label="DC IP">
                <CInput value={dcIp} onChange={setDcIp} placeholder="10.10.0.1" />
              </ConfigField>
              <ConfigField label="DC Hostname">
                <CInput value={dcHostname} onChange={setDcHostname} placeholder="dc01.corp.local" />
              </ConfigField>
            </div>
            <ConfigField label="DNS Server" hint="Override system DNS for this target">
              <CInput value={dnsServer} onChange={setDnsServer} placeholder="10.10.0.1" />
            </ConfigField>
            <ConfigField label="Base DN" hint="Auto-derived from domain if blank">
              <CInput value={baseDn} onChange={setBaseDn} placeholder="DC=corp,DC=local" />
            </ConfigField>
            <ConfigField label="Target Subnets" hint="Comma-separated CIDRs">
              <CInput value={targetSubnets} onChange={setTargetSubnets} placeholder="10.10.0.0/24, 192.168.1.0/24" />
            </ConfigField>
          </div>
        )}
      </div>
      <SaveBar onSave={() => saveMut.mutate()} onCancel={onCancel} saving={saveMut.isPending} error={saveErrorMessage(saveMut.error)} />

      {profile && (
        <div className="mt-6 pt-6 border-t border-white/5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className={`w-2 h-2 rounded-full ${status?.running ? 'bg-green-400 animate-pulse' : 'bg-white/20'}`} />
              <span className="text-xs font-mono text-white/50">
                {status?.running ? `RUNNING — PID ${status.pid}` : 'STOPPED'}
              </span>
            </div>
            <div className="flex gap-2">
              <button onClick={() => startMut.mutate()} disabled={status?.running || startMut.isPending}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-green-500/30 text-green-400 text-xs font-mono hover:bg-green-500/10 disabled:opacity-30 transition-all">
                <Play className="w-3 h-3" />START
              </button>
              <button onClick={() => stopMut.mutate()} disabled={!status?.running || stopMut.isPending}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-red-500/30 text-red-400 text-xs font-mono hover:bg-red-500/10 disabled:opacity-30 transition-all">
                <Square className="w-3 h-3" />STOP
              </button>
            </div>
          </div>
          {clientCmd && (
            <div>
              <div className="text-xs font-mono text-amber-500/50 tracking-widest uppercase mb-2">CLIENT COMMAND TEMPLATE — Replace &lt;TOKEN&gt; on jump host:</div>
              <div className="relative group rounded-xl border border-amber-500/20 bg-amber-500/5 p-4">
                <code className="text-xs font-mono text-amber-300/80 break-all">{clientCmd}</code>
                <button onClick={copyCmd}
                  className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity p-1.5 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 text-amber-400">
                  <Copy className="w-3 h-3" />
                </button>
                {copied && (
                  <motion.div initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }}
                    className="absolute top-2 right-8 text-[10px] font-mono text-green-400 bg-green-500/20 px-2 py-1 rounded">
                    COPIED
                  </motion.div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </PanelShell>
  )
}
