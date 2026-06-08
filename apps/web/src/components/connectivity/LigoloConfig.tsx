'use client'

import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, Play, Square } from 'lucide-react'
import { connectivityApi, type ConnectivityProfile } from '@/lib/connectivityApi'
import { PanelShell, ConfigField, CInput, SaveBar } from './shared'

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

export function LigoloConfig({
  profile, onSaved, onCancel,
}: {
  profile: ConnectivityProfile | null
  onSaved: (p: ConnectivityProfile) => void
  onCancel: () => void
}) {
  const qc = useQueryClient()
  const cfg = (profile?.config ?? {}) as Record<string, unknown>
  const [name, setName] = useState(profile?.name ?? 'Ligolo-ng')
  const [proxyPort, setProxyPort] = useState(String(cfg.proxy_port ?? '11601'))
  const [tunIface, setTunIface] = useState(String(cfg.tun_interface ?? 'ligolo'))
  const [newRoute, setNewRoute] = useState('')
  const [notes, setNotes] = useState(profile?.notes ?? '')
  const [targetDomain, setTargetDomain] = useState(String(cfg.target_domain ?? ''))
  const [dcIp, setDcIp] = useState(String(cfg.dc_ip ?? ''))
  const [dcHostname, setDcHostname] = useState(String(cfg.dc_hostname ?? ''))
  const [dnsServer, setDnsServer] = useState(String(cfg.dns_server ?? ''))
  const [baseDn, setBaseDn] = useState(String(cfg.base_dn ?? ''))
  const [targetSubnets, setTargetSubnets] = useState(String((cfg.target_subnets as string[] | undefined)?.join(', ') ?? ''))
  const hasTargetData = !!(cfg.target_domain || cfg.dc_ip || cfg.dc_hostname || cfg.dns_server || cfg.base_dn || (cfg.target_subnets as string[] | undefined)?.length)
  const [showTarget, setShowTarget] = useState(hasTargetData)

  const { data: status, refetch } = useQuery({
    queryKey: ['ligolo-status', profile?.id],
    queryFn: () => connectivityApi.ligoloStatus(profile!.id),
    enabled: !!profile && profile.mode === 'LIGOLO',
    refetchInterval: 4000,
  })

  const saveMut = useMutation({
    mutationFn: () => {
      const config = {
        proxy_port: parseInt(proxyPort, 10),
        tun_interface: tunIface,
        ...(targetDomain && { target_domain: targetDomain }),
        ...(dcIp && { dc_ip: dcIp }),
        ...(dcHostname && { dc_hostname: dcHostname }),
        ...(dnsServer && { dns_server: dnsServer }),
        ...(baseDn && { base_dn: baseDn }),
        ...(targetSubnets && { target_subnets: targetSubnets.split(',').map(s => s.trim()).filter(Boolean) }),
      }
      return profile
        ? connectivityApi.updateProfile(profile.id, { name, config, notes: notes || undefined })
        : connectivityApi.createProfile({ name, mode: 'LIGOLO', config, notes: notes || undefined })
    },
    onSuccess: (p) => { qc.invalidateQueries({ queryKey: ['connectivity-profiles'] }); onSaved(p) },
  })

  const startMut = useMutation({
    mutationFn: () => connectivityApi.ligoloStart(profile!.id),
    onSuccess: () => refetch(),
  })

  const stopMut = useMutation({
    mutationFn: () => connectivityApi.ligoloStop(profile!.id),
    onSuccess: () => refetch(),
  })

  const addRouteMut = useMutation({
    mutationFn: (cidr: string) => connectivityApi.ligoloAddRoute(profile!.id, cidr),
    onSuccess: () => { setNewRoute(''); refetch() },
  })

  return (
    <PanelShell title="LIGOLO-NG" color="#34d399">
      <div className="p-3 rounded-xl bg-emerald-500/5 border border-emerald-500/10 text-xs font-mono text-emerald-400/60">
        TUN-based full network routing. No SOCKS proxy needed — kernel routes traffic through the ligolo TUN interface.
        Requires <code className="text-emerald-300/80">CAP_NET_ADMIN</code> or root.
      </div>
      <ConfigField label="Profile Name">
        <CInput value={name} onChange={setName} placeholder="e.g. Corp Internal Segment" />
      </ConfigField>
      <div className="grid grid-cols-2 gap-3">
        <ConfigField label="Proxy Listen Port">
          <CInput value={proxyPort} onChange={setProxyPort} type="number" />
        </ConfigField>
        <ConfigField label="TUN Interface">
          <CInput value={tunIface} onChange={setTunIface} placeholder="ligolo" />
        </ConfigField>
      </div>
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
              <div className={`w-2 h-2 rounded-full ${status?.running ? 'bg-emerald-400 animate-pulse' : 'bg-white/20'}`} />
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
          <div>
            <div className="text-xs font-mono text-emerald-500/50 tracking-widest uppercase mb-2">ROUTED NETWORKS</div>
            <div className="flex gap-2 mb-2">
              <input value={newRoute} onChange={e => setNewRoute(e.target.value)}
                placeholder="10.10.0.0/24"
                className="flex-1 bg-black border border-emerald-500/20 rounded-lg px-3 py-1.5 font-mono text-sm text-white/70 placeholder-white/15 focus:outline-none focus:border-emerald-400/40"
              />
              <button onClick={() => newRoute && addRouteMut.mutate(newRoute)}
                className="flex items-center gap-1 px-3 py-1.5 rounded-lg border border-emerald-500/30 text-emerald-400 text-xs font-mono hover:bg-emerald-500/10 transition-all">
                <Plus className="w-3 h-3" />ADD
              </button>
            </div>
            <div className="space-y-1.5">
              {(status?.routes ?? []).map(r => (
                <div key={r} className="flex items-center justify-between px-3 py-1.5 rounded-lg bg-emerald-500/5 border border-emerald-500/10">
                  <span className="font-mono text-xs text-emerald-300/70">{r}</span>
                  <span className="text-[10px] font-mono text-emerald-400/40">via {tunIface}</span>
                </div>
              ))}
              {(status?.routes ?? []).length === 0 && (
                <div className="text-xs font-mono text-white/20 px-3 py-2">No routes. Add a CIDR above.</div>
              )}
            </div>
          </div>
        </div>
      )}
    </PanelShell>
  )
}
