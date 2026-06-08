'use client'

import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
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

export function Socks5Config({
  profile, onSaved, onCancel,
}: {
  profile: ConnectivityProfile | null
  onSaved: (p: ConnectivityProfile) => void
  onCancel: () => void
}) {
  const qc = useQueryClient()
  const cfg = (profile?.config ?? {}) as Record<string, unknown>
  const [name, setName] = useState(profile?.name ?? 'SOCKS5 Tunnel')
  const [proxyHost, setProxyHost] = useState(String(cfg.proxy_host ?? '127.0.0.1'))
  const [proxyPort, setProxyPort] = useState(String(cfg.proxy_port ?? '1080'))
  const [notes, setNotes] = useState(profile?.notes ?? '')
  const [targetDomain, setTargetDomain] = useState(String(cfg.target_domain ?? ''))
  const [dcIp, setDcIp] = useState(String(cfg.dc_ip ?? ''))
  const [dcHostname, setDcHostname] = useState(String(cfg.dc_hostname ?? ''))
  const [dnsServer, setDnsServer] = useState(String(cfg.dns_server ?? ''))
  const [baseDn, setBaseDn] = useState(String(cfg.base_dn ?? ''))
  const [targetSubnets, setTargetSubnets] = useState(String((cfg.target_subnets as string[] | undefined)?.join(', ') ?? ''))
  const hasTargetData = !!(cfg.target_domain || cfg.dc_ip || cfg.dc_hostname || cfg.dns_server || cfg.base_dn || (cfg.target_subnets as string[] | undefined)?.length)
  const [showTarget, setShowTarget] = useState(hasTargetData)

  const mut = useMutation({
    mutationFn: () => {
      const config = {
        proxy_host: proxyHost,
        proxy_port: parseInt(proxyPort, 10),
        ...(targetDomain && { target_domain: targetDomain }),
        ...(dcIp && { dc_ip: dcIp }),
        ...(dcHostname && { dc_hostname: dcHostname }),
        ...(dnsServer && { dns_server: dnsServer }),
        ...(baseDn && { base_dn: baseDn }),
        ...(targetSubnets && { target_subnets: targetSubnets.split(',').map(s => s.trim()).filter(Boolean) }),
      }
      return profile
        ? connectivityApi.updateProfile(profile.id, { name, config, notes: notes || undefined })
        : connectivityApi.createProfile({ name, mode: 'SOCKS5', config, notes: notes || undefined })
    },
    onSuccess: (p) => { qc.invalidateQueries({ queryKey: ['connectivity-profiles'] }); onSaved(p) },
  })

  return (
    <PanelShell title="SOCKS5 TUNNEL" color="#a78bfa">
      <div className="p-3 rounded-xl bg-purple-500/5 border border-purple-500/10 text-xs font-mono text-purple-400/60">
        Use an existing SOCKS5 proxy. Works with: <code className="text-purple-300/80">ssh -D</code>, Metasploit, any SOCKS5 tool.
      </div>
      <ConfigField label="Profile Name">
        <CInput value={name} onChange={setName} placeholder="e.g. SSH Tunnel to Jump Host" />
      </ConfigField>
      <div className="grid grid-cols-[1fr_120px] gap-3">
        <ConfigField label="Proxy Host">
          <CInput value={proxyHost} onChange={setProxyHost} placeholder="127.0.0.1" />
        </ConfigField>
        <ConfigField label="Port">
          <CInput value={proxyPort} onChange={setProxyPort} placeholder="1080" type="number" />
        </ConfigField>
      </div>
      <ConfigField label="Notes">
        <CInput value={notes} onChange={setNotes} placeholder="e.g. ssh -D 1080 user@jump-host" />
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
      <SaveBar onSave={() => mut.mutate()} onCancel={onCancel} saving={mut.isPending} error={saveErrorMessage(mut.error)} />
    </PanelShell>
  )
}
