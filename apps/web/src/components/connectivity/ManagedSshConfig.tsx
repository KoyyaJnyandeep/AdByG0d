'use client'

import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { KeyRound } from 'lucide-react'
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

export function ManagedSshConfig({
  profile, onSaved, onCancel,
}: {
  profile: ConnectivityProfile | null
  onSaved: (p: ConnectivityProfile) => void
  onCancel: () => void
}) {
  const qc = useQueryClient()
  const cfg = (profile?.config ?? {}) as Record<string, unknown>
  const [name, setName] = useState(profile?.name ?? 'Managed SSH SOCKS')
  const [jumpboxHost, setJumpboxHost] = useState(String(cfg.jumpbox_host ?? ''))
  const [jumpboxPort, setJumpboxPort] = useState(String(cfg.jumpbox_port ?? '22'))
  const [jumpboxUsername, setJumpboxUsername] = useState(String(cfg.jumpbox_username ?? ''))
  const [authMethod, setAuthMethod] = useState(String(cfg.auth_method ?? 'ssh_key'))
  const [sshKeyPath, setSshKeyPath] = useState(String(cfg.ssh_key_path ?? ''))
  const [password, setPassword] = useState('')
  const [notes, setNotes] = useState(profile?.notes ?? '')
  const [targetDomain, setTargetDomain] = useState(String(cfg.target_domain ?? ''))
  const [dcIp, setDcIp] = useState(String(cfg.dc_ip ?? ''))
  const [dcHostname, setDcHostname] = useState(String(cfg.dc_hostname ?? ''))
  const [targetSubnets, setTargetSubnets] = useState(String((cfg.target_subnets as string[] | undefined)?.join(', ') ?? ''))
  const hasTargetData = !!(cfg.target_domain || cfg.dc_ip || cfg.dc_hostname || (cfg.target_subnets as string[] | undefined)?.length)
  const [showTarget, setShowTarget] = useState(hasTargetData)

  const statusQ = useQuery({
    queryKey: ['managed-ssh-status', profile?.id],
    queryFn: () => connectivityApi.tunnelStatus(profile!.id),
    enabled: !!profile,
    refetchInterval: 5000,
    retry: false,
  })

  const saveMut = useMutation({
    mutationFn: () => {
      const config = {
        jumpbox_host: jumpboxHost,
        jumpbox_port: parseInt(jumpboxPort, 10),
        jumpbox_username: jumpboxUsername,
        auth_method: authMethod,
        ...(sshKeyPath && { ssh_key_path: sshKeyPath }),
        ...(targetDomain && { target_domain: targetDomain }),
        ...(dcIp && { dc_ip: dcIp }),
        ...(dcHostname && { dc_hostname: dcHostname }),
        ...(targetSubnets && { target_subnets: targetSubnets.split(',').map(s => s.trim()).filter(Boolean) }),
      }
      return profile
        ? connectivityApi.updateProfile(profile.id, { name, config, notes: notes || undefined })
        : connectivityApi.createProfile({ name, mode: 'MANAGED_SSH_SOCKS', config, notes: notes || undefined })
    },
    onSuccess: (p) => { qc.invalidateQueries({ queryKey: ['connectivity-profiles'] }); onSaved(p) },
  })

  const startMut = useMutation({
    mutationFn: () => connectivityApi.tunnelStart(profile!.id, authMethod === 'password_dev' ? password : undefined),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['managed-ssh-status', profile?.id] })
      qc.invalidateQueries({ queryKey: ['connectivity-profiles'] })
      setPassword('')
    },
  })

  const stopMut = useMutation({
    mutationFn: () => connectivityApi.tunnelStop(profile!.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['managed-ssh-status', profile?.id] })
      qc.invalidateQueries({ queryKey: ['connectivity-profiles'] })
    },
  })

  const session = statusQ.data
  const active = session?.status === 'active'

  return (
    <PanelShell title="MANAGED SSH SOCKS" color="#38bdf8">
      <div className="p-3 rounded-xl bg-sky-500/5 border border-sky-500/10 text-xs font-mono text-sky-300/60 space-y-1">
        <div className="flex items-center gap-2">
          <KeyRound className="w-3.5 h-3.5" />
          <span>AdByG0d starts <code>ssh -N -D 127.0.0.1:&lt;auto&gt;</code> and keeps the SOCKS tunnel active until stopped.</span>
        </div>
        {session?.tunnel_endpoint && <div className="text-sky-200/70">ACTIVE: {session.tunnel_endpoint}</div>}
        {session?.error_summary && <div className="text-red-300/70">{session.error_summary}</div>}
      </div>

      <ConfigField label="Profile Name"><CInput value={name} onChange={setName} /></ConfigField>
      <div className="grid grid-cols-[1fr_110px] gap-3">
        <ConfigField label="Jumpbox Host"><CInput value={jumpboxHost} onChange={setJumpboxHost} placeholder="10.10.10.5" /></ConfigField>
        <ConfigField label="SSH Port"><CInput value={jumpboxPort} onChange={setJumpboxPort} type="number" /></ConfigField>
      </div>
      <ConfigField label="Jumpbox Username"><CInput value={jumpboxUsername} onChange={setJumpboxUsername} placeholder="kali" /></ConfigField>
      <ConfigField label="Auth Method">
        <select
          value={authMethod}
          onChange={e => setAuthMethod(e.target.value)}
          className="w-full bg-black border border-cyan-500/20 rounded-xl px-4 py-2.5 font-mono text-sm text-white/80 focus:outline-none focus:border-cyan-400/50"
        >
          <option value="ssh_key">SSH key / agent</option>
          <option value="password_dev">Password dev mode</option>
        </select>
      </ConfigField>
      {authMethod === 'ssh_key' && (
        <ConfigField label="SSH Key Path" hint="Optional server-side key path; leave blank for ssh-agent/default keys.">
          <CInput value={sshKeyPath} onChange={setSshKeyPath} placeholder="/home/user/.ssh/id_rsa" />
        </ConfigField>
      )}
      {authMethod === 'password_dev' && profile && (
        <ConfigField label="Runtime Password" hint="Used only for this start request; not stored.">
          <CInput value={password} onChange={setPassword} type="password" placeholder="SSH password" />
        </ConfigField>
      )}
      <ConfigField label="Notes"><CInput value={notes} onChange={setNotes} /></ConfigField>

      <div className="border-t border-white/5 pt-4">
        <button type="button" onClick={() => setShowTarget(v => !v)} className="flex items-center gap-2 text-xs font-mono text-white/30 hover:text-white/60 transition-colors tracking-widest uppercase">
          <span>{showTarget ? '▼' : '▶'}</span> TARGET DETAILS (Optional)
        </button>
        {showTarget && (
          <div className="mt-4 space-y-3">
            <ConfigField label="Target Domain"><CInput value={targetDomain} onChange={setTargetDomain} placeholder="corp.local" /></ConfigField>
            <div className="grid grid-cols-2 gap-3">
              <ConfigField label="DC IP"><CInput value={dcIp} onChange={setDcIp} placeholder="10.10.0.10" /></ConfigField>
              <ConfigField label="DC Hostname"><CInput value={dcHostname} onChange={setDcHostname} placeholder="dc01.corp.local" /></ConfigField>
            </div>
            <ConfigField label="Target Subnets" hint="Comma-separated CIDRs"><CInput value={targetSubnets} onChange={setTargetSubnets} placeholder="10.10.0.0/24" /></ConfigField>
          </div>
        )}
      </div>

      <SaveBar onSave={() => saveMut.mutate()} onCancel={onCancel} saving={saveMut.isPending} error={saveErrorMessage(saveMut.error)} />

      {profile && (
        <div className="flex gap-3 pt-2">
          <button disabled={startMut.isPending || active} onClick={() => startMut.mutate()} className="flex-1 py-2.5 rounded-xl border border-sky-500/40 text-sky-300 font-mono text-sm disabled:opacity-40">START TUNNEL</button>
          <button disabled={stopMut.isPending || !active} onClick={() => stopMut.mutate()} className="flex-1 py-2.5 rounded-xl border border-red-500/40 text-red-300 font-mono text-sm disabled:opacity-40">STOP TUNNEL</button>
        </div>
      )}
    </PanelShell>
  )
}
