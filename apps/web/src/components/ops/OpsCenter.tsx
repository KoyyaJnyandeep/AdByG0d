'use client'

import { useState, useEffect, useCallback } from 'react'
import {
  Search, ChevronDown, ChevronRight, Play, Save, RefreshCw, X,
  CheckCircle, XCircle, Clock, Square, Zap, Shield, Terminal,
} from 'lucide-react'
import dynamic from 'next/dynamic'
import { Job, executeJob, listJobs, killJob, getTargetProfile, saveTargetProfile, TargetProfile } from '@/lib/opsApi'
import { AppShell } from '@/components/layout/AppShell'
import { fmtTime, safeDateMs } from '@/lib/utils'

const LiveOutputTerminal = dynamic(() => import('./LiveOutputTerminal'), { ssr: false })

type Risk  = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
type Opsec = 'LOUD' | 'BALANCED' | 'GHOST'

interface TechParam {
  key: string
  label: string
  type: 'text' | 'password' | 'textarea'
  placeholder?: string
  required?: boolean
}

interface Technique {
  id: string
  name: string
  desc: string
  mitre?: string
  risk: Risk
}

interface TechCategory {
  id: string
  label: string
  color: string
  techniques: Technique[]
}

const ARSENAL: TechCategory[] = [
  {
    id: 'recon', label: 'RECONNAISSANCE', color: '#06b6d4',
    techniques: [
      { id: 'ldap_enum',       name: 'LDAP Enum',       desc: 'Full AD object dump — users, groups, computers, SPNs, GPOs, trusts, ACLs',      mitre: 'T1087.002', risk: 'LOW'    },
      { id: 'smb_enum',        name: 'SMB Enum',         desc: 'Enumerate SMB shares via smbclient',                                             mitre: 'T1135',     risk: 'LOW'    },
      { id: 'nmap_scan',       name: 'Nmap Scan',        desc: 'Network port scan with service detection',                                        mitre: 'T1046',     risk: 'MEDIUM' },
      { id: 'rpcdump',         name: 'RPC Dump',         desc: 'Enumerate RPC endpoints and registered services via DCERPC',                      mitre: 'T1135',     risk: 'LOW'    },
      { id: 'lookupsid',       name: 'LookupSID',        desc: 'Brute-force SID enumeration to discover domain principals',                       mitre: 'T1087.002', risk: 'MEDIUM' },
      { id: 'samrdump',        name: 'SAMR Dump',        desc: 'User and group enumeration via Security Account Manager RPC',                     mitre: 'T1087.002', risk: 'MEDIUM' },
      { id: 'netview',         name: 'Netview',          desc: 'Enumerate active logon sessions on domain hosts',                                  mitre: 'T1049',     risk: 'LOW'    },
      { id: 'find_delegation', name: 'Find Delegation',  desc: 'Identify unconstrained, constrained, and resource-based constrained delegations',  mitre: 'T1558',     risk: 'LOW'    },
      { id: 'user_enum',       name: 'User Enum',        desc: 'Enumerate domain users via LDAP or Kerberos pre-auth probing',                    mitre: 'T1087.002', risk: 'LOW'    },
      { id: 'acl_enum',        name: 'ACL Enum',         desc: 'Enumerate object DACLs — find WriteDACL / GenericAll / GenericWrite paths',       mitre: 'T1222',     risk: 'LOW'    },
      { id: 'delegation_enum', name: 'Delegation Enum',  desc: 'Dump full delegation attributes for all domain accounts',                          mitre: 'T1558',     risk: 'LOW'    },
      { id: 'gpo_enum',        name: 'GPO Enum',         desc: 'Enumerate Group Policy Objects and their applied settings',                        mitre: 'T1615',     risk: 'LOW'    },
      { id: 'services_enum',   name: 'Services Enum',    desc: 'List running services on target host via DCERPC',                                  mitre: 'T1007',     risk: 'LOW'    },
      { id: 'reg_query',       name: 'Reg Query',        desc: 'Query Windows registry hive for sensitive configuration values',                   mitre: 'T1012',     risk: 'LOW'    },
    ],
  },
  {
    id: 'kerberos', label: 'KERBEROS ATTACKS', color: '#f59e0b',
    techniques: [
      { id: 'kerberoast',          name: 'Kerberoast',    desc: 'Request TGS tickets for SPN accounts — crack RC4/AES hashes offline',                    mitre: 'T1558.003', risk: 'HIGH'     },
      { id: 'asreproast',          name: 'AS-REP Roast',  desc: 'Harvest $krb5asrep hashes from accounts with pre-auth disabled',                         mitre: 'T1558.004', risk: 'HIGH'     },
      { id: 'getnpusers',          name: 'GetNPUsers',    desc: 'Impacket: AS-REP Roast without credentials — targets no-preauth accounts',               mitre: 'T1558.004', risk: 'HIGH'     },
      { id: 'getuserspns',         name: 'GetUserSPNs',   desc: 'Impacket: Kerberoast — request TGS for all registered SPN accounts',                     mitre: 'T1558.003', risk: 'HIGH'     },
      { id: 'getTGT',              name: 'GetTGT',        desc: 'Request TGT and save as .ccache for pass-the-ticket attacks',                             mitre: 'T1558',     risk: 'MEDIUM'   },
      { id: 'getst',               name: 'GetST (S4U)',   desc: 'S4U2Self + S4U2Proxy — impersonate any user via constrained/RBCD delegation abuse',       mitre: 'T1558.001', risk: 'CRITICAL' },
      { id: 'ticketer',            name: 'Ticketer',      desc: 'Forge Golden / Silver Kerberos tickets using KRBTGT hash or service account hash',        mitre: 'T1558.001', risk: 'CRITICAL' },
      { id: 'rubeus_monitor',      name: 'Rubeus Monitor', desc: 'Monitor LSASS for TGT harvesting in real-time via Rubeus',                               mitre: 'T1558',     risk: 'HIGH'     },
      { id: 'kerberoast_spn_enum', name: 'SPN Enum',      desc: 'Enumerate SPN-registered accounts — triage kerberoast targets before requesting tickets', mitre: 'T1558.003', risk: 'LOW'      },
    ],
  },
  {
    id: 'creds', label: 'CREDENTIAL ACCESS', color: '#e11d48',
    techniques: [
      { id: 'dcsync',      name: 'DCSync',       desc: 'Replicate NTDS via MS-DRSR — requires Domain Admin or explicit Replicating Directory Changes',  mitre: 'T1003.006', risk: 'CRITICAL' },
      { id: 'secretsdump', name: 'Secrets Dump', desc: 'Remote SAM / LSA secrets / NTDS.dit extraction via DCERPC — no agent required',                  mitre: 'T1003.002', risk: 'CRITICAL' },
      { id: 'laps_dump',   name: 'LAPS Dump',    desc: 'Read LAPS managed local admin passwords from ms-Mcs-AdmPwd attribute via LDAP',                  mitre: 'T1003.004', risk: 'HIGH'     },
      { id: 'gmsa_dump',   name: 'GMSA Dump',    desc: 'Retrieve Group Managed Service Account passwords from msDS-ManagedPassword attribute',            mitre: 'T1552',     risk: 'HIGH'     },
    ],
  },
  {
    id: 'lateral', label: 'LATERAL MOVEMENT', color: '#dc2626',
    techniques: [
      { id: 'smbexec',  name: 'SMB Exec',  desc: 'Remote execution — creates a service binary via SMB to run arbitrary commands',            mitre: 'T1021.002', risk: 'CRITICAL' },
      { id: 'wmiexec',  name: 'WMI Exec',  desc: 'Semi-interactive shell via WMI — no binary drops, lower EDR visibility',                   mitre: 'T1047',     risk: 'CRITICAL' },
      { id: 'atexec',   name: 'AT Exec',   desc: 'Remote command execution via Windows Task Scheduler (atsvc interface)',                     mitre: 'T1053.005', risk: 'HIGH'     },
      { id: 'psexec',   name: 'PSExec',    desc: 'Service binary deployment over SMB ADMIN$ — interactive shell via named pipe',             mitre: 'T1021.002', risk: 'CRITICAL' },
    ],
  },
  {
    id: 'coercion', label: 'COERCION & RELAY', color: '#7c3aed',
    techniques: [
      { id: 'coerce',          name: 'Coerce Auth',  desc: 'Force DC outbound auth via PetitPotam / PrinterBug / DFSCoerce — capture NTLM hash',     mitre: 'T1187',     risk: 'HIGH'     },
      { id: 'ntlmrelayx',      name: 'NTLM Relay',   desc: 'Relay captured NTLM auth to SMB/LDAP/LDAPS — execute commands or create resources',       mitre: 'T1557.001', risk: 'CRITICAL' },
      { id: 'ntlmrelayx_adcs', name: 'NTLM → ADCS',  desc: 'Relay NTLM to AD CS HTTP endpoint — obtain machine certificate for PKINIT or Schannel', mitre: 'T1557.001', risk: 'CRITICAL' },
    ],
  },
  {
    id: 'account', label: 'ACCOUNT OPERATIONS', color: '#8b5cf6',
    techniques: [
      { id: 'addcomputer',    name: 'Add Computer',    desc: 'Create machine account (MachineAccountQuota) for RBCD attack chain setup',            mitre: 'T1136.002', risk: 'HIGH' },
      { id: 'changepasswd',   name: 'Change Password', desc: 'Reset a user account password via SAMRPC — requires GenericAll / ForceChangePassword', mitre: 'T1098',     risk: 'HIGH' },
      { id: 'renamemachine',  name: 'Rename Machine',  desc: 'Rename machine account for sAMAccountName spoofing (CVE-2021-42278)',                  mitre: 'T1098',     risk: 'HIGH' },
      { id: 'password_reset', name: 'Password Reset',  desc: 'Force reset account password via AD replication rights',                              mitre: 'T1098',     risk: 'HIGH' },
    ],
  },
  {
    id: 'acl', label: 'ACL ABUSE', color: '#a855f7',
    techniques: [
      { id: 'dacledit',   name: 'DACL Edit',   desc: 'Add / remove DACEs — GenericAll / WriteDACL / WriteOwner → full account takeover',    mitre: 'T1222.001', risk: 'CRITICAL' },
      { id: 'rbcd_write', name: 'RBCD Write',  desc: 'Write msDS-AllowedToActOnBehalfOfOtherIdentity — enables S4U2Proxy impersonation',     mitre: 'T1134.001', risk: 'CRITICAL' },
      { id: 'whisker',    name: 'Whisker',     desc: 'Inject msDS-KeyCredentialLink into target — shadow credentials via PKINIT auth',       mitre: 'T1098',     risk: 'CRITICAL' },
    ],
  },
  {
    id: 'adcs', label: 'CERTIFICATE SERVICES', color: '#0891b2',
    techniques: [
      { id: 'certipy_find',     name: 'Certipy Find',    desc: 'Enumerate AD CS — templates, CAs, ESC1-ESC13 misconfigurations',                      mitre: 'T1552',  risk: 'LOW'      },
      { id: 'certipy_req',      name: 'Certipy Req',     desc: 'Request cert via vulnerable template — specify UPN to obtain admin certificate',       mitre: 'T1649',  risk: 'HIGH'     },
      { id: 'certipy_auth',     name: 'Certipy Auth',    desc: 'Authenticate with obtained certificate — extract NT hash via Kerberos PKINIT',         mitre: 'T1649',  risk: 'HIGH'     },
      { id: 'certipy_template', name: 'Template Edit',   desc: 'Modify certificate template EKU/flags — create ESC1 condition for impersonation',      mitre: 'T1649',  risk: 'CRITICAL' },
    ],
  },
  {
    id: 'posture', label: 'NETWORK POSTURE', color: '#059669',
    techniques: [
      { id: 'smb_signing_check',  name: 'SMB Signing',   desc: 'Check if SMB signing is required — if disabled, relay attacks are viable',        mitre: 'T1557.001', risk: 'LOW'    },
      { id: 'ldap_signing_check', name: 'LDAP Signing',  desc: 'Check LDAP channel binding and signing requirements on domain controllers',        mitre: 'T1557.001', risk: 'LOW'    },
      { id: 'llmnr_nbtns_check',  name: 'LLMNR/NBT-NS',  desc: 'Detect LLMNR and NBT-NS poisoning attack surface on the broadcast domain',         mitre: 'T1557.001', risk: 'LOW'    },
      { id: 'ntlm_config_check',  name: 'NTLM Config',   desc: 'Detect NTLMv1 usage and permissive NTLM security levels',                          mitre: 'T1557.001', risk: 'LOW'    },
      { id: 'winrm_check',        name: 'WinRM Check',   desc: 'Check if Windows Remote Management is enabled — lateral movement surface',          mitre: 'T1021.006', risk: 'LOW'    },
      { id: 'open_shares_check',  name: 'Open Shares',   desc: 'Enumerate anonymously accessible SMB shares and sensitive file exposure',           mitre: 'T1135',     risk: 'LOW'    },
      { id: 'cred_manager_check', name: 'Cred Manager',  desc: 'Check Windows Credential Manager vault for stored plaintext credentials',           mitre: 'T1555.004', risk: 'MEDIUM' },
    ],
  },
  {
    id: 'spray', label: 'SPRAY & CRACK', color: '#b91c1c',
    techniques: [
      { id: 'password_spray',     name: 'Password Spray',  desc: 'LDAP/Kerberos password spray against user list — intelligent lockout avoidance',  mitre: 'T1110.003', risk: 'HIGH'   },
      { id: 'password_spray_smb', name: 'SMB Spray',        desc: 'SMB authentication spray across domain accounts',                                mitre: 'T1110.003', risk: 'HIGH'   },
      { id: 'manual_crack',       name: 'Manual Crack',     desc: 'Offline hash cracking with custom wordlist — hashcat-compatible format',          mitre: 'T1110.002', risk: 'MEDIUM' },
    ],
  },
  {
    id: 'gpo', label: 'GROUP POLICY', color: '#d97706',
    techniques: [
      { id: 'gpo_inject', name: 'GPO Inject', desc: 'Inject malicious scheduled task via GPO write access — domain-wide code execution',  mitre: 'T1484.001', risk: 'CRITICAL' },
    ],
  },
  {
    id: 'sccm', label: 'SCCM / MECM', color: '#0369a1',
    techniques: [
      { id: 'sccm_enum', name: 'SCCM Enum', desc: 'Enumerate SCCM/MECM deployments, client push accounts, and policies', mitre: 'T1018',  risk: 'LOW'  },
      { id: 'sccm_naa',  name: 'SCCM NAA',  desc: 'Extract Network Access Account credentials from SCCM distribution points', mitre: 'T1552', risk: 'HIGH' },
    ],
  },
  {
    id: 'cve', label: 'CVE EXPLOITS', color: '#ef4444',
    techniques: [
      { id: 'zerologon',         name: 'Zerologon',         desc: 'CVE-2020-1472 — Zero DC machine account password via MS-NRPC cryptographic flaw',      mitre: 'CVE-2020-1472', risk: 'CRITICAL' },
      { id: 'zerologon_restore', name: 'Zerologon Restore', desc: 'Restore DC machine account password after Zerologon — prevents permanent domain break', mitre: 'CVE-2020-1472', risk: 'HIGH'     },
    ],
  },
]

const TECH_EXTRA_PARAMS: Record<string, TechParam[]> = {
  nmap_scan: [
    { key: 'ports', label: 'PORTS', type: 'text', placeholder: '22,80,443,445,88,389,636,3389' },
    { key: 'flags', label: 'FLAGS', type: 'text', placeholder: '-sV --open -T4' },
  ],
  getst: [
    { key: 'spn',         label: 'TARGET SPN',   type: 'text', placeholder: 'cifs/dc01.corp.local', required: true },
    { key: 'impersonate', label: 'IMPERSONATE',  type: 'text', placeholder: 'administrator',        required: true },
  ],
  ticketer: [
    { key: 'domain_sid', label: 'DOMAIN SID',              type: 'text', placeholder: 'S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX', required: true },
    { key: 'nthash',     label: 'KRBTGT NT HASH',           type: 'text', placeholder: 'aad3b435b51404eeaad3b435b51404ee', required: true },
    { key: 'extra_sid',  label: 'EXTRA SID (Enterprise Admins)', type: 'text', placeholder: 'S-1-5-21-...-519' },
  ],
  dacledit: [
    { key: 'action',     label: 'ACTION',      type: 'text', placeholder: 'write' },
    { key: 'target_dn',  label: 'TARGET DN',   type: 'text', placeholder: 'CN=target,DC=corp,DC=local' },
    { key: 'principal',  label: 'PRINCIPAL',   type: 'text', placeholder: 'attacker' },
  ],
  smbexec:  [{ key: 'command', label: 'COMMAND', type: 'text', placeholder: 'whoami /all', required: true }],
  wmiexec:  [{ key: 'command', label: 'COMMAND', type: 'text', placeholder: 'whoami /all', required: true }],
  atexec:   [{ key: 'command', label: 'COMMAND', type: 'text', placeholder: 'whoami /all', required: true }],
  psexec:   [{ key: 'command', label: 'COMMAND', type: 'text', placeholder: 'cmd.exe /c whoami', required: true }],
  reg_query: [{ key: 'key', label: 'REGISTRY KEY', type: 'text', placeholder: 'HKLM\\SAM\\SAM', required: true }],
  addcomputer: [
    { key: 'computer_name', label: 'COMPUTER NAME', type: 'text',     placeholder: 'EVILPC$' },
    { key: 'computer_pass', label: 'COMPUTER PASS', type: 'password', placeholder: 'Password123!' },
  ],
  changepasswd: [
    { key: 'target_user',  label: 'TARGET USER',  type: 'text',     placeholder: 'victim', required: true },
    { key: 'new_password', label: 'NEW PASSWORD', type: 'password', placeholder: 'NewPass123!', required: true },
  ],
  password_reset: [
    { key: 'target_user',  label: 'TARGET USER',  type: 'text',     placeholder: 'victim', required: true },
    { key: 'new_password', label: 'NEW PASSWORD', type: 'password', placeholder: '' },
  ],
  renamemachine:      [{ key: 'new_name',      label: 'NEW MACHINE NAME',           type: 'text',     placeholder: 'DC01$' }],
  rbcd_write: [
    { key: 'delegate_from', label: 'DELEGATE FROM', type: 'text', placeholder: 'EVILPC$' },
    { key: 'delegate_to',   label: 'DELEGATE TO',   type: 'text', placeholder: 'target_computer$' },
  ],
  whisker:            [{ key: 'target_dn',     label: 'TARGET ACCOUNT',             type: 'text',     placeholder: 'CN=user,DC=corp,DC=local' }],
  certipy_req: [
    { key: 'ca',       label: 'CERTIFICATE AUTHORITY',    type: 'text', placeholder: 'corp-CA', required: true },
    { key: 'template', label: 'TEMPLATE',                 type: 'text', placeholder: 'User' },
    { key: 'upn',      label: 'UPN (ESC1 impersonation)', type: 'text', placeholder: 'administrator@corp.local' },
  ],
  certipy_auth: [
    { key: 'pfx',      label: 'PFX FILE PATH', type: 'text',     placeholder: '/tmp/administrator.pfx', required: true },
    { key: 'pfx_pass', label: 'PFX PASSWORD',  type: 'password', placeholder: '' },
  ],
  certipy_template:   [{ key: 'template',      label: 'TEMPLATE NAME',              type: 'text',     placeholder: 'User', required: true }],
  coerce: [
    { key: 'listener_ip', label: 'LISTENER IP', type: 'text', placeholder: '192.168.1.100' },
    { key: 'method',      label: 'METHOD',       type: 'text', placeholder: 'PetitPotam' },
  ],
  ntlmrelayx:         [{ key: 'target_url',    label: 'RELAY TARGET',               type: 'text',     placeholder: 'smb://192.168.1.200', required: true }],
  ntlmrelayx_adcs: [
    { key: 'adcs_url', label: 'ADCS URL',  type: 'text', placeholder: 'http://ca.corp.local/certsrv/', required: true },
    { key: 'template', label: 'TEMPLATE',  type: 'text', placeholder: 'Machine' },
  ],
  gpo_inject: [
    { key: 'gpo_id',  label: 'GPO ID',  type: 'text', placeholder: '{GUID}' },
    { key: 'command', label: 'COMMAND', type: 'text', placeholder: 'cmd.exe /c ...' },
  ],
  password_spray:     [{ key: 'userlist', label: 'USER LIST (one per line)', type: 'textarea', placeholder: 'administrator\nuser1\nuser2' }],
  password_spray_smb: [{ key: 'userlist', label: 'USER LIST (one per line)', type: 'textarea', placeholder: 'administrator\nuser1\nuser2' }],
  manual_crack: [
    { key: 'hash',     label: 'HASH',           type: 'text', placeholder: 'aad3b435b51404eeaad3b435b51404ee', required: true },
    { key: 'wordlist', label: 'WORDLIST PATH',   type: 'text', placeholder: '/usr/share/wordlists/rockyou.txt' },
  ],
  zerologon:         [{ key: 'dc_name', label: 'DC NETBIOS NAME', type: 'text', placeholder: 'DC01', required: true }],
  zerologon_restore: [
    { key: 'dc_name',       label: 'DC NETBIOS NAME',      type: 'text', placeholder: 'DC01',            required: true },
    { key: 'original_hash', label: 'ORIGINAL MACHINE HASH', type: 'text', placeholder: 'aad3b435...', required: true },
  ],
}

const RISK: Record<Risk, { color: string; bg: string; border: string }> = {
  LOW:      { color: '#22c55e', bg: 'rgba(34,197,94,0.08)',   border: 'rgba(34,197,94,0.25)'  },
  MEDIUM:   { color: '#f59e0b', bg: 'rgba(245,158,11,0.08)',  border: 'rgba(245,158,11,0.25)' },
  HIGH:     { color: '#f97316', bg: 'rgba(249,115,22,0.08)',  border: 'rgba(249,115,22,0.25)' },
  CRITICAL: { color: '#e11d48', bg: 'rgba(225,29,72,0.08)',   border: 'rgba(225,29,72,0.25)'  },
}

const OPSEC: Record<Opsec, { color: string; glow: string; desc: string }> = {
  LOUD:     { color: '#e11d48', glow: 'rgba(225,29,72,0.3)',   desc: 'Max speed — detection risk accepted' },
  BALANCED: { color: '#f59e0b', glow: 'rgba(245,158,11,0.3)', desc: 'Normal tempo — moderate stealth' },
  GHOST:    { color: '#22c55e', glow: 'rgba(34,197,94,0.3)',   desc: 'Max stealth — slower execution' },
}

const STATUS_ICONS: Record<string, React.ReactNode> = {
  PENDING:   <Clock size={11} />,
  RUNNING:   <Zap  size={11} className="animate-pulse" />,
  COMPLETED: <CheckCircle size={11} />,
  FAILED:    <XCircle size={11} />,
  KILLED:    <Square  size={11} />,
}

const STATUS_COLORS: Record<string, string> = {
  PENDING:   '#f59e0b',
  RUNNING:   '#a78bfa',
  COMPLETED: '#22c55e',
  FAILED:    '#f97316',
  KILLED:    'rgba(255,255,255,0.25)',
}

const ALL_TECHNIQUES = ARSENAL.flatMap(c => c.techniques)
const findTech  = (id: string) => ALL_TECHNIQUES.find(t => t.id === id)
const findCat   = (id: string) => ARSENAL.find(c => c.techniques.some(t => t.id === id))

function JobRow({
  job, expanded, onToggle, onKill,
}: {
  job: Job
  expanded: boolean
  onToggle: () => void
  onKill: () => void
}) {
  const color  = STATUS_COLORS[job.status] ?? STATUS_COLORS.PENDING
  const icon   = STATUS_ICONS[job.status]  ?? STATUS_ICONS.PENDING
  const opsecColor = OPSEC[job.opsec_profile as Opsec]?.color ?? 'rgba(255,255,255,0.3)'

  const elapsed = (() => {
    if (job.status !== 'RUNNING' || !job.started_at) return null
    const startedAt = safeDateMs(job.started_at)
    if (startedAt === null) return null
    const secs = Math.max(0, Math.floor((Date.now() - startedAt) / 1000))
    const m = Math.floor(secs / 60)
    const s = secs % 60
    return m > 0 ? `${m}m ${s}s` : `${s}s`
  })()

  return (
    <div
      className="overflow-hidden rounded-lg border transition-all"
      style={{ borderColor: `${color}18`, background: `${color}04` }}
    >
      <div
        className="flex cursor-pointer select-none items-center gap-2 px-3 py-2.5 hover:bg-white/[0.02]"
        onClick={onToggle}
      >
        <span style={{ color }}>{icon}</span>

        <span className="min-w-0 flex-1 truncate text-[11px] font-bold tracking-wide text-white/80">
          {job.technique_id.toUpperCase()}
        </span>

        <span className="shrink-0 text-[10px] text-white/30">→ {job.target}</span>

        {elapsed && (
          <span className="shrink-0 rounded px-1.5 text-[9px]" style={{ color: 'rgba(167,139,250,0.7)' }}>
            {elapsed}
          </span>
        )}

        <span
          className="shrink-0 rounded border px-1.5 py-0.5 text-[8px] font-bold"
          style={{ borderColor: `${opsecColor}35`, color: opsecColor }}
        >
          {job.opsec_profile}
        </span>

        {job.status === 'RUNNING' && (
          <button
            onClick={e => { e.stopPropagation(); onKill() }}
            className="shrink-0 rounded border border-red-500/30 bg-red-500/8 px-2 py-0.5 text-[9px] text-red-400 transition-colors hover:bg-red-500/15"
          >
            KILL
          </button>
        )}

        <span className="shrink-0 text-[9px] text-white/20">
          {fmtTime(job.created_at, { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
        </span>

        <span className="shrink-0 text-white/20">
          {expanded ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
        </span>
      </div>

      {expanded && (
        <div
          className="border-t"
          style={{ borderColor: `${color}15`, height: '280px' }}
        >
          <LiveOutputTerminal jobId={job.id} />
        </div>
      )}
    </div>
  )
}

function Field({
  label, value, onChange, placeholder, type = 'text',
}: {
  label: string
  value: string
  onChange: (v: string) => void
  placeholder?: string
  type?: string
}) {
  return (
    <div>
      <label className="mb-0.5 block text-[8px] font-bold tracking-[0.15em] text-white/25">{label}</label>
      <input
        type={type}
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full rounded border bg-white/[0.03] px-2.5 py-1.5 text-[11px] text-white/80 placeholder-white/15 outline-none transition-colors focus:bg-white/[0.05]"
        style={{ borderColor: 'rgba(255,255,255,0.07)' }}
        onFocus={e => e.currentTarget.style.borderColor = 'rgba(255,255,255,0.2)'}
        onBlur={e => e.currentTarget.style.borderColor = 'rgba(255,255,255,0.07)'}
      />
    </div>
  )
}

export default function OpsCenter() {
  const [search, setSearch] = useState('')
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set())
  const [selectedTech, setSelectedTech] = useState('ldap_enum')
  const [profile, setProfile] = useState<TargetProfile>({ target: '', domain: '', username: '', password: '', dc_ip: '' })
  const [profileDirty, setProfileDirty] = useState(false)
  const [profileSaving, setProfileSaving] = useState(false)
  const [profileSavedFlash, setProfileSavedFlash] = useState(false)
  const [opsec, setOpsec] = useState<Opsec>('BALANCED')
  const [extraParams, setExtraParams] = useState<Record<string, string>>({})
  const [jobs, setJobs] = useState<Job[]>([])
  const [executing, setExecuting] = useState(false)
  const [error, setError] = useState('')
  const [expandedJobs, setExpandedJobs] = useState<Set<string>>(new Set())
  const [mounted, setMounted] = useState(false)
  const [, setTick] = useState(0)

  useEffect(() => {
    setMounted(true)
    const t = setInterval(() => setTick(x => x + 1), 1000)
    getTargetProfile().then(p => { setProfile(p) }).catch(() => {})
    return () => clearInterval(t)
  }, [])

  useEffect(() => { setExtraParams({}) }, [selectedTech])

  const refreshJobs = useCallback(async () => {
    try { setJobs(await listJobs()) } catch {}
  }, [])

  useEffect(() => {
    refreshJobs()
    const iv = setInterval(refreshJobs, 4000)
    return () => clearInterval(iv)
  }, [refreshJobs])

  useEffect(() => {
    const running = jobs.filter(j => j.status === 'RUNNING').map(j => j.id)
    if (running.length) setExpandedJobs(prev => new Set([...prev, ...running]))
  }, [jobs])

  const handleSaveProfile = async () => {
    setProfileSaving(true)
    try {
      await saveTargetProfile(profile)
      setProfileDirty(false)
      setProfileSavedFlash(true)
      setTimeout(() => setProfileSavedFlash(false), 2000)
    } catch {}
    finally { setProfileSaving(false) }
  }

  const updateProfile = (key: keyof TargetProfile) => (v: string) => {
    setProfile(p => ({ ...p, [key]: v }))
    setProfileDirty(true)
  }

  const handleExecute = async () => {
    if (!profile.target) { setError('Target IP is required'); return }
    setError('')
    setExecuting(true)
    try {
      const job = await executeJob({
        technique_id: selectedTech,
        target: profile.target,
        params: {
          domain:   profile.domain,
          username: profile.username,
          password: profile.password,
          dc_ip:    profile.dc_ip || profile.target,
          ...extraParams,
        },
        opsec_profile: opsec,
      })
      setJobs(prev => [job, ...prev])
      setExpandedJobs(prev => new Set([...prev, job.id]))
    } catch (e: unknown) {
      const raw = e instanceof Error ? e.message : String(e)
      try {
        const parsed = JSON.parse(raw)
        setError(parsed?.detail ?? raw)
      } catch {
        setError(raw)
      }
    }
    finally { setExecuting(false) }
  }

  const toggleJob = (id: string) =>
    setExpandedJobs(prev => {
      const n = new Set(prev)
      if (n.has(id)) {
        n.delete(id)
      } else {
        n.add(id)
      }
      return n
    })

  const toggleCat = (id: string) =>
    setCollapsed(prev => {
      const n = new Set(prev)
      if (n.has(id)) {
        n.delete(id)
      } else {
        n.add(id)
      }
      return n
    })

  const filteredArsenal = search.trim()
    ? ARSENAL
        .map(cat => ({
          ...cat,
          techniques: cat.techniques.filter(t =>
            `${t.name} ${t.id} ${t.desc} ${t.mitre ?? ''}`
              .toLowerCase()
              .includes(search.toLowerCase()),
          ),
        }))
        .filter(cat => cat.techniques.length > 0)
    : ARSENAL

  const tech    = findTech(selectedTech)
  const cat     = findCat(selectedTech)
  const extras  = TECH_EXTRA_PARAMS[selectedTech] ?? []

  const running   = jobs.filter(j => j.status === 'RUNNING').length
  const completed = jobs.filter(j => j.status === 'COMPLETED').length
  const failed    = jobs.filter(j => j.status === 'FAILED').length

  return (
    <AppShell>
      {/* Root */}
      <div
        className="flex h-full flex-col"
        style={{
          background: '#050508',
          fontFamily: "'JetBrains Mono', 'Courier New', monospace",
        }}
      >
        {/* Scanline overlay */}
        <div
          className="pointer-events-none fixed inset-0 z-50 opacity-[0.35]"
          style={{
            backgroundImage:
              'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.06) 2px, rgba(0,0,0,0.06) 4px)',
          }}
        />

        {/* ── TOPBAR ──────────────────────────────────────────────────────── */}
        <header
          className="relative z-10 flex shrink-0 items-center justify-between border-b px-6 py-3"
          style={{ background: '#07070d', borderColor: 'rgba(255,255,255,0.05)' }}
        >
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2.5">
              <span
                className="h-2 w-2 animate-pulse rounded-full"
                style={{ background: '#e11d48', boxShadow: '0 0 8px rgba(225,29,72,0.9)' }}
              />
              <h1 className="text-sm font-black tracking-[0.25em] text-white/90">ADBYGOD // OPS CENTER</h1>
            </div>
            <div className="h-3.5 w-px" style={{ background: 'rgba(255,255,255,0.08)' }} />
            <span className="text-[9px] tracking-[0.2em] text-white/20">AUTHORIZED OPERATOR CONSOLE</span>
          </div>

          <div className="flex items-center gap-2">
            {[
              { label: 'ACTIVE',    value: running,      color: running  > 0 ? '#a78bfa' : 'rgba(255,255,255,0.2)' },
              { label: 'COMPLETED', value: completed,    color: '#22c55e' },
              { label: 'FAILED',    value: failed,       color: failed   > 0 ? '#f97316' : 'rgba(255,255,255,0.2)' },
              { label: 'TOTAL',     value: jobs.length,  color: 'rgba(255,255,255,0.45)' },
            ].map(s => (
              <div
                key={s.label}
                className="flex items-baseline gap-1.5 rounded border px-3 py-1.5"
                style={{ borderColor: 'rgba(255,255,255,0.06)', background: 'rgba(255,255,255,0.02)' }}
              >
                <span className="text-lg font-black leading-none tabular-nums" style={{ color: s.color }}>{s.value}</span>
                <span className="text-[8px] tracking-widest text-white/25">{s.label}</span>
              </div>
            ))}
          </div>

          <time className="text-[10px] tabular-nums text-white/20">
            {mounted ? new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC' : ''}
          </time>
        </header>

        {/* ── 3-COLUMN BODY ───────────────────────────────────────────────── */}
        <div className="flex flex-1 overflow-hidden">

          {/* ── LEFT: ARSENAL BROWSER ─────────────────────────────────────── */}
          <aside
            className="flex w-64 shrink-0 flex-col border-r"
            style={{ background: '#06060b', borderColor: 'rgba(255,255,255,0.04)' }}
          >
            {/* Search */}
            <div className="shrink-0 border-b px-3 py-2.5" style={{ borderColor: 'rgba(255,255,255,0.04)' }}>
              <div
                className="flex items-center gap-2 rounded border px-2.5 py-1.5 transition-colors focus-within:border-white/15"
                style={{ borderColor: 'rgba(255,255,255,0.07)', background: 'rgba(255,255,255,0.03)' }}
              >
                <Search size={11} className="shrink-0 text-white/25" />
                <input
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  placeholder="search techniques..."
                  className="min-w-0 flex-1 bg-transparent text-[11px] text-white/70 placeholder-white/20 outline-none"
                />
                {search && (
                  <button onClick={() => setSearch('')} className="shrink-0 text-white/25 hover:text-white/50">
                    <X size={9} />
                  </button>
                )}
              </div>
            </div>

            {/* Categories */}
            <nav className="flex-1 overflow-y-auto py-1" style={{ scrollbarWidth: 'none' }}>
              {filteredArsenal.map(category => (
                <div key={category.id}>
                  {/* Category header */}
                  <button
                    className="flex w-full items-center gap-2 px-3 py-1.5 text-left transition-colors hover:bg-white/[0.025]"
                    onClick={() => toggleCat(category.id)}
                  >
                    {collapsed.has(category.id)
                      ? <ChevronRight size={9} className="shrink-0 text-white/20" />
                      : <ChevronDown  size={9} className="shrink-0 text-white/20" />
                    }
                    <span
                      className="flex-1 text-[8px] font-black tracking-[0.18em]"
                      style={{ color: category.color }}
                    >
                      {category.label}
                    </span>
                    <span className="text-[8px] text-white/15">{category.techniques.length}</span>
                  </button>

                  {/* Techniques */}
                  {!collapsed.has(category.id) && category.techniques.map(t => {
                    const selected = t.id === selectedTech
                    return (
                      <button
                        key={t.id}
                        className="relative flex w-full items-center gap-2 py-1.5 pl-5 pr-3 text-left transition-all hover:bg-white/[0.025]"
                        style={{
                          borderLeft: selected ? `2px solid ${category.color}` : '2px solid transparent',
                          background: selected ? `${category.color}0a` : undefined,
                        }}
                        onClick={() => setSelectedTech(t.id)}
                      >
                        <span
                          className="min-w-0 flex-1 truncate text-[11px] leading-snug"
                          style={{ color: selected ? 'rgba(255,255,255,0.9)' : 'rgba(255,255,255,0.45)' }}
                        >
                          {t.name}
                        </span>
                        {t.mitre && (
                          <span className="shrink-0 text-[8px] text-white/15">{t.mitre}</span>
                        )}
                        <span
                          className="h-1.5 w-1.5 shrink-0 rounded-full"
                          style={{
                            background: RISK[t.risk].color,
                            boxShadow: selected ? `0 0 5px ${RISK[t.risk].color}` : undefined,
                          }}
                        />
                      </button>
                    )
                  })}
                </div>
              ))}
            </nav>

            {/* Risk legend */}
            <div
              className="shrink-0 border-t px-3 py-2"
              style={{ borderColor: 'rgba(255,255,255,0.04)' }}
            >
              <div className="flex items-center justify-between">
                {(['LOW','MEDIUM','HIGH','CRITICAL'] as Risk[]).map(r => (
                  <div key={r} className="flex items-center gap-1">
                    <span className="h-1.5 w-1.5 rounded-full" style={{ background: RISK[r].color }} />
                    <span className="text-[7px] tracking-widest" style={{ color: RISK[r].color }}>{r}</span>
                  </div>
                ))}
              </div>
            </div>
          </aside>

          {/* ── MIDDLE: OPERATION CONFIG ───────────────────────────────────── */}
          <section
            className="flex w-[360px] shrink-0 flex-col overflow-y-auto border-r"
            style={{ background: '#070710', borderColor: 'rgba(255,255,255,0.04)', scrollbarWidth: 'none' }}
          >
            <div className="space-y-5 p-5">

              {/* TARGET PROFILE */}
              <div>
                <div className="mb-2.5 flex items-center justify-between">
                  <span className="text-[8px] font-black tracking-[0.2em] text-white/35">TARGET PROFILE</span>
                  <button
                    onClick={handleSaveProfile}
                    disabled={!profileDirty || profileSaving}
                    className="flex items-center gap-1 rounded border px-2 py-0.5 text-[8px] transition-all disabled:cursor-not-allowed disabled:opacity-30"
                    style={{
                      borderColor: profileSavedFlash ? 'rgba(34,197,94,0.4)' : 'rgba(255,255,255,0.08)',
                      color: profileSavedFlash ? '#22c55e' : profileDirty ? 'rgba(255,255,255,0.5)' : 'rgba(255,255,255,0.2)',
                      background: profileSavedFlash ? 'rgba(34,197,94,0.08)' : undefined,
                    }}
                  >
                    <Save size={8} />
                    {profileSaving ? 'SAVING…' : profileSavedFlash ? '✓ SAVED' : profileDirty ? 'SAVE' : 'SAVED'}
                  </button>
                </div>

                <div
                  className="space-y-2 rounded-lg border p-3"
                  style={{ borderColor: 'rgba(255,255,255,0.06)', background: 'rgba(255,255,255,0.015)' }}
                >
                  <div className="grid grid-cols-2 gap-2">
                    <Field label="TARGET IP"  value={profile.target}   onChange={updateProfile('target')}   placeholder="192.168.1.10" />
                    <Field label="DC IP"       value={profile.dc_ip}    onChange={updateProfile('dc_ip')}    placeholder="192.168.1.1" />
                  </div>
                  <Field label="DOMAIN"        value={profile.domain}   onChange={updateProfile('domain')}   placeholder="corp.local" />
                  <div className="grid grid-cols-2 gap-2">
                    <Field label="USERNAME"    value={profile.username} onChange={updateProfile('username')} placeholder="administrator" />
                    <Field label="PASSWORD"    value={profile.password} onChange={updateProfile('password')} placeholder="••••••••" type="password" />
                  </div>
                </div>
              </div>

              {/* DIVIDER */}
              <div style={{ height: '1px', background: 'rgba(255,255,255,0.04)' }} />

              {/* SELECTED TECHNIQUE */}
              {tech && (
                <div>
                  <span className="mb-2 block text-[8px] font-black tracking-[0.2em] text-white/35">SELECTED TECHNIQUE</span>
                  <div
                    className="rounded-lg border p-3"
                    style={{
                      borderColor: `${cat?.color ?? '#ffffff'}22`,
                      background: `${cat?.color ?? '#ffffff'}06`,
                    }}
                  >
                    <div className="mb-2 flex flex-wrap items-center gap-1.5">
                      <span className="text-sm font-black text-white/90">{tech.name}</span>
                      <div className="ml-auto flex items-center gap-1.5">
                        {tech.mitre && (
                          <span
                            className="rounded border px-1.5 py-0.5 text-[8px] font-bold"
                            style={{ borderColor: `${cat?.color}35`, color: cat?.color }}
                          >
                            {tech.mitre}
                          </span>
                        )}
                        <span
                          className="rounded border px-1.5 py-0.5 text-[8px] font-black"
                          style={{ borderColor: RISK[tech.risk].border, color: RISK[tech.risk].color, background: RISK[tech.risk].bg }}
                        >
                          {tech.risk}
                        </span>
                      </div>
                    </div>
                    <p className="text-[10px] leading-relaxed text-white/35">{tech.desc}</p>
                  </div>
                </div>
              )}

              {/* EXTRA PARAMS */}
              {extras.length > 0 && (
                <div>
                  <span className="mb-2 block text-[8px] font-black tracking-[0.2em] text-white/35">TECHNIQUE PARAMS</span>
                  <div className="space-y-2">
                    {extras.map(param => (
                      <div key={param.key}>
                        <label className="mb-0.5 flex items-center gap-1 text-[8px] font-bold tracking-[0.15em] text-white/25">
                          {param.label}
                          {param.required && <span className="text-red-400/70">*</span>}
                        </label>
                        {param.type === 'textarea' ? (
                          <textarea
                            value={extraParams[param.key] ?? ''}
                            onChange={e => setExtraParams(p => ({ ...p, [param.key]: e.target.value }))}
                            placeholder={param.placeholder}
                            rows={3}
                            className="w-full resize-none rounded border bg-white/[0.03] px-2.5 py-1.5 text-[11px] text-white/80 placeholder-white/15 outline-none transition-colors focus:bg-white/[0.05]"
                            style={{ borderColor: 'rgba(255,255,255,0.07)' }}
                          />
                        ) : (
                          <input
                            type={param.type}
                            value={extraParams[param.key] ?? ''}
                            onChange={e => setExtraParams(p => ({ ...p, [param.key]: e.target.value }))}
                            placeholder={param.placeholder}
                            className="w-full rounded border bg-white/[0.03] px-2.5 py-1.5 text-[11px] text-white/80 placeholder-white/15 outline-none transition-colors focus:bg-white/[0.05]"
                            style={{ borderColor: 'rgba(255,255,255,0.07)' }}
                            onFocus={e => e.currentTarget.style.borderColor = 'rgba(255,255,255,0.2)'}
                            onBlur={e => e.currentTarget.style.borderColor = 'rgba(255,255,255,0.07)'}
                          />
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* DIVIDER */}
              <div style={{ height: '1px', background: 'rgba(255,255,255,0.04)' }} />

              {/* OPSEC */}
              <div>
                <span className="mb-2 block text-[8px] font-black tracking-[0.2em] text-white/35">OPSEC PROFILE</span>
                <div className="grid grid-cols-3 gap-1.5">
                  {(['LOUD', 'BALANCED', 'GHOST'] as Opsec[]).map(o => {
                    const cfg = OPSEC[o]
                    const sel = opsec === o
                    return (
                      <button
                        key={o}
                        onClick={() => setOpsec(o)}
                        className="rounded border py-2.5 text-[9px] font-black tracking-widest transition-all"
                        style={{
                          borderColor: sel ? cfg.color : 'rgba(255,255,255,0.06)',
                          color:       sel ? cfg.color : 'rgba(255,255,255,0.25)',
                          background:  sel ? `${cfg.color}0f` : 'transparent',
                          boxShadow:   sel ? `0 0 14px ${cfg.glow}, inset 0 0 14px ${cfg.glow}` : undefined,
                        }}
                      >
                        {o}
                      </button>
                    )
                  })}
                </div>
                <p className="mt-1.5 text-[9px] text-white/20">{OPSEC[opsec].desc}</p>
              </div>

              {/* ERROR */}
              {error && (
                <div
                  className="rounded-lg border px-3 py-2 text-[11px] text-red-400"
                  style={{ borderColor: 'rgba(225,29,72,0.3)', background: 'rgba(225,29,72,0.06)' }}
                >
                  ✗ {error}
                </div>
              )}

              {/* EXECUTE */}
              <button
                onClick={handleExecute}
                disabled={executing}
                className="group relative w-full overflow-hidden rounded-lg border py-3.5 text-[10px] font-black tracking-[0.25em] transition-all"
                style={{
                  borderColor: executing ? 'rgba(225,29,72,0.25)' : 'rgba(225,29,72,0.55)',
                  color:       executing ? 'rgba(225,29,72,0.45)' : '#e11d48',
                  background:  executing ? 'rgba(225,29,72,0.05)' : 'rgba(225,29,72,0.1)',
                  boxShadow:   executing ? undefined : '0 0 24px rgba(225,29,72,0.12), inset 0 0 24px rgba(225,29,72,0.04)',
                }}
              >
                {!executing && (
                  <span
                    className="absolute inset-0 -translate-x-full skew-x-12 bg-gradient-to-r from-transparent via-red-500/10 to-transparent transition-transform duration-700 group-hover:translate-x-full"
                  />
                )}
                <span className="relative flex items-center justify-center gap-2">
                  {executing ? (
                    <>
                      <span className="animate-spin text-base">◌</span>
                      EXECUTING...
                    </>
                  ) : (
                    <>
                      <Play size={11} className="fill-current" />
                      EXECUTE OPERATION
                    </>
                  )}
                </span>
              </button>
            </div>
          </section>

          {/* ── RIGHT: JOB FEED ───────────────────────────────────────────── */}
          <main className="flex flex-1 flex-col overflow-hidden" style={{ background: '#050508' }}>
            {/* Header */}
            <div
              className="flex shrink-0 items-center justify-between border-b px-5 py-3"
              style={{ borderColor: 'rgba(255,255,255,0.04)' }}
            >
              <div className="flex items-center gap-2.5">
                <Terminal size={13} className="text-white/25" />
                <span className="text-[9px] font-black tracking-[0.2em] text-white/40">JOB QUEUE</span>
                {jobs.length > 0 && (
                  <span
                    className="rounded border px-1.5 py-0.5 text-[8px] text-white/25"
                    style={{ borderColor: 'rgba(255,255,255,0.06)' }}
                  >
                    {jobs.length}
                  </span>
                )}
                {running > 0 && (
                  <span
                    className="animate-pulse rounded border px-2 py-0.5 text-[8px] font-bold"
                    style={{ borderColor: 'rgba(167,139,250,0.3)', color: '#a78bfa', background: 'rgba(167,139,250,0.08)' }}
                  >
                    {running} RUNNING
                  </span>
                )}
              </div>
              <button
                onClick={refreshJobs}
                className="rounded border p-1.5 text-white/20 transition-colors hover:text-white/50"
                style={{ borderColor: 'rgba(255,255,255,0.06)' }}
              >
                <RefreshCw size={11} />
              </button>
            </div>

            {/* Jobs list */}
            <div className="flex-1 overflow-y-auto p-4" style={{ scrollbarWidth: 'none' }}>
              {jobs.length === 0 ? (
                <div className="flex h-full flex-col items-center justify-center gap-3 select-none">
                  <Shield size={36} style={{ color: 'rgba(255,255,255,0.04)' }} />
                  <span className="text-[9px] tracking-[0.2em] text-white/10">NO ACTIVE OPERATIONS</span>
                </div>
              ) : (
                <div className="space-y-2">
                  {jobs.map(job => (
                    <JobRow
                      key={job.id}
                      job={job}
                      expanded={expandedJobs.has(job.id)}
                      onToggle={() => toggleJob(job.id)}
                      onKill={async () => { await killJob(job.id); refreshJobs() }}
                    />
                  ))}
                </div>
              )}
            </div>
          </main>

        </div>
      </div>
    </AppShell>
  )
}
