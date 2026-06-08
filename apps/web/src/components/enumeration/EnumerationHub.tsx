'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import { Search, Database, Network, TreePine, Settings, Lock, Key, Server, FolderSearch, Users, Globe } from 'lucide-react'
import { cn } from '@/lib/utils'
import { adCommandsApi } from '@/lib/api'
import { BackButton } from '@/components/ui/BackButton'
import { AttackTechCard } from '@/components/ui/AttackTechCard'

const TABS = [
  { key: 'domain',     label: 'Domain Enum',   icon: Network,   color: '#60a5fa' },
  { key: 'ldap',       label: 'LDAP',          icon: Database,  color: '#34d399' },
  { key: 'bloodhound', label: 'BloodHound',    icon: TreePine,  color: '#f472b6' },
  { key: 'gpo',        label: 'GPO Abuse',     icon: Settings,  color: '#fbbf24' },
  { key: 'adcs',       label: 'ADCS',          icon: Lock,      color: '#fb923c' },
  { key: 'kerberos',   label: 'Kerberos',      icon: Key,       color: '#a78bfa' },
  { key: 'mssql',      label: 'MSSQL',         icon: Server,       color: '#22d3ee' },
  { key: 'filehunt',   label: 'File Hunt',     icon: FolderSearch, color: '#f97316' },
  { key: 'userhunt',   label: 'User Hunt',     icon: Users,        color: '#e879f9' },
  { key: 'adidns',     label: 'ADIDNS Abuse',  icon: Globe,        color: '#ef4444' },
] as const

type TabKey = typeof TABS[number]['key']

const TAB_TECHNIQUE_IDS: Record<TabKey, string[]> = {
  domain: [
    'enum-domain-info', 'enum-domain-controllers', 'enum-domain-users', 'enum-domain-groups',
    'enum-domain-computers', 'enum-domain-admins', 'enum-domain-trusts', 'enum-domain-policy',
    'enum-domain-spns', 'enum-domain-delegation', 'enum-domain-gpos', 'enum-domain-ous',
    'enum-domain-acls', 'enum-domain-schema', 'enum-domain-fgpp', 'enum-domain-sites',
    'enum-domain-subnets', 'enum-domain-managed', 'enum-domain-privesc-paths', 'enum-domain-dcsync',
  ],
  ldap: [
    'ldap-anonymous-bind', 'ldap-enum-users', 'ldap-enum-groups', 'ldap-enum-computers',
    'ldap-enum-spns', 'ldap-enum-gpos', 'ldap-enum-delegation', 'ldap-enum-acls',
    'ldap-enum-schema', 'ldap-enum-trusts', 'ldap-enum-password-policy', 'ldap-enum-laps',
    'ldap-enum-gmsa', 'ldap-passwd-not-required', 'ldap-enum-printers', 'ldap-enum-exchange',
    'ldap-nmap-scripts', 'ldap-windapsearch', 'ldap-ldapdomaindump', 'ldap-bloodyad',
  ],
  bloodhound: [
    'bh-sharphound-all', 'bh-sharphound-stealth', 'bh-bloodhound-py', 'bh-rusthound',
    'bh-azurehound', 'bh-bloodhound-ce', 'bh-da-paths', 'bh-shortest-path',
    'bh-owned-analysis', 'bh-kerberoastable', 'bh-asreproastable', 'bh-dcsync-rights',
    'bh-gpo-linked', 'bh-laps-readers', 'bh-unconstrained', 'bh-constrained',
    'bh-shadow-creds', 'bh-acl-abuse', 'bh-cross-domain', 'bh-high-value',
  ],
  gpo: [
    'gpo-enum-all', 'gpo-linked-ous', 'gpo-permissions', 'gpo-abuse-writeable',
    'gpo-new-immediate-task', 'gpo-computer-startup', 'gpo-user-logon', 'gpo-sharpharpoon',
    'gpo-pywerbuilder', 'gpo-modifygpo', 'gpo-create-malicious', 'gpo-restricted-groups',
    'gpo-scheduled-tasks', 'gpo-registry-keys', 'gpo-scripts', 'gpo-file-deploy',
    'gpo-forcelogoff', 'gpo-sharpdpapi', 'gpo-backdoor-scripts', 'gpo-force-update',
  ],
  adcs: [
    'adcs-certipy-find', 'adcs-esc1', 'adcs-esc2', 'adcs-esc3',
    'adcs-esc4', 'adcs-esc6', 'adcs-esc7', 'adcs-esc8',
    'adcs-esc9', 'adcs-esc10', 'adcs-esc11', 'adcs-esc13',
    'adcs-golden-cert', 'adcs-shadow-credentials', 'adcs-ntlm-relay-adcs', 'adcs-certsync',
    'adcs-petitpotam-adcs', 'adcs-coerce-adcs', 'adcs-pkinit', 'adcs-unpac-pkinit',
  ],
  kerberos: [
    'kerb-kerberoasting', 'kerb-asreproasting', 'kerb-pass-the-ticket', 'kerb-overpass-hash',
    'kerb-s4u2self', 'kerb-s4u2proxy', 'kerb-unconstrained-dump', 'kerb-constrained-abuse',
    'kerb-resource-based', 'kerb-silver-ticket', 'kerb-golden-ticket', 'kerb-diamond-ticket',
    'kerb-sapphire-ticket', 'kerb-skeleton-key', 'kerb-ms14-068', 'kerb-roasting-targeted',
    'kerb-delegation-enum', 'kerb-tgt-delegation', 'kerb-forwardable-tgt', 'kerb-cross-realm',
  ],
  mssql: [
    'mssql-enum-instances', 'mssql-linked-servers', 'mssql-xp-cmdshell', 'mssql-impersonation',
    'mssql-enum-logins', 'mssql-enum-databases', 'mssql-ole-automation', 'mssql-clr-assembly',
    'mssql-linked-exec', 'mssql-crawl-links', 'mssql-uu-privesc', 'mssql-sp-addsrvrolemember',
    'mssql-token-impersonation', 'mssql-agent-jobs', 'mssql-registry-read', 'mssql-credential-objects',
    'mssql-azure-managed', 'mssql-service-accounts', 'mssql-netsec-scan', 'mssql-coerce',
  ],
  filehunt: [
    'enum-snaffler', 'enum-sysvol-hunt', 'enum-gpp-decrypt', 'enum-spider-plus',
  ],
  userhunt: [
    'enum-userhunter', 'enum-sessionhunter', 'enum-netcease', 'enum-nxc-user-hunt',
  ],
  adidns: [
    'enum-adidnsdump-linux', 'enum-adidns-wildcard', 'enum-adidns-wpad',
    'enum-adidns-record-inject', 'enum-dnsadmins-dll',
  ],
}

type Technique = {
  id: string
  title: string
  tool: string
  risk_level: string
  platform: string
  mitre_technique_id: string
  description: string
  commands: { label: string; command: string; params: string[] }[]
}

export function EnumerationHub() {
  const [activeTab, setActiveTab] = useState<TabKey>('domain')
  const [openId, setOpenId] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [platform, setPlatform] = useState<'linux' | 'windows' | 'all'>('all')

  const ids = TAB_TECHNIQUE_IDS[activeTab]

  const { data: techniques = [], isLoading } = useQuery({
    queryKey: ['ad-commands', 'enumeration', activeTab],
    queryFn: () => adCommandsApi.list<Technique>({ ids: ids.join(',') }),
    staleTime: 5 * 60 * 1000,
  })

  const visible = techniques.filter(t =>
    !search || t.title.toLowerCase().includes(search.toLowerCase()) || t.tool.toLowerCase().includes(search.toLowerCase())
  )

  const tab = TABS.find(t => t.key === activeTab)!

  return (
    <div className="p-6 space-y-6">
      <div>
        <BackButton />
        <h1 className="text-2xl font-bold text-white">Enumeration Hub</h1>
        <p className="text-sm text-zinc-500 mt-1">Domain intelligence gathering — Phase 2</p>
      </div>

      <div className="flex flex-wrap gap-2">
        {TABS.map(({ key, label, icon: Icon, color }) => (
          <button
            key={key}
            onClick={() => { setActiveTab(key); setOpenId(null); setSearch('') }}
            className={cn(
              'flex items-center gap-2 rounded-xl border px-4 py-2 text-sm font-medium transition-all',
              activeTab === key
                ? 'border-transparent text-black'
                : 'border-white/10 text-zinc-500 hover:border-white/20 hover:text-zinc-300 bg-white/[0.02]'
            )}
            style={activeTab === key ? { background: color } : {}}
          >
            <Icon className="h-3.5 w-3.5" />
            {label}
          </button>
        ))}
      </div>

      {/* Search + platform filter */}
      <div className="flex items-center gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-zinc-600" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder={`Search ${tab.label} techniques…`}
            className="w-full rounded-xl border border-white/10 bg-white/[0.03] py-2.5 pl-9 pr-4 text-sm text-zinc-200 outline-none placeholder:text-zinc-600 focus:border-white/20"
          />
        </div>
        {(['all', 'linux', 'windows'] as const).map(p => (
          <button key={p} onClick={() => setPlatform(p)}
            className={cn('rounded-xl border px-3 py-2 text-[11px] font-semibold transition-all flex-shrink-0',
              platform === p ? 'border-transparent text-black' : 'border-white/10 text-zinc-500 hover:text-zinc-300 bg-white/[0.02]'
            )}
            style={platform === p ? { background: p === 'linux' ? '#34d399' : p === 'windows' ? '#60a5fa' : '#6366f1' } : {}}>
            {p === 'all' ? 'All' : p === 'linux' ? '🐧' : '🪟'}
          </button>
        ))}
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-20 text-zinc-600 text-sm">Loading techniques…</div>
      ) : (
        <motion.div
          key={activeTab}
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.25 }}
          className="space-y-2"
        >
          {visible.length === 0 && (
            <div className="py-12 text-center text-sm text-zinc-600">
              {techniques.length === 0 ? 'No techniques loaded yet — techniques will appear once catalog is expanded.' : 'No techniques match your search.'}
            </div>
          )}
          {visible.map(tech => (
            <AttackTechCard
              key={tech.id}
              tech={tech}
              isOpen={openId === tech.id}
              onToggle={() => setOpenId(openId === tech.id ? null : tech.id)}
              accentColor={tab.color}
              platformFilter={platform}
            />
          ))}
        </motion.div>
      )}
    </div>
  )
}
