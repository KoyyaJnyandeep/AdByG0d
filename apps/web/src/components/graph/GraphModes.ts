import type { ColorMode, GraphMode, GraphToggles, LayoutMode } from './engine/types'
import { DEFAULT_TOGGLES } from './engine/types'

export interface ModePreset {
  mode: GraphMode
  label: string
  icon: string
  description: string
  hideEdgeTypes: string[]
  showOnlyEdgeTypes: string[]
  colorMode: ColorMode
  layoutHint: LayoutMode
  tier0Only: boolean
  toggleOverrides: Partial<GraphToggles>
}

const ATTACK_EDGE_TYPES = [
  'GENERIC_ALL','WRITE_DACL','WRITE_OWNER','OWNS','FORCE_CHANGE_PASSWORD',
  'DCSYNC','ALLOWED_TO_ACT','ALLOWED_TO_DELEGATE','ADD_MEMBER','ADMIN_TO',
  'LOCAL_ADMIN','CAN_ENROLL','HAS_CONTROL','PASS_THE_HASH','PASS_THE_TICKET',
  'PASS_THE_CERT','OVERPASS_THE_HASH','COERCION','REMOTE_EXEC','READ_LAPS_PASSWORD',
  'READ_GMSA_PASSWORD','ADD_KEY_CREDENTIAL_LINK','S4U2SELF','GPO_EXEC','DCOM_EXEC',
  'WMI_EXEC','SCM_EXEC','SEIMPERSONATE','ADCS_RELAY','PETITPOTAM','GOLDEN_TICKET',
  'AADCONNECT_SYNC','DNS_ADMIN_EXEC','NTLM_RELAY','KERBEROS_RELAY',
]

const DELEGATION_TYPES = ['ALLOWED_TO_DELEGATE','ALLOWED_TO_ACT','S4U2SELF']
const ADCS_TYPES = ['CAN_ENROLL','ADCS_RELAY','ADCS_ESC1','ADCS_ESC8','ADCS_ESC15','PASS_THE_CERT']
const LATERAL_TYPES = [
  'PASS_THE_HASH','PASS_THE_TICKET','PASS_THE_CERT','OVERPASS_THE_HASH',
  'COERCION','REMOTE_EXEC','DCOM_EXEC','WMI_EXEC','SCM_EXEC','ADMIN_TO','LOCAL_ADMIN',
]
const MEMBERSHIP_TYPES = ['MEMBER_OF','CONTAINS','APPLIES_GPO']

export const MODE_PRESETS: Record<GraphMode, ModePreset> = {
  ExposureOverview: {
    mode: 'ExposureOverview',
    label: 'Exposure Overview',
    icon: 'activity',
    description: 'Full attack surface — all high-risk edges visible',
    hideEdgeTypes: ['TRUSTS'],
    showOnlyEdgeTypes: [],
    colorMode: 'risk',
    layoutHint: 'force',
    tier0Only: false,
    toggleOverrides: { hideLowRisk: true },
  },
  Tier0Path: {
    mode: 'Tier0Path',
    label: 'Tier-0 Path View',
    icon: 'shield',
    description: 'Only paths that lead to Tier-0 assets',
    hideEdgeTypes: MEMBERSHIP_TYPES,
    showOnlyEdgeTypes: ATTACK_EDGE_TYPES,
    colorMode: 'tier',
    layoutHint: 'attack',
    tier0Only: true,
    toggleOverrides: { attackEdgesOnly: true, tier0PathsOnly: true },
  },
  ADCSView: {
    mode: 'ADCSView',
    label: 'ADCS View',
    icon: 'certificate',
    description: 'Certificate Services enrollment and abuse paths',
    hideEdgeTypes: [],
    showOnlyEdgeTypes: ADCS_TYPES,
    colorMode: 'risk',
    layoutHint: 'force',
    tier0Only: false,
    toggleOverrides: {},
  },
  DelegationView: {
    mode: 'DelegationView',
    label: 'Delegation View',
    icon: 'repeat',
    description: 'Kerberos delegation chains',
    hideEdgeTypes: [],
    showOnlyEdgeTypes: DELEGATION_TYPES,
    colorMode: 'risk',
    layoutHint: 'force',
    tier0Only: false,
    toggleOverrides: {},
  },
  LateralMovement: {
    mode: 'LateralMovement',
    label: 'Lateral Movement',
    icon: 'git-branch',
    description: 'Pass-the-* and remote execution edges',
    hideEdgeTypes: [],
    showOnlyEdgeTypes: LATERAL_TYPES,
    colorMode: 'risk',
    layoutHint: 'force',
    tier0Only: false,
    toggleOverrides: {},
  },
  GroupMembership: {
    mode: 'GroupMembership',
    label: 'Group Membership',
    icon: 'users',
    description: 'Group hierarchy and membership relationships',
    hideEdgeTypes: [],
    showOnlyEdgeTypes: MEMBERSHIP_TYPES,
    colorMode: 'default',
    layoutHint: 'hierarchical',
    tier0Only: false,
    toggleOverrides: { showContainers: true },
  },
  RemediationSim: {
    mode: 'RemediationSim',
    label: 'Remediation Sim',
    icon: 'tool',
    description: 'Focus on directly actionable attack edges',
    hideEdgeTypes: MEMBERSHIP_TYPES,
    showOnlyEdgeTypes: [],
    colorMode: 'risk',
    layoutHint: 'force',
    tier0Only: false,
    toggleOverrides: { hideLowRisk: true, attackEdgesOnly: true },
  },
}

export function applyModeToState(
  preset: ModePreset,
): {
  edgeTypeFilter: Set<string>
  colorMode: ColorMode
  layoutMode: LayoutMode
  tier0Only: boolean
  toggles: GraphToggles
} {
  return {
    edgeTypeFilter: preset.showOnlyEdgeTypes.length > 0
      ? new Set(preset.showOnlyEdgeTypes)
      : new Set<string>(),
    colorMode: preset.colorMode,
    layoutMode: preset.layoutHint,
    tier0Only: preset.tier0Only,
    toggles: { ...DEFAULT_TOGGLES, ...preset.toggleOverrides },
  }
}
