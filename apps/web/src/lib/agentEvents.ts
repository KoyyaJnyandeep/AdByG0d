export type AgentEventType =
  | 'chunk' | 'done' | 'error'
  | 'tool_call' | 'tool_result'
  | 'approval_required' | 'approved' | 'rejected'
  | 'sub_agent_spawned' | 'sub_agent_update' | 'sub_agent_done'
  | 'target_card_update' | 'critical_alert'
  | 'memory_saved' | 'report_section_written'
  | 'campaign_phase' | 'playbook_step'

export interface ChunkEvent { type: 'chunk'; text: string }
export interface DoneEvent { type: 'done' }
export interface ErrorEvent { type: 'error'; message: string }

export interface ToolCallEvent {
  type: 'tool_call'
  id: string
  tool: string
  args: Record<string, unknown>
}

export interface ToolResultEvent {
  type: 'tool_result'
  id: string
  tool: string
  summary: string
  duration_ms: number
}

export interface ApprovalRequiredEvent {
  type: 'approval_required'
  request_id: string
  tool: string
  args: Record<string, unknown>
  description: string
  opsec_rating: 'QUIET' | 'MEDIUM' | 'LOUD' | 'CRITICAL'
  opsec_note: string
}

export interface ApprovedEvent { type: 'approved'; request_id: string }
export interface RejectedEvent { type: 'rejected'; request_id: string }

export interface SubAgentSpawnedEvent { type: 'sub_agent_spawned'; agent_id: string; task: string }
export interface SubAgentUpdateEvent { type: 'sub_agent_update'; agent_id: string; status: string }
export interface SubAgentDoneEvent { type: 'sub_agent_done'; agent_id: string; summary: string }

export interface TargetCardUpdateEvent {
  type: 'target_card_update'
  card: {
    domain?: string
    dc_ip?: string
    auth_level?: string
    owned_accounts?: string[]
    owned_machines?: string[]
    findings_critical?: number
    hashes_captured?: number
    hashes_cracked?: number
    paths_to_da?: number
    opsec_noise?: string
    next_best_action?: string
  }
}

export interface CriticalAlertEvent {
  type: 'critical_alert'
  severity: 'CRITICAL' | 'HIGH'
  title: string
  detail: string
  recommended_action: string
}

export interface MemorySavedEvent { type: 'memory_saved'; key: string; value: unknown }
export interface ReportSectionWrittenEvent {
  type: 'report_section_written'
  section: string
  preview: string
}
export interface CampaignPhaseEvent { type: 'campaign_phase'; phase: string; status: string }
export interface PlaybookStepEvent { type: 'playbook_step'; step_id: string; status: string }

export type AgentEvent =
  | ChunkEvent | DoneEvent | ErrorEvent
  | ToolCallEvent | ToolResultEvent
  | ApprovalRequiredEvent | ApprovedEvent | RejectedEvent
  | SubAgentSpawnedEvent | SubAgentUpdateEvent | SubAgentDoneEvent
  | TargetCardUpdateEvent | CriticalAlertEvent
  | MemorySavedEvent | ReportSectionWrittenEvent
  | CampaignPhaseEvent | PlaybookStepEvent

export function parseAgentEvent(line: string): AgentEvent | null {
  const raw = line.startsWith('data: ') ? line.slice(6) : line
  if (!raw.trim()) return null
  try {
    return JSON.parse(raw) as AgentEvent
  } catch {
    return null
  }
}

export interface TraceItem {
  id: string
  tool: string
  args: Record<string, unknown>
  summary?: string
  duration_ms?: number
  status: 'pending' | 'done' | 'error'
}
