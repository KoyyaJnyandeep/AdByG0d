export interface AISettings {
  claudeApiKey: string
  openaiApiKey: string
  openaiBaseUrl: string
  ollamaBaseUrl: string
  ollamaModel: string
  defaultProvider: 'claude' | 'openai' | 'ollama'
}

const KEY = 'adbygod_ai_settings'

const DEFAULTS: AISettings = {
  claudeApiKey: '',
  openaiApiKey: '',
  openaiBaseUrl: 'https://api.openai.com/v1',
  ollamaBaseUrl: 'http://localhost:11434',
  ollamaModel: 'llama3.2',
  defaultProvider: 'claude',
}

export function loadAISettings(): AISettings {
  if (typeof window === 'undefined') return { ...DEFAULTS }
  try {
    const raw = sessionStorage.getItem(KEY)
    if (!raw) return { ...DEFAULTS }
    return { ...DEFAULTS, ...JSON.parse(raw) }
  } catch {
    return { ...DEFAULTS }
  }
}

export function saveAISettings(settings: Partial<AISettings>): void {
  if (typeof window === 'undefined') return
  try {
    const current = loadAISettings()
    window.sessionStorage.setItem(KEY, JSON.stringify({ ...current, ...settings }))
  } catch {
    // Storage can be unavailable in private browsing or locked-down webviews.
  }
}

export function clearAISettings(): void {
  if (typeof window === 'undefined') return
  try {
    window.sessionStorage.removeItem(KEY)
  } catch {
    // Ignore storage failures; callers reset in-memory state separately.
  }
}

export function maskKey(key: string): string {
  if (!key || key.length < 16) return key ? '••••••••' : ''
  return key.slice(0, 8) + '••••••••' + key.slice(-4)
}
