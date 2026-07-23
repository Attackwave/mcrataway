const API_BASE = import.meta.env.VITE_API_BASE ?? window.location.origin

const TOKEN_STORAGE_KEY = 'mcrataway-token'

/** Read the auth token from localStorage (set via the UI) or a meta tag. */
function getAuthToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_STORAGE_KEY)
  } catch {
    return null
  }
}

export function setAuthToken(token: string | null): void {
  try {
    if (token) {
      localStorage.setItem(TOKEN_STORAGE_KEY, token)
    } else {
      localStorage.removeItem(TOKEN_STORAGE_KEY)
    }
  } catch {
    /* ignore storage errors */
  }
}

export function hasAuthToken(): boolean {
  return getAuthToken() !== null
}

export interface ScanJob {
  job_id: string
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED'
  progress: number
  total_files: number
  scanned_files: number
  error: string | null
}

export interface Finding {
  detector_id: string
  severity: string
  description: string
  file_path: string
  class_name: string
  method_name: string
  matched_value: string
  context: Record<string, string>
}

export interface Verdict {
  file_path: string
  sha256: string
  verdict: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS'
  confidence: number
  findings: Finding[]
  metadata: Record<string, unknown>
}

export interface RulePack {
  pack_id: string
  rule_count: number
  rules: Rule[]
}

export interface Rule {
  id: string
  family: string
  severity: string
  description: string
}

export interface QuarantineItem {
  original_path: string
  sha256: string
  verdict: string
  timestamp: string
  restored: boolean
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const headers = new Headers(options?.headers)
  headers.set('Content-Type', 'application/json')
  const token = getAuthToken()
  if (token) {
    headers.set('X-Mcrataway-Token', token)
  }
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  })
  if (res.status === 401) {
    throw new Error('Authentication required: set a valid token in Settings.')
  }
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`)
  }
  return res.json() as Promise<T>
}

export async function getRoots(): Promise<string[]> {
  return request('/system/roots')
}

export async function startScan(
  roots: string[] | null = null,
  autoDiscover = true,
): Promise<{ job_id: string; status: string; roots: string[] }> {
  const params = new URLSearchParams()
  if (roots && roots.length > 0) {
    for (const r of roots) {
      params.append('roots', r)
    }
  }
  if (autoDiscover) {
    params.set('auto_discover', 'true')
  }
  const qs = params.toString()
  return request(`/scan/${qs ? `?${qs}` : ''}`, { method: 'POST' })
}

export async function getJob(jobId: string): Promise<ScanJob> {
  return request(`/scan/${jobId}`)
}

export async function getFindings(severity?: string): Promise<Verdict[]> {
  const params = severity ? `?severity=${severity}` : ''
  return request(`/findings/${params}`)
}

export async function getRules(): Promise<RulePack[]> {
  return request('/rules/')
}

export async function getQuarantined(): Promise<QuarantineItem[]> {
  return request('/quarantine/')
}

export async function restoreQuarantined(sha256: string): Promise<{ success: boolean }> {
  return request(`/quarantine/${sha256}`, { method: 'DELETE' })
}

export function connectJobStream(jobId: string): WebSocket {
  const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const token = getAuthToken()
  const tokenQuery = token ? `?token=${encodeURIComponent(token)}` : ''
  return new WebSocket(
    `${wsProtocol}//${window.location.host}/scan/${jobId}/stream${tokenQuery}`,
  )
}

export function severityColor(severity: string): string {
  const colors: Record<string, string> = {
    CRITICAL: 'text-[var(--danger)] font-bold',
    HIGH: 'text-[var(--danger)]',
    MEDIUM: 'text-[var(--warning)]',
    LOW: 'text-[var(--text-secondary)]',
    INFO: 'text-[var(--text-secondary)] opacity-60',
  }
  return colors[severity] ?? 'text-[var(--text-secondary)]'
}

export function verdictBadge(verdict: string): string {
  const colors: Record<string, string> = {
    MALICIOUS: 'bg-[var(--danger-bg)] text-[var(--danger)]',
    SUSPICIOUS: 'bg-[var(--warning-bg)] text-[var(--warning)]',
    CLEAN: 'bg-green-950 text-[var(--success)]',
  }
  return colors[verdict] ?? 'bg-[var(--bg-tertiary)] text-[var(--text-secondary)]'
}
