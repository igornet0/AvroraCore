export type PermissionName =
  | 'READ'
  | 'WRITE'
  | 'INSERT'
  | 'UPDATE'
  | 'DELETE'
  | 'GRANT'

export const ALL_PERMISSIONS: PermissionName[] = [
  'READ',
  'WRITE',
  'INSERT',
  'UPDATE',
  'DELETE',
  'GRANT',
]

export interface Role {
  id: string
  name: string
  scope: string
  permissions: string[]
}

export interface Session {
  active_role: Role
}

export interface TreeNode {
  path: string
  id: string
  generation: number
  state: string
}

export interface DataValue {
  path: string
  value: string
  encoding: string
}

export type DbLifecycle = 'empty' | 'locked' | 'unlocked'

export interface DbStatus {
  status: DbLifecycle
  path: string
}

export interface ChannelInfo {
  spec: {
    id: string
    kind: string
    bind: string | null
    capacity: number
  }
  started: boolean
}

export interface StreamSpec {
  id: string
  direction: string
  channel_id: string
  path_scope: string
  required_perms: string[]
}

export interface TriggerDef {
  id: string
  on: string
  path_prefix: string
  action: { type: string; stream_id?: string }
}

export interface CoreEventRow {
  kind: string
  path: string
  payload: string
  session: string
  role_id: string
  source_stream: string | null
  ts: string
}

export interface OverlayRow {
  path: string
  deleted: boolean
  payload: string
  source: string
  seq: number
}

export interface SubsystemInfo {
  spec: {
    id: string
    name: string
    stream_id: string
    path_template: string
    payload_template: string
    interval_ms: number
  }
  running: boolean
  ticks: number
}

export interface SchemaSnapshot {
  product: string
  nodes: TreeNode[]
  overlays: OverlayRow[]
  channels: ChannelInfo[]
  streams: StreamSpec[]
  triggers: TriggerDef[]
  subsystems: SubsystemInfo[]
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const token = getUiToken()
  const res = await fetch(path, {
    ...init,
    headers: {
      Accept: 'application/json',
      ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init?.headers,
    },
  })
  const text = await res.text()
  let body: unknown = null
  if (text) {
    try {
      body = JSON.parse(text)
    } catch {
      body = { error: text }
    }
  }
  if (!res.ok) {
    if (res.status === 401 && !path.startsWith('/api/auth/')) {
      clearUiToken()
    }
    const err =
      body && typeof body === 'object' && body !== null && 'error' in body
        ? String((body as { error: unknown }).error)
        : res.statusText
    throw new Error(err)
  }
  return body as T
}

const UI_TOKEN_KEY = 'avrora-ui-token'

export function getUiToken(): string | null {
  return sessionStorage.getItem(UI_TOKEN_KEY)
}

export function setUiToken(token: string) {
  sessionStorage.setItem(UI_TOKEN_KEY, token)
}

export function clearUiToken() {
  sessionStorage.removeItem(UI_TOKEN_KEY)
}

export interface AuthStatus {
  enrolled: boolean
  path: string
}

export interface AuthSetupBegin {
  totp_secret: string
  otpauth_url: string
  qr_png_base64: string | null
}

export interface AuthTokenResponse {
  token: string
  token_type: string
}

export const api = {
  product: () => request<{ name: string }>('/api/product'),
  health: () => request<{ status: string }>('/api/health'),
  authStatus: () => request<AuthStatus>('/api/auth/status'),
  authSetupBegin: (access_key: string) =>
    request<AuthSetupBegin>('/api/auth/setup/begin', {
      method: 'POST',
      body: JSON.stringify({ access_key }),
    }),
  authSetupConfirm: async (access_key: string, totp_code: string) => {
    const res = await request<AuthTokenResponse>('/api/auth/setup/confirm', {
      method: 'POST',
      body: JSON.stringify({ access_key, totp_code }),
    })
    setUiToken(res.token)
    return res
  },
  authLogin: async (access_key: string, totp_code: string) => {
    const res = await request<AuthTokenResponse>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ access_key, totp_code }),
    })
    setUiToken(res.token)
    return res
  },
  authLogout: async () => {
    try {
      await request<{ ok: boolean }>('/api/auth/logout', { method: 'POST' })
    } finally {
      clearUiToken()
    }
  },
  authMe: () => request<{ ok: boolean }>('/api/auth/me'),
  dbStatus: () => request<DbStatus>('/api/db/status'),
  lockDb: () => request<DbStatus>('/api/db/lock', { method: 'POST' }),
  session: () => request<Session>('/api/session'),
  activate: (role_id: string) =>
    request<Session>('/api/session/activate', {
      method: 'POST',
      body: JSON.stringify({ role_id }),
    }),
  roles: () => request<Role[]>('/api/roles'),
  createRole: (body: {
    id: string
    name: string
    scope: string
    permissions: string[]
  }) =>
    request<Role>('/api/roles', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  patchRole: (
    id: string,
    body: { name?: string; scope?: string; permissions?: string[] },
  ) =>
    request<Role>(`/api/roles/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify(body),
    }),
  deleteRole: (id: string) =>
    request<{ ok: boolean }>(`/api/roles/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),
  tree: () => request<TreeNode[]>('/api/tree'),
  ensureNode: (path: string) =>
    request<TreeNode>('/api/tree/ensure', {
      method: 'POST',
      body: JSON.stringify({ path }),
    }),
  revokeNode: (path: string) =>
    request<{ ok: boolean }>('/api/tree/revoke', {
      method: 'POST',
      body: JSON.stringify({ path }),
    }),
  rotateNode: (path: string) =>
    request<TreeNode>('/api/tree/rotate', {
      method: 'POST',
      body: JSON.stringify({ path }),
    }),
  listData: (prefix = '') =>
    request<{ keys: string[] }>(
      `/api/data?prefix=${encodeURIComponent(prefix)}`,
    ),
  getData: (path: string) =>
    request<DataValue>(`/api/data/${path.split('/').map(encodeURIComponent).join('/')}`),
  putData: (path: string, value: string) =>
    request<{ ok: boolean; path: string }>(
      `/api/data/${path.split('/').map(encodeURIComponent).join('/')}`,
      {
        method: 'PUT',
        body: JSON.stringify({ value }),
      },
    ),
  deleteData: (path: string) =>
    request<{ ok: boolean }>(
      `/api/data/${path.split('/').map(encodeURIComponent).join('/')}`,
      { method: 'DELETE' },
    ),
  channels: () => request<ChannelInfo[]>('/api/channels'),
  createChannel: (body: {
    id: string
    kind: string
    bind?: string
    capacity?: number
  }) =>
    request<{ ok: boolean; id: string }>('/api/channels', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  startChannel: (id: string) =>
    request<{ ok: boolean }>(`/api/channels/${encodeURIComponent(id)}/start`, {
      method: 'POST',
    }),
  stopChannel: (id: string) =>
    request<{ ok: boolean }>(`/api/channels/${encodeURIComponent(id)}/stop`, {
      method: 'POST',
    }),
  streams: () => request<StreamSpec[]>('/api/streams'),
  createStream: (body: {
    id: string
    direction: string
    channel_id: string
    path_scope: string
    required_perms?: string[]
  }) =>
    request<{ ok: boolean; id: string }>('/api/streams', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  ingest: (body: { stream_id: string; path: string; value: string }) =>
    request<{ ok: boolean }>('/api/streams/ingest', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  triggers: () => request<TriggerDef[]>('/api/triggers'),
  createTrigger: (body: {
    id: string
    on: string
    path_prefix: string
    forward_stream_id: string
  }) =>
    request<{ ok: boolean; id: string }>('/api/triggers', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  events: (limit = 100) =>
    request<CoreEventRow[]>(`/api/events?limit=${limit}`),
  schema: () => request<SchemaSnapshot>('/api/schema'),
  overlays: (prefix = '') =>
    request<OverlayRow[]>(`/api/overlays?prefix=${encodeURIComponent(prefix)}`),
  resolve: (path: string) =>
    request<{
      path: string
      base_present: boolean
      overlay_present: boolean
      deleted: boolean
      payload: string | null
      layer_seq: number | null
    }>('/api/resolve', {
      method: 'POST',
      body: JSON.stringify({ path }),
    }),
  seal: (path: string, value: string) =>
    request<{ ok: boolean }>('/api/seal', {
      method: 'POST',
      body: JSON.stringify({ path, value }),
    }),
  subsystems: () => request<SubsystemInfo[]>('/api/subsystems'),
  createSubsystem: (body: {
    id: string
    name: string
    stream_id: string
    path_template: string
    payload_template: string
    interval_ms?: number
  }) =>
    request<{ ok: boolean; id: string }>('/api/subsystems', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  startSubsystem: (id: string) =>
    request<{ ok: boolean }>(
      `/api/subsystems/${encodeURIComponent(id)}/start`,
      { method: 'POST' },
    ),
  stopSubsystem: (id: string) =>
    request<{ ok: boolean }>(
      `/api/subsystems/${encodeURIComponent(id)}/stop`,
      { method: 'POST' },
    ),
  deleteSubsystem: (id: string) =>
    request<{ ok: boolean }>(`/api/subsystems/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),
  backupList: () => request<BackupInfo[]>('/api/backup'),
  backupCreate: (backup_id: string, include_rowstore = false) =>
    request<{ backup_id: string; checkpoint_sequence: number }>('/api/backup', {
      method: 'POST',
      body: JSON.stringify({ backup_id, include_rowstore }),
    }),
  backupVerify: (backup_id: string) =>
    request<{ backup_id: string; checkpoint_sequence: number; valid: boolean; errors: string[] }>(
      `/api/backup/${encodeURIComponent(backup_id)}/verify`,
      { method: 'POST' },
    ),
  backupRestore: (backup_id: string, target_id: string) =>
    request<{
      backup_id: string
      target_id: string
      checkpoint_sequence: number
    }>('/api/backup/restore', {
      method: 'POST',
      body: JSON.stringify({ backup_id, target_id }),
    }),
  backupRecover: (target_id: string) =>
    request<{ target_id: string; checkpoint_sequence: number; state: string }>(
      `/api/backup/recover/${encodeURIComponent(target_id)}`,
      { method: 'POST' },
    ),
}

export interface BackupInfo {
  backup_id: string
  checkpoint_sequence: number
  created_at: string
  valid: boolean
  state: string
}
