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

export interface CreateDbResponse {
  status: string
  master_key: string
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: {
      Accept: 'application/json',
      ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
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
    const err =
      body && typeof body === 'object' && body !== null && 'error' in body
        ? String((body as { error: unknown }).error)
        : res.statusText
    throw new Error(err)
  }
  return body as T
}

export const api = {
  health: () => request<{ status: string }>('/api/health'),
  dbStatus: () => request<DbStatus>('/api/db/status'),
  createDb: (with_demo = true) =>
    request<CreateDbResponse>('/api/db/create', {
      method: 'POST',
      body: JSON.stringify({ with_demo }),
    }),
  unlockDb: (master_key: string) =>
    request<DbStatus>('/api/db/unlock', {
      method: 'POST',
      body: JSON.stringify({ master_key }),
    }),
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
}
