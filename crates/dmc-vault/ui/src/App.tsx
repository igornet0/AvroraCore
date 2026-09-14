import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { api, type DbLifecycle, type Role } from './api/client'
import { DataBrowser } from './pages/DataBrowser'
import { AccessTree } from './pages/AccessTree'
import { Roles } from './pages/Roles'
import { UnlockGate } from './pages/UnlockGate'
import './App.css'

type Page = 'data' | 'tree' | 'roles'
type Theme = 'light' | 'dark'

const THEME_KEY = 'dbs-theme'

function readInitialTheme(): Theme {
  const saved = localStorage.getItem(THEME_KEY)
  if (saved === 'light' || saved === 'dark') return saved
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

export default function App() {
  const [page, setPage] = useState<Page>('data')
  const [roles, setRoles] = useState<Role[]>([])
  const [active, setActive] = useState<Role | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [ready, setReady] = useState(false)
  const [theme, setTheme] = useState<Theme>(() => readInitialTheme())
  const [dbStatus, setDbStatus] = useState<DbLifecycle | null>(null)
  const [dbPath, setDbPath] = useState('')

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem(THEME_KEY, theme)
  }, [theme])

  const refreshStatus = useCallback(async () => {
    const st = await api.dbStatus()
    setDbStatus(st.status)
    setDbPath(st.path)
    return st.status
  }, [])

  const refresh = useCallback(async () => {
    setError(null)
    try {
      const status = await refreshStatus()
      if (status !== 'unlocked') {
        setReady(false)
        setActive(null)
        setRoles([])
        return
      }
      const [session, roleList] = await Promise.all([api.session(), api.roles()])
      setActive(session.active_role)
      setRoles(roleList)
      setReady(true)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
      setReady(false)
    }
  }, [refreshStatus])

  useEffect(() => {
    void refresh()
  }, [refresh])

  async function onActivate(roleId: string) {
    setError(null)
    try {
      const session = await api.activate(roleId)
      setActive(session.active_role)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  async function onLock() {
    setError(null)
    try {
      await api.lockDb()
      await refresh()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  function toggleTheme() {
    setTheme((t) => (t === 'dark' ? 'light' : 'dark'))
  }

  if (dbStatus === null) {
    return (
      <div className="unlock-screen">
        <p className="muted">Connecting…</p>
      </div>
    )
  }

  if (dbStatus !== 'unlocked') {
    return (
      <UnlockGate
        status={dbStatus}
        dbPath={dbPath}
        onUnlocked={() => void refresh()}
      />
    )
  }

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">DBS</span>
          <div>
            <strong>DataBaseSecury</strong>
            <p>Local admin</p>
          </div>
        </div>
        <nav>
          <NavButton active={page === 'data'} onClick={() => setPage('data')}>
            Data Browser
          </NavButton>
          <NavButton active={page === 'tree'} onClick={() => setPage('tree')}>
            Access Tree
          </NavButton>
          <NavButton active={page === 'roles'} onClick={() => setPage('roles')}>
            Roles
          </NavButton>
        </nav>
        <div className="sidebar-foot">
          <button type="button" className="theme-toggle" onClick={() => void onLock()}>
            <span className="theme-meta">
              <strong>Lock</strong>
              <span>Wipe keys from RAM</span>
            </span>
            <span className="theme-icon" aria-hidden>
              ■
            </span>
          </button>
          <button type="button" className="theme-toggle" onClick={toggleTheme}>
            <span className="theme-meta">
              <strong>{theme === 'dark' ? 'Dark' : 'Light'}</strong>
              <span>Switch appearance</span>
            </span>
            <span className="theme-icon" aria-hidden>
              {theme === 'dark' ? '☾' : '☀'}
            </span>
          </button>
        </div>
      </aside>

      <div className="main">
        <header className="topbar">
          <div className="session-banner">
            {active ? (
              <>
                Acting as <strong>{active.name}</strong>
                <span className="muted">
                  {active.scope || '/'} · {active.permissions.join(', ') || 'none'}
                </span>
              </>
            ) : (
              <span className="muted">No session</span>
            )}
          </div>
          <label className="role-select">
            Role
            <select
              value={active?.id ?? ''}
              onChange={(e) => void onActivate(e.target.value)}
              disabled={!ready}
            >
              {roles.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.name} ({r.id})
                </option>
              ))}
            </select>
          </label>
        </header>

        {error && (
          <div className="banner error" role="alert">
            {error}
            <button type="button" onClick={() => void refresh()}>
              Retry
            </button>
          </div>
        )}

        <main className="content">
          {page === 'data' && <DataBrowser onError={setError} />}
          {page === 'tree' && <AccessTree onError={setError} />}
          {page === 'roles' && (
            <Roles
              roles={roles}
              activeId={active?.id ?? null}
              onChange={() => void refresh()}
              onActivate={(id) => void onActivate(id)}
              onError={setError}
            />
          )}
        </main>
      </div>
    </div>
  )
}

function NavButton({
  active,
  onClick,
  children,
}: {
  active: boolean
  onClick: () => void
  children: ReactNode
}) {
  return (
    <button
      type="button"
      className={active ? 'nav-btn active' : 'nav-btn'}
      onClick={onClick}
    >
      {children}
    </button>
  )
}
