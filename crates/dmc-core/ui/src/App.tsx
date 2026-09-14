import { useCallback, useEffect, useState, type ReactNode } from 'react'
import {
  api,
  clearUiToken,
  getUiToken,
  type DbLifecycle,
  type Role,
} from './api/client'
import { DataBrowser } from './pages/DataBrowser'
import { AccessTree } from './pages/AccessTree'
import { Roles } from './pages/Roles'
import { UnlockGate } from './pages/UnlockGate'
import { AuthGate } from './pages/AuthGate'
import { ChannelsPage } from './pages/ChannelsPage'
import { EventsPage } from './pages/EventsPage'
import { SchemaPage } from './pages/SchemaPage'
import { SubsystemsPage } from './pages/SubsystemsPage'
import { BackupPage } from './pages/BackupPage'
import { Brand } from './components/Brand'
import './App.css'

type Page =
  | 'schema'
  | 'channels'
  | 'events'
  | 'subsystems'
  | 'data'
  | 'tree'
  | 'roles'
  | 'backup'
type Theme = 'light' | 'dark'

const THEME_KEY = 'avrora-theme'

const PAGES: Record<
  Page,
  { title: string; blurb: string; group: 'runtime' | 'storage' | 'access' }
> = {
  schema: {
    title: 'Схема',
    blurb: 'Дерево ключей и слои overlay в реальном времени',
    group: 'runtime',
  },
  channels: {
    title: 'Потоки и каналы',
    blurb: 'Каналы связи, inbound/outbound потоки и триггеры',
    group: 'runtime',
  },
  events: {
    title: 'События',
    blurb: 'Живая лента обработки и срабатываний',
    group: 'runtime',
  },
  subsystems: {
    title: 'Подсистемы',
    blurb: 'Продьюсеры данных, которые пишут в потоки',
    group: 'runtime',
  },
  data: {
    title: 'Данные',
    blurb: 'Просмотр и правка значений по путям',
    group: 'storage',
  },
  tree: {
    title: 'Дерево доступа',
    blurb: 'Узлы ключей: ensure, revoke, rotate',
    group: 'storage',
  },
  roles: {
    title: 'Роли',
    blurb: 'Права и области доступа сессии',
    group: 'access',
  },
  backup: {
    title: 'Backup',
    blurb: 'Снимки vault (base/journal/runtime) и recover',
    group: 'storage',
  },
}

function readInitialTheme(): Theme {
  const saved = localStorage.getItem(THEME_KEY)
  if (saved === 'light' || saved === 'dark') return saved
  return 'dark'
}

function isRootRole(role: Role | null): boolean {
  return role?.id === 'root'
}

export default function App() {
  const [page, setPage] = useState<Page>('schema')
  const [roles, setRoles] = useState<Role[]>([])
  const [active, setActive] = useState<Role | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [ready, setReady] = useState(false)
  const [theme, setTheme] = useState<Theme>(() => readInitialTheme())
  const [dbStatus, setDbStatus] = useState<DbLifecycle | null>(null)
  const [dbPath, setDbPath] = useState('')
  const [uiAuthed, setUiAuthed] = useState(false)
  const [authEnrolled, setAuthEnrolled] = useState<boolean | null>(null)
  const [authPath, setAuthPath] = useState('')

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem(THEME_KEY, theme)
  }, [theme])

  const refreshAuth = useCallback(async () => {
    const st = await api.authStatus()
    setAuthEnrolled(st.enrolled)
    setAuthPath(st.path)
    if (!st.enrolled) {
      setUiAuthed(false)
      return false
    }
    if (!getUiToken()) {
      setUiAuthed(false)
      return false
    }
    try {
      await api.authMe()
      setUiAuthed(true)
      return true
    } catch {
      clearUiToken()
      setUiAuthed(false)
      return false
    }
  }, [])

  const refreshStatus = useCallback(async () => {
    const st = await api.dbStatus()
    setDbStatus(st.status)
    setDbPath(st.path)
    return st.status
  }, [])

  const refresh = useCallback(async () => {
    setError(null)
    try {
      const ok = await refreshAuth()
      if (!ok) {
        setReady(false)
        setDbStatus(null)
        setActive(null)
        setRoles([])
        return
      }
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
  }, [refreshAuth, refreshStatus])

  useEffect(() => {
    void refresh()
  }, [refresh])

  useEffect(() => {
    if (dbStatus !== 'unlocked') return
    const id = window.setInterval(() => {
      void (async () => {
        try {
          const st = await api.dbStatus()
          if (st.status !== 'unlocked') await refresh()
        } catch {
          await refresh()
        }
      })()
    }, 2000)
    return () => window.clearInterval(id)
  }, [dbStatus, refresh])

  useEffect(() => {
    if (page === 'backup' && !isRootRole(active)) {
      setPage('schema')
    }
  }, [page, active])

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

  async function onUiLogout() {
    setError(null)
    try {
      await api.authLogout()
    } catch {
      clearUiToken()
    }
    setUiAuthed(false)
    setReady(false)
    setDbStatus(null)
    await refresh()
  }

  if (authEnrolled === null) {
    return (
      <div className="unlock-screen">
        <div className="boot-card">
          <img className="boot-logo" src="/icon.png" alt="" width={64} height={64} />
          <div className="boot-pulse" aria-hidden />
          <p>Подключение к Avrora…</p>
        </div>
      </div>
    )
  }

  if (!uiAuthed) {
    return (
      <AuthGate
        enrolled={authEnrolled}
        authPath={authPath}
        onAuthed={() => void refresh()}
      />
    )
  }

  if (dbStatus === null) {
    return (
      <div className="unlock-screen">
        <div className="boot-card">
          <img className="boot-logo" src="/icon.png" alt="" width={64} height={64} />
          <div className="boot-pulse" aria-hidden />
          <p>Загрузка хранилища…</p>
        </div>
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

  const meta = PAGES[page]
  const rootActive = isRootRole(active)

  return (
    <div className="shell">
      <aside className="sidebar">
        <Brand tagline="Ядро данных" size="sm" />

        <nav className="nav-groups" aria-label="Разделы">
          <NavGroup label="Runtime">
            <NavButton active={page === 'schema'} onClick={() => setPage('schema')}>
              Схема
              <span>live</span>
            </NavButton>
            <NavButton active={page === 'channels'} onClick={() => setPage('channels')}>
              Потоки
              <span>I/O</span>
            </NavButton>
            <NavButton active={page === 'events'} onClick={() => setPage('events')}>
              События
            </NavButton>
            <NavButton active={page === 'subsystems'} onClick={() => setPage('subsystems')}>
              Подсистемы
            </NavButton>
          </NavGroup>
          <NavGroup label="Хранилище">
            <NavButton active={page === 'data'} onClick={() => setPage('data')}>
              Данные
            </NavButton>
            <NavButton active={page === 'tree'} onClick={() => setPage('tree')}>
              Ключи
            </NavButton>
            {rootActive && (
              <NavButton active={page === 'backup'} onClick={() => setPage('backup')}>
                Backup
                <span>root</span>
              </NavButton>
            )}
          </NavGroup>
          <NavGroup label="Доступ">
            <NavButton active={page === 'roles'} onClick={() => setPage('roles')}>
              Роли
            </NavButton>
          </NavGroup>
        </nav>

        <div className="sidebar-foot">
          <button type="button" className="theme-toggle" onClick={() => void onLock()}>
            <span className="theme-meta">
              <strong>Заблокировать</strong>
              <span>Очистить ключи в RAM</span>
            </span>
          </button>
          <button type="button" className="theme-toggle" onClick={() => void onUiLogout()}>
            <span className="theme-meta">
              <strong>Выйти из UI</strong>
              <span>Сбросить 2FA-сессию</span>
            </span>
          </button>
          <button
            type="button"
            className="theme-toggle"
            onClick={() => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))}
          >
            <span className="theme-meta">
              <strong>{theme === 'dark' ? 'Тёмная' : 'Светлая'}</strong>
              <span>Тема оформления</span>
            </span>
          </button>
        </div>
      </aside>

      <div className="main">
        <header className="topbar">
          <div className="page-crumb">
            <span className="crumb-group">
              {meta.group === 'runtime'
                ? 'Runtime'
                : meta.group === 'storage'
                  ? 'Хранилище'
                  : 'Доступ'}
            </span>
            <h1>{meta.title}</h1>
            <p>{meta.blurb}</p>
          </div>
          <div className="session-box">
            <div className="session-banner">
              {active ? (
                <>
                  <span className="session-label">Сессия</span>
                  <strong>{active.name}</strong>
                  <span className="pill ok">{active.scope || '/'}</span>
                </>
              ) : (
                <span className="muted">Нет сессии</span>
              )}
            </div>
            <label className="role-select">
              Роль
              <select
                value={active?.id ?? ''}
                onChange={(e) => void onActivate(e.target.value)}
                disabled={!ready}
              >
                {roles.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.name}
                  </option>
                ))}
              </select>
            </label>
          </div>
        </header>

        {error && (
          <div className="banner error" role="alert">
            <span>{error}</span>
            <button type="button" onClick={() => void refresh()}>
              Повторить
            </button>
          </div>
        )}

        <main className="content">
          {page === 'schema' && <SchemaPage onError={setError} />}
          {page === 'channels' && <ChannelsPage onError={setError} />}
          {page === 'events' && <EventsPage onError={setError} />}
          {page === 'subsystems' && <SubsystemsPage onError={setError} />}
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
          {page === 'backup' && rootActive && (
            <BackupPage dbUnlocked={dbStatus === 'unlocked'} />
          )}
        </main>
      </div>
    </div>
  )
}

function NavGroup({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="nav-group">
      <div className="nav-group-label">{label}</div>
      <div className="nav-group-items">{children}</div>
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
