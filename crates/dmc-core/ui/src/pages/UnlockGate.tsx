import { useEffect, useState } from 'react'
import { api, type DbLifecycle } from '../api/client'
import { Brand } from '../components/Brand'

export function UnlockGate({
  status,
  dbPath,
  onUnlocked,
}: {
  status: DbLifecycle
  dbPath: string
  onUnlocked: () => void
}) {
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const id = window.setInterval(() => {
      void (async () => {
        try {
          const st = await api.dbStatus()
          if (st.status === 'unlocked') onUnlocked()
        } catch (e) {
          setError(e instanceof Error ? e.message : String(e))
        }
      })()
    }, 1500)
    return () => window.clearInterval(id)
  }, [onUnlocked])

  return (
    <div className="unlock-screen">
      <div className="unlock-card">
        <div className="unlock-brand">
          <Brand tagline="Зашифрованное ядро" size="lg" />
        </div>

        <h1>{status === 'empty' ? 'База не создана' : 'Хранилище заблокировано'}</h1>
        <p className="muted">
          Unlock и создание vault выполняются только через Avrora Client.
          Master Password и USB KeyPass остаются на машине клиента; браузер их не
          принимает.
        </p>
        <p className="mono muted path-line">{dbPath}</p>

        {error && (
          <div className="banner error unlock-error" role="alert">
            {error}
          </div>
        )}

        <div className="usb-status wait">
          {status === 'empty'
            ? 'avrora-client db create — затем эта страница откроется'
            : 'avrora-client unlock — KeyPass на клиенте'}
        </div>
        <pre className="master-key-box">{`avrora-client bootstrap --server HOST:7432 --token …
avrora-client auth login
avrora-client ${status === 'empty' ? 'db create --usb /Volumes/KEY' : 'unlock --usb /Volumes/KEY'}`}</pre>
      </div>
    </div>
  )
}
