import { useState } from 'react'
import { api, type DbLifecycle } from '../api/client'

export function UnlockGate({
  status,
  dbPath,
  onUnlocked,
}: {
  status: DbLifecycle
  dbPath: string
  onUnlocked: () => void
}) {
  const [masterKey, setMasterKey] = useState('')
  const [createdKey, setCreatedKey] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [withDemo, setWithDemo] = useState(true)

  async function create() {
    setBusy(true)
    setError(null)
    try {
      const res = await api.createDb(withDemo)
      setCreatedKey(res.master_key)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  async function unlock() {
    setBusy(true)
    setError(null)
    try {
      await api.unlockDb(masterKey.trim())
      onUnlocked()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  async function continueAfterCreate() {
    onUnlocked()
  }

  async function copyKey() {
    if (!createdKey) return
    await navigator.clipboard.writeText(createdKey)
    setCopied(true)
  }

  return (
    <div className="unlock-screen">
      <div className="unlock-card">
        <div className="brand unlock-brand">
          <span className="brand-mark">DBS</span>
          <div>
            <strong>DataBaseSecury</strong>
            <p>Master-key vault</p>
          </div>
        </div>

        <h1>{status === 'empty' ? 'Create database' : 'Unlock database'}</h1>
        <p className="muted">
          Master secret is kept only in process memory. On shutdown it is wiped.
          Ciphertext stays on disk; wrong key → data stays sealed.
        </p>
        <p className="mono muted path-line">{dbPath}</p>

        {error && (
          <div className="banner error unlock-error" role="alert">
            {error}
          </div>
        )}

        {createdKey ? (
          <div className="master-reveal">
            <h2>Save this master key now</h2>
            <p className="muted">
              It will not be shown again by the server. Without it, encrypted data
              cannot be opened after restart.
            </p>
            <code className="master-key-box">{createdKey}</code>
            <div className="row-actions">
              <button type="button" onClick={() => void copyKey()}>
                {copied ? 'Copied' : 'Copy'}
              </button>
              <button
                type="button"
                className="primary"
                onClick={() => void continueAfterCreate()}
              >
                I saved the key — continue
              </button>
            </div>
          </div>
        ) : status === 'empty' ? (
          <div className="unlock-form">
            <label className="check">
              <input
                type="checkbox"
                checked={withDemo}
                onChange={(e) => setWithDemo(e.target.checked)}
              />
              Seed demo company/finance/hr data
            </label>
            <button
              type="button"
              className="primary"
              disabled={busy}
              onClick={() => void create()}
            >
              {busy ? 'Creating…' : 'Generate master key & create DB'}
            </button>
          </div>
        ) : (
          <form
            className="unlock-form"
            onSubmit={(e) => {
              e.preventDefault()
              void unlock()
            }}
          >
            <label>
              Master key (64 hex chars)
              <input
                value={masterKey}
                onChange={(e) => setMasterKey(e.target.value)}
                placeholder="paste master key"
                autoComplete="off"
                spellCheck={false}
                className="mono"
              />
            </label>
            <button type="submit" className="primary" disabled={busy || !masterKey.trim()}>
              {busy ? 'Unlocking…' : 'Unlock'}
            </button>
          </form>
        )}
      </div>
    </div>
  )
}
