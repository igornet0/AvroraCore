import { useCallback, useEffect, useState } from 'react'
import { api } from '../api/client'

type BackupItem = {
  backup_id: string
  checkpoint_sequence: number
  created_at: string
  valid: boolean
  state: string
}

export function BackupPage({ dbUnlocked }: { dbUnlocked: boolean }) {
  const [backupId, setBackupId] = useState('daily-01')
  const [targetId, setTargetId] = useState('restore-01')
  const [items, setItems] = useState<BackupItem[]>([])
  const [msg, setMsg] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const refresh = useCallback(async () => {
    const list = await api.backupList()
    setItems(list)
  }, [])

  useEffect(() => {
    if (dbUnlocked) void refresh().catch(() => setItems([]))
  }, [dbUnlocked, refresh])

  async function run(fn: () => Promise<void>) {
    setBusy(true)
    setMsg(null)
    try {
      await fn()
      await refresh()
    } catch (e) {
      setMsg(String(e))
    } finally {
      setBusy(false)
    }
  }

  if (!dbUnlocked) {
    return (
      <section className="panel">
        <p className="kicker">Backup</p>
        <p>Unlock vault via control plane (avrora-client) before creating backups.</p>
      </section>
    )
  }

  return (
    <section className="panel">
      <p className="kicker">Backup</p>
      <p className="meta">
        {`{data_root}`}/backups/backup-{'{id}'}/ — manifest + base/journal/runtime. Recover
        invalidates sessions.
      </p>
      <label htmlFor="b-id">Backup ID</label>
      <input id="b-id" value={backupId} onChange={(e) => setBackupId(e.target.value)} />
      <label htmlFor="t-id">Restore target</label>
      <input id="t-id" value={targetId} onChange={(e) => setTargetId(e.target.value)} />
      <div className="actions">
        <button
          type="button"
          className="btn primary"
          disabled={busy}
          onClick={() =>
            void run(async () => {
              const r = await api.backupCreate(backupId)
              setMsg(`created checkpoint_sequence=${r.checkpoint_sequence}`)
            })
          }
        >
          Create
        </button>
        <button
          type="button"
          className="btn"
          disabled={busy}
          onClick={() =>
            void run(async () => {
              const r = await api.backupVerify(backupId)
              setMsg(`valid=${r.valid}`)
            })
          }
        >
          Verify
        </button>
        <button
          type="button"
          className="btn"
          disabled={busy}
          onClick={() =>
            void run(async () => {
              const r = await api.backupRestore(backupId, targetId)
              setMsg(`restored seq=${r.checkpoint_sequence}`)
            })
          }
        >
          Restore
        </button>
        <button
          type="button"
          className="btn warn"
          disabled={busy}
          onClick={() =>
            void run(async () => {
              await api.lockDb()
              const r = await api.backupRecover(targetId)
              setMsg(`recovered seq=${r.checkpoint_sequence}; re-auth required`)
            })
          }
        >
          Recover
        </button>
      </div>
      {msg && <p className="meta">{msg}</p>}
      <ul>
        {items.map((b) => (
          <li key={b.backup_id}>
            {b.backup_id} seq={b.checkpoint_sequence} valid={String(b.valid)} state={b.state}
          </li>
        ))}
      </ul>
    </section>
  )
}
