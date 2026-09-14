import { useCallback, useEffect, useState } from 'react'
import { api } from '../api/client'

export function DataBrowser({ onError }: { onError: (msg: string | null) => void }) {
  const [keys, setKeys] = useState<string[]>([])
  const [prefix, setPrefix] = useState('')
  const [selected, setSelected] = useState<string | null>(null)
  const [value, setValue] = useState('')
  const [encoding, setEncoding] = useState('')
  const [newPath, setNewPath] = useState('')
  const [newValue, setNewValue] = useState('')

  const loadKeys = useCallback(async () => {
    onError(null)
    try {
      const res = await api.listData(prefix)
      setKeys(res.keys)
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e))
    }
  }, [prefix, onError])

  useEffect(() => {
    void loadKeys()
  }, [loadKeys])

  async function openKey(path: string) {
    onError(null)
    try {
      const res = await api.getData(path)
      setSelected(path)
      setValue(res.value)
      setEncoding(res.encoding)
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e))
    }
  }

  async function save() {
    if (!selected) return
    onError(null)
    try {
      await api.putData(selected, value)
      await loadKeys()
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e))
    }
  }

  async function remove() {
    if (!selected) return
    onError(null)
    try {
      await api.deleteData(selected)
      setSelected(null)
      setValue('')
      setEncoding('')
      await loadKeys()
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e))
    }
  }

  async function create() {
    onError(null)
    const path = newPath.replace(/^\//, '')
    try {
      await api.putData(path, newValue)
      setNewPath('')
      setNewValue('')
      await loadKeys()
      await openKey(path)
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e))
    }
  }

  return (
    <section className="panel">
      <div className="panel-head">
        <h1>Data Browser</h1>
        <p>Encrypted KV entries visible under the active role scope.</p>
      </div>

      <div className="toolbar">
        <label>
          Prefix
          <input
            value={prefix}
            onChange={(e) => setPrefix(e.target.value)}
            placeholder="company/finance"
          />
        </label>
        <button type="button" onClick={() => void loadKeys()}>
          Refresh
        </button>
      </div>

      <div className="split">
        <div className="list-pane">
          <h2>Keys ({keys.length})</h2>
          <ul className="key-list">
            {keys.map((k) => (
              <li key={k}>
                <button
                  type="button"
                  className={selected === k ? 'key-item active' : 'key-item'}
                  onClick={() => void openKey(k)}
                >
                  {k}
                </button>
              </li>
            ))}
            {keys.length === 0 && <li className="muted">No keys</li>}
          </ul>

          <div className="create-box">
            <h3>Create / overwrite</h3>
            <input
              value={newPath}
              onChange={(e) => setNewPath(e.target.value)}
              placeholder="company/finance/invoices/003"
            />
            <textarea
              value={newValue}
              onChange={(e) => setNewValue(e.target.value)}
              placeholder="value"
              rows={3}
            />
            <button type="button" className="primary" onClick={() => void create()} disabled={!newPath}>
              Put
            </button>
          </div>
        </div>

        <div className="detail-pane">
          {selected ? (
            <>
              <h2>{selected}</h2>
              <p className="muted">encoding: {encoding}</p>
              <textarea
                className="value-editor"
                value={value}
                onChange={(e) => setValue(e.target.value)}
                rows={16}
              />
              <div className="row-actions">
                <button type="button" className="primary" onClick={() => void save()}>
                  Save
                </button>
                <button type="button" className="danger" onClick={() => void remove()}>
                  Delete
                </button>
              </div>
            </>
          ) : (
            <p className="muted">Select a key to inspect its decrypted value.</p>
          )}
        </div>
      </div>
    </section>
  )
}
