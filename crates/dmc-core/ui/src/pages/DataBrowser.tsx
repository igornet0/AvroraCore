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
        <h2>Значения по путям</h2>
        <p>Список ключей в scope активной роли. Overlay виден как обычное значение.</p>
      </div>

      <div className="toolbar">
        <label>
          Префикс
          <input
            value={prefix}
            onChange={(e) => setPrefix(e.target.value)}
            placeholder="company/finance"
          />
        </label>
        <button type="button" onClick={() => void loadKeys()}>
          Обновить
        </button>
      </div>

      <div className="split">
        <div className="list-pane soft">
          <h2>Ключи ({keys.length})</h2>
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
            {keys.length === 0 && (
              <li className="empty-state" style={{ border: 0 }}>
                Нет ключей по этому префиксу
              </li>
            )}
          </ul>

          <div className="create-box">
            <h3>Создать / перезаписать</h3>
            <input
              value={newPath}
              onChange={(e) => setNewPath(e.target.value)}
              placeholder="company/finance/invoices/003"
            />
            <textarea
              value={newValue}
              onChange={(e) => setNewValue(e.target.value)}
              placeholder="значение"
              rows={3}
            />
            <button type="button" className="primary" onClick={() => void create()} disabled={!newPath}>
              Сохранить
            </button>
          </div>
        </div>

        <div className="detail-pane soft">
          {selected ? (
            <>
              <h2 className="mono">{selected}</h2>
              <p className="muted">encoding: {encoding}</p>
              <textarea
                className="value-editor"
                value={value}
                onChange={(e) => setValue(e.target.value)}
                rows={16}
              />
              <div className="row-actions">
                <button type="button" className="primary" onClick={() => void save()}>
                  Сохранить
                </button>
                <button type="button" className="danger" onClick={() => void remove()}>
                  Удалить
                </button>
              </div>
            </>
          ) : (
            <div className="empty-state">Выберите ключ слева</div>
          )}
        </div>
      </div>
    </section>
  )
}
