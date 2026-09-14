import { useCallback, useEffect, useState } from 'react'
import { api, type CoreEventRow } from '../api/client'

export function EventsPage({ onError }: { onError: (e: string | null) => void }) {
  const [events, setEvents] = useState<CoreEventRow[]>([])
  const [live, setLive] = useState(true)
  const [filter, setFilter] = useState('')

  const refresh = useCallback(async () => {
    try {
      setEvents(await api.events(150))
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e))
    }
  }, [onError])

  useEffect(() => {
    void refresh()
    if (!live) return
    const id = window.setInterval(() => void refresh(), 1000)
    return () => window.clearInterval(id)
  }, [refresh, live])

  const q = filter.trim().toLowerCase()
  const visible = [...events]
    .reverse()
    .filter(
      (e) =>
        !q ||
        e.kind.toLowerCase().includes(q) ||
        e.path.toLowerCase().includes(q) ||
        e.role_id.toLowerCase().includes(q) ||
        e.payload.toLowerCase().includes(q),
    )

  return (
    <section className="panel">
      <div className="panel-head row">
        <div>
          <h2>Лента событий</h2>
          <p>Overlay, триггеры, тики подсистем — всё в одном потоке.</p>
        </div>
        <div className="row-actions">
          <label className="toggle">
            <input
              type="checkbox"
              checked={live}
              onChange={(e) => setLive(e.target.checked)}
            />
            Live
          </label>
          <button type="button" onClick={() => void refresh()}>
            Обновить
          </button>
        </div>
      </div>

      <div className="toolbar">
        <label>
          Фильтр
          <input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="kind, path, role…"
          />
        </label>
      </div>

      {visible.length === 0 ? (
        <div className="empty-state">
          Событий пока нет. Отправьте ingest или запустите подсистему.
        </div>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>Время</th>
              <th>Тип</th>
              <th>Путь</th>
              <th>Роль</th>
              <th>Payload</th>
            </tr>
          </thead>
          <tbody>
            {visible.map((e, i) => (
              <tr key={`${e.ts}-${i}`}>
                <td className="mono muted">{formatTs(e.ts)}</td>
                <td>
                  <span className="pill">{e.kind}</span>
                </td>
                <td className="mono">{e.path}</td>
                <td>{e.role_id}</td>
                <td className="mono truncate" title={e.payload}>
                  {e.payload || '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}

function formatTs(ts: string) {
  try {
    return new Date(ts).toLocaleTimeString()
  } catch {
    return ts
  }
}
