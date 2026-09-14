import { useCallback, useEffect, useState } from 'react'
import { api, type OverlayRow, type SchemaSnapshot } from '../api/client'

export function SchemaPage({ onError }: { onError: (e: string | null) => void }) {
  const [schema, setSchema] = useState<SchemaSnapshot | null>(null)
  const [overlays, setOverlays] = useState<OverlayRow[]>([])
  const [path, setPath] = useState('company/finance/invoices/1')
  const [resolved, setResolved] = useState<{
    path: string
    base_present: boolean
    overlay_present: boolean
    deleted: boolean
    payload: string | null
    layer_seq: number | null
  } | null>(null)
  const [sealValue, setSealValue] = useState('BASE')
  const [live, setLive] = useState(true)

  const refresh = useCallback(async () => {
    try {
      const [s, o] = await Promise.all([api.schema(), api.overlays('')])
      setSchema(s)
      setOverlays(o)
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e))
    }
  }, [onError])

  useEffect(() => {
    void refresh()
    if (!live) return
    const id = window.setInterval(() => void refresh(), 1500)
    return () => window.clearInterval(id)
  }, [refresh, live])

  return (
    <div className="panel-stack">
      <section className="panel">
        <div className="panel-head row">
          <div>
            <h2>Карта данных</h2>
            <p>
              База статична. Overlay — ссылочный слой поверх неё. Live-обновление{' '}
              {live ? 'включено' : 'выключено'}.
            </p>
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

        <div className="stat-row">
          <Stat label="Узлы" value={String(schema?.nodes.length ?? 0)} />
          <Stat label="Overlay" value={String(overlays.length)} />
          <Stat label="Каналы" value={String(schema?.channels.length ?? 0)} />
          <Stat label="Потоки" value={String(schema?.streams.length ?? 0)} />
          <Stat label="Триггеры" value={String(schema?.triggers.length ?? 0)} />
          <Stat
            label="Подсистемы"
            value={String(schema?.subsystems.length ?? 0)}
          />
        </div>

        <div className="schema-grid">
          <div className="list-pane soft">
            <h3>Дерево ключей (base)</h3>
            {(schema?.nodes.length ?? 0) === 0 ? (
              <div className="empty-state">Пока пусто — создайте БД с demo или seal.</div>
            ) : (
              <ul className="tree-list">
                {(schema?.nodes ?? []).map((n) => (
                  <li key={n.path || '/'}>
                    <button
                      type="button"
                      className="tree-pick"
                      onClick={() => setPath(n.path || '/')}
                    >
                      <span className="mono">{n.path || '/'}</span>
                      <span className={n.state === 'Active' ? 'pill ok' : 'pill bad'}>
                        {n.state}
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
          <div className="list-pane soft">
            <h3>Слои overlay</h3>
            {overlays.length === 0 ? (
              <div className="empty-state">
                Нет наложений. Ingest или подсистема создаст слой.
              </div>
            ) : (
              <ul className="tree-list">
                {overlays.map((o) => (
                  <li key={`${o.path}-${o.seq}`}>
                    <button
                      type="button"
                      className="tree-pick"
                      onClick={() => setPath(o.path)}
                    >
                      <span>
                        <span className="pill">#{o.seq}</span>{' '}
                        <span className="mono">{o.path}</span>
                      </span>
                      <span className="muted truncate">
                        {o.deleted ? 'deleted' : o.payload.slice(0, 48)}
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>Просмотр пути</h2>
          <p>Resolve показывает base + overlay. Seal записывает неизменную базу.</p>
        </div>
        <div className="field-grid two">
          <label className="span-2">
            Путь
            <input
              value={path}
              onChange={(e) => setPath(e.target.value)}
              className="mono"
            />
          </label>
          <label>
            Значение для seal (base)
            <input
              value={sealValue}
              onChange={(e) => setSealValue(e.target.value)}
            />
          </label>
        </div>
        <div className="row-actions">
          <button
            type="button"
            onClick={() =>
              void api
                .resolve(path)
                .then(setResolved)
                .catch((e) => onError(String(e.message ?? e)))
            }
          >
            Resolve
          </button>
          <button
            type="button"
            className="primary"
            onClick={() =>
              void api
                .seal(path, sealValue)
                .then(refresh)
                .catch((e) => onError(String(e.message ?? e)))
            }
          >
            Seal base
          </button>
        </div>

        {resolved && (
          <div className="resolve-card">
            <div className="stat-row compact">
              <Stat
                label="Base"
                value={resolved.base_present ? 'есть' : 'нет'}
              />
              <Stat
                label="Overlay"
                value={
                  resolved.overlay_present
                    ? resolved.deleted
                      ? 'удалён'
                      : `#${resolved.layer_seq}`
                    : 'нет'
                }
              />
            </div>
            <pre className="code-block">
              {resolved.deleted
                ? '(удалено overlay)'
                : (resolved.payload ?? '(пусто)')}
            </pre>
          </div>
        )}
      </section>
    </div>
  )
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="stat">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  )
}
