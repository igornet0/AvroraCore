import { useCallback, useEffect, useState } from 'react'
import { api, type StreamSpec, type SubsystemInfo } from '../api/client'

export function SubsystemsPage({
  onError,
}: {
  onError: (e: string | null) => void
}) {
  const [items, setItems] = useState<SubsystemInfo[]>([])
  const [streams, setStreams] = useState<StreamSpec[]>([])
  const [id, setId] = useState('sensor-a')
  const [name, setName] = useState('Sensor A')
  const [stream, setStream] = useState('in-demo')
  const [pathTpl, setPathTpl] = useState('company/demo/tick-{n}')
  const [payloadTpl, setPayloadTpl] = useState('{"n":{n},"ts":"{ts}"}')
  const [intervalMs, setIntervalMs] = useState(1000)
  const [live, setLive] = useState(true)
  const [busy, setBusy] = useState(false)

  const refresh = useCallback(async () => {
    try {
      const [subs, sts] = await Promise.all([api.subsystems(), api.streams()])
      setItems(subs)
      setStreams(sts.filter((s) => s.direction === 'inbound'))
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e))
    }
  }, [onError])

  useEffect(() => {
    void refresh()
    if (!live) return
    const t = window.setInterval(() => void refresh(), 1000)
    return () => window.clearInterval(t)
  }, [refresh, live])

  function run(action: () => Promise<unknown>) {
    setBusy(true)
    void action()
      .then(() => refresh())
      .catch((e) => onError(String(e.message ?? e)))
      .finally(() => setBusy(false))
  }

  return (
    <div className="panel-stack">
      <section className="panel">
        <div className="panel-head row">
          <div>
            <h2>Продьюсеры</h2>
            <p>
              Подсистема тикает по таймеру, пишет в inbound-поток → overlay →
              события и триггеры. База не меняется.
            </p>
          </div>
          <label className="toggle">
            <input
              type="checkbox"
              checked={live}
              onChange={(e) => setLive(e.target.checked)}
            />
            Live
          </label>
        </div>

        <div className="field-grid">
          <label>
            ID
            <input value={id} onChange={(e) => setId(e.target.value)} />
          </label>
          <label>
            Имя
            <input value={name} onChange={(e) => setName(e.target.value)} />
          </label>
          <label>
            Inbound поток
            <input
              value={stream}
              onChange={(e) => setStream(e.target.value)}
              list="inbound-streams"
            />
            <datalist id="inbound-streams">
              {streams.map((s) => (
                <option key={s.id} value={s.id} />
              ))}
            </datalist>
          </label>
          <label>
            Интервал (мс)
            <input
              type="number"
              min={50}
              value={intervalMs}
              onChange={(e) => setIntervalMs(Number(e.target.value))}
            />
          </label>
          <label className="span-2">
            Шаблон пути <span className="muted">({'{n}'}, {'{ts}'})</span>
            <input
              value={pathTpl}
              onChange={(e) => setPathTpl(e.target.value)}
              className="mono"
            />
          </label>
          <label className="span-2">
            Шаблон payload
            <input
              value={payloadTpl}
              onChange={(e) => setPayloadTpl(e.target.value)}
              className="mono"
            />
          </label>
        </div>
        <div className="row-actions">
          <button
            type="button"
            className="primary"
            disabled={busy}
            onClick={() =>
              run(() =>
                api.createSubsystem({
                  id,
                  name,
                  stream_id: stream,
                  path_template: pathTpl,
                  payload_template: payloadTpl,
                  interval_ms: intervalMs,
                }),
              )
            }
          >
            Создать подсистему
          </button>
        </div>
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>Запущенные</h2>
          <p>Start/Stop управляет фоновым циклом.</p>
        </div>

        {items.length === 0 ? (
          <div className="empty-state">
            Нет подсистем. Сначала создайте inbound-поток на странице «Потоки».
          </div>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Имя</th>
                <th>Поток</th>
                <th>Интервал</th>
                <th>Статус</th>
                <th>Тики</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {items.map((s) => (
                <tr key={s.spec.id}>
                  <td>
                    <strong>{s.spec.name}</strong>
                    <div className="mono muted">{s.spec.id}</div>
                  </td>
                  <td>
                    <code>{s.spec.stream_id}</code>
                  </td>
                  <td>{s.spec.interval_ms} ms</td>
                  <td>
                    <span className={s.running ? 'pill ok' : 'pill'}>
                      {s.running ? 'работает' : 'стоп'}
                    </span>
                  </td>
                  <td>{s.ticks}</td>
                  <td className="row-actions">
                    <button
                      type="button"
                      className="primary"
                      disabled={busy || s.running}
                      onClick={() => run(() => api.startSubsystem(s.spec.id))}
                    >
                      Start
                    </button>
                    <button
                      type="button"
                      disabled={busy || !s.running}
                      onClick={() => run(() => api.stopSubsystem(s.spec.id))}
                    >
                      Stop
                    </button>
                    <button
                      type="button"
                      className="danger"
                      disabled={busy}
                      onClick={() => run(() => api.deleteSubsystem(s.spec.id))}
                    >
                      Удалить
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  )
}
