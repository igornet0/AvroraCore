import { useCallback, useEffect, useState } from 'react'
import {
  api,
  type ChannelInfo,
  type StreamSpec,
  type TriggerDef,
} from '../api/client'

export function ChannelsPage({ onError }: { onError: (e: string | null) => void }) {
  const [channels, setChannels] = useState<ChannelInfo[]>([])
  const [streams, setStreams] = useState<StreamSpec[]>([])
  const [triggers, setTriggers] = useState<TriggerDef[]>([])
  const [chId, setChId] = useState('bus2')
  const [chKind, setChKind] = useState('internal')
  const [chBind, setChBind] = useState('127.0.0.1:19000')
  const [stId, setStId] = useState('in-demo')
  const [stDir, setStDir] = useState('inbound')
  const [stChannel, setStChannel] = useState('bus')
  const [stScope, setStScope] = useState('company')
  const [trId, setTrId] = useState('fwd-demo')
  const [trOn, setTrOn] = useState('OverlayApply')
  const [trPrefix, setTrPrefix] = useState('company')
  const [trFwd, setTrFwd] = useState('out-demo')
  const [ingestStream, setIngestStream] = useState('in-demo')
  const [ingestPath, setIngestPath] = useState('company/demo/1')
  const [ingestValue, setIngestValue] = useState('hello')
  const [busy, setBusy] = useState(false)

  const refresh = useCallback(async () => {
    onError(null)
    try {
      const [c, s, t] = await Promise.all([
        api.channels(),
        api.streams(),
        api.triggers(),
      ])
      setChannels(c)
      setStreams(s)
      setTriggers(t)
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e))
    }
  }, [onError])

  useEffect(() => {
    void refresh()
  }, [refresh])

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
            <h2>1. Каналы</h2>
            <p>Точка входа: internal bus, TCP или HTTP.</p>
          </div>
          <button type="button" onClick={() => void refresh()} disabled={busy}>
            Обновить
          </button>
        </div>

        <div className="field-grid three">
          <label>
            ID
            <input value={chId} onChange={(e) => setChId(e.target.value)} />
          </label>
          <label>
            Тип
            <select value={chKind} onChange={(e) => setChKind(e.target.value)}>
              <option value="internal">internal — в процессе</option>
              <option value="tcp">tcp — сеть</option>
              <option value="http">http — admin API</option>
            </select>
          </label>
          <label>
            Bind
            <input
              value={chBind}
              onChange={(e) => setChBind(e.target.value)}
              disabled={chKind === 'internal'}
              placeholder="127.0.0.1:port"
            />
          </label>
        </div>
        <div className="row-actions">
          <button
            type="button"
            className="primary"
            disabled={busy || !chId.trim()}
            onClick={() =>
              run(() =>
                api.createChannel({
                  id: chId,
                  kind: chKind,
                  bind: chKind === 'internal' ? undefined : chBind,
                }),
              )
            }
          >
            Создать канал
          </button>
        </div>

        {channels.length === 0 ? (
          <Empty hint="Каналов пока нет. Создайте internal bus для начала." />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Тип</th>
                <th>Адрес</th>
                <th>Статус</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {channels.map((c) => (
                <tr key={c.spec.id}>
                  <td>
                    <code>{c.spec.id}</code>
                  </td>
                  <td>
                    <span className="pill">{c.spec.kind}</span>
                  </td>
                  <td className="mono muted">{c.spec.bind ?? '—'}</td>
                  <td>
                    <span className={c.started ? 'pill ok' : 'pill'}>
                      {c.started ? 'запущен' : 'остановлен'}
                    </span>
                  </td>
                  <td className="row-actions">
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => run(() => api.startChannel(c.spec.id))}
                    >
                      Start
                    </button>
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => run(() => api.stopChannel(c.spec.id))}
                    >
                      Stop
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>2. Потоки</h2>
          <p>
            Inbound принимает данные → overlay. Outbound отдаёт результат триггеров.
          </p>
        </div>

        <div className="field-grid">
          <label>
            ID потока
            <input value={stId} onChange={(e) => setStId(e.target.value)} />
          </label>
          <label>
            Направление
            <select value={stDir} onChange={(e) => setStDir(e.target.value)}>
              <option value="inbound">inbound — вход</option>
              <option value="outbound">outbound — выход</option>
            </select>
          </label>
          <label>
            Канал
            <input
              value={stChannel}
              onChange={(e) => setStChannel(e.target.value)}
              list="channel-ids"
            />
            <datalist id="channel-ids">
              {channels.map((c) => (
                <option key={c.spec.id} value={c.spec.id} />
              ))}
            </datalist>
          </label>
          <label>
            Область путей
            <input
              value={stScope}
              onChange={(e) => setStScope(e.target.value)}
              className="mono"
              placeholder="company/…"
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
                api.createStream({
                  id: stId,
                  direction: stDir,
                  channel_id: stChannel,
                  path_scope: stScope,
                  required_perms: ['WRITE', 'READ'],
                }),
              )
            }
          >
            Создать поток
          </button>
        </div>

        {streams.length === 0 ? (
          <Empty hint="Нет потоков. Привяжите inbound к каналу bus." />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Направление</th>
                <th>Канал</th>
                <th>Scope</th>
              </tr>
            </thead>
            <tbody>
              {streams.map((s) => (
                <tr key={s.id}>
                  <td>
                    <code>{s.id}</code>
                  </td>
                  <td>
                    <span
                      className={
                        s.direction === 'inbound' ? 'pill ok' : 'pill'
                      }
                    >
                      {s.direction}
                    </span>
                  </td>
                  <td>{s.channel_id}</td>
                  <td className="mono">{s.path_scope}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <div className="callout">
          <strong>Быстрая отправка</strong>
          <p className="muted">
            Пишет в overlay выбранного inbound-потока (база не меняется).
          </p>
          <div className="field-grid three">
            <label>
              Stream
              <input
                value={ingestStream}
                onChange={(e) => setIngestStream(e.target.value)}
                list="stream-ids"
              />
              <datalist id="stream-ids">
                {streams.map((s) => (
                  <option key={s.id} value={s.id} />
                ))}
              </datalist>
            </label>
            <label>
              Путь
              <input
                value={ingestPath}
                onChange={(e) => setIngestPath(e.target.value)}
                className="mono"
              />
            </label>
            <label>
              Значение
              <input
                value={ingestValue}
                onChange={(e) => setIngestValue(e.target.value)}
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
                  api.ingest({
                    stream_id: ingestStream,
                    path: ingestPath,
                    value: ingestValue,
                  }),
                )
              }
            >
              Ingest → overlay
            </button>
          </div>
        </div>
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>3. Триггеры</h2>
          <p>При событии переслать сообщение в outbound-поток.</p>
        </div>

        <div className="field-grid">
          <label>
            ID
            <input value={trId} onChange={(e) => setTrId(e.target.value)} />
          </label>
          <label>
            Событие
            <select value={trOn} onChange={(e) => setTrOn(e.target.value)}>
              <option value="OverlayApply">OverlayApply</option>
              <option value="DataPut">DataPut</option>
              <option value="StreamMessage">StreamMessage</option>
              <option value="SubsystemTick">SubsystemTick</option>
            </select>
          </label>
          <label>
            Префикс пути
            <input
              value={trPrefix}
              onChange={(e) => setTrPrefix(e.target.value)}
              className="mono"
            />
          </label>
          <label>
            Outbound поток
            <input
              value={trFwd}
              onChange={(e) => setTrFwd(e.target.value)}
              list="stream-ids"
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
                api.createTrigger({
                  id: trId,
                  on: trOn,
                  path_prefix: trPrefix,
                  forward_stream_id: trFwd,
                }),
              )
            }
          >
            Создать триггер
          </button>
        </div>

        {triggers.length === 0 ? (
          <Empty hint="Триггеров нет. Пример: OverlayApply → out-demo." />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Событие</th>
                <th>Префикс</th>
                <th>Действие</th>
              </tr>
            </thead>
            <tbody>
              {triggers.map((t) => (
                <tr key={t.id}>
                  <td>
                    <code>{t.id}</code>
                  </td>
                  <td>
                    <span className="pill">{t.on}</span>
                  </td>
                  <td className="mono">{t.path_prefix}</td>
                  <td>
                    → <code>{t.action.stream_id ?? t.action.type}</code>
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

function Empty({ hint }: { hint: string }) {
  return <div className="empty-state">{hint}</div>
}
