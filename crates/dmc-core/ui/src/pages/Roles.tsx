import { useState } from 'react'
import { ALL_PERMISSIONS, api, type Role } from '../api/client'

export function Roles({
  roles,
  activeId,
  onChange,
  onActivate,
  onError,
}: {
  roles: Role[]
  activeId: string | null
  onChange: () => void
  onActivate: (id: string) => void
  onError: (msg: string | null) => void
}) {
  const [id, setId] = useState('')
  const [name, setName] = useState('')
  const [scope, setScope] = useState('company/')
  const [perms, setPerms] = useState<string[]>(['READ', 'WRITE'])

  function togglePerm(p: string) {
    setPerms((prev) => (prev.includes(p) ? prev.filter((x) => x !== p) : [...prev, p]))
  }

  async function create() {
    onError(null)
    try {
      await api.createRole({
        id: id.trim(),
        name: name.trim() || id.trim(),
        scope: scope.trim() || '/',
        permissions: perms,
      })
      setId('')
      setName('')
      onChange()
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e))
    }
  }

  async function remove(roleId: string) {
    onError(null)
    try {
      await api.deleteRole(roleId)
      onChange()
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e))
    }
  }

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Роли и права</h2>
        <p>Именованные capability. Для создания нужна GRANT на родительский scope.</p>
      </div>

      <table className="table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Имя</th>
            <th>Scope</th>
            <th>Права</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {roles.map((r) => (
            <tr key={r.id} className={r.id === activeId ? 'active-row' : ''}>
              <td>
                <code>{r.id}</code>
              </td>
              <td>{r.name}</td>
              <td>
                <code>{r.scope || '/'}</code>
              </td>
              <td className="muted">{r.permissions.join(', ')}</td>
              <td className="row-actions">
                <button type="button" onClick={() => onActivate(r.id)}>
                  Активировать
                </button>
                {r.id !== 'root' && (
                  <button
                    type="button"
                    className="danger"
                    onClick={() => void remove(r.id)}
                  >
                    Удалить
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <div className="create-box wide">
        <h3>Новая роль</h3>
        <div className="form-grid">
          <label>
            ID
            <input value={id} onChange={(e) => setId(e.target.value)} placeholder="analytics" />
          </label>
          <label>
            Имя
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Analytics" />
          </label>
          <label className="span-2">
            Scope
            <input
              value={scope}
              onChange={(e) => setScope(e.target.value)}
              placeholder="company/finance"
            />
          </label>
        </div>
        <div className="perm-grid">
          {ALL_PERMISSIONS.map((p) => (
            <label key={p} className="check">
              <input
                type="checkbox"
                checked={perms.includes(p)}
                onChange={() => togglePerm(p)}
              />
              {p}
            </label>
          ))}
        </div>
        <button type="button" className="primary" onClick={() => void create()} disabled={!id.trim()}>
          Создать роль
        </button>
      </div>
    </section>
  )
}
