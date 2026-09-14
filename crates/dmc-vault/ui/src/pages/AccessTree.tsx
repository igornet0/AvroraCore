import { useCallback, useEffect, useState } from 'react'
import { api, type TreeNode } from '../api/client'

export function AccessTree({ onError }: { onError: (msg: string | null) => void }) {
  const [nodes, setNodes] = useState<TreeNode[]>([])
  const [path, setPath] = useState('company/analytics')

  const load = useCallback(async () => {
    onError(null)
    try {
      setNodes(await api.tree())
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e))
    }
  }, [onError])

  useEffect(() => {
    void load()
  }, [load])

  async function ensure() {
    onError(null)
    try {
      await api.ensureNode(path)
      await load()
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e))
    }
  }

  async function revoke(nodePath: string) {
    onError(null)
    try {
      await api.revokeNode(nodePath)
      await load()
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e))
    }
  }

  async function rotate(nodePath: string) {
    onError(null)
    try {
      await api.rotateNode(nodePath)
      await load()
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e))
    }
  }

  return (
    <section className="panel">
      <div className="panel-head">
        <h1>Access Tree</h1>
        <p>Key-tree nodes: path KEKs, DEK generation, Active / Revoked.</p>
      </div>

      <div className="toolbar">
        <label>
          Ensure path
          <input
            value={path}
            onChange={(e) => setPath(e.target.value)}
            placeholder="company/finance"
          />
        </label>
        <button type="button" className="primary" onClick={() => void ensure()}>
          Ensure
        </button>
        <button type="button" onClick={() => void load()}>
          Refresh
        </button>
      </div>

      <table className="table">
        <thead>
          <tr>
            <th>Path</th>
            <th>State</th>
            <th>Gen</th>
            <th>Key ID</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {nodes.map((n) => (
            <tr key={n.path + n.generation} className={n.state === 'Revoked' ? 'revoked' : ''}>
              <td>
                <code>{n.path}</code>
              </td>
              <td>
                <span className={n.state === 'Active' ? 'pill ok' : 'pill bad'}>{n.state}</span>
              </td>
              <td>{n.generation}</td>
              <td className="mono muted">{n.id.slice(0, 16)}…</td>
              <td className="row-actions">
                {n.path !== '/' && n.state === 'Active' && (
                  <>
                    <button type="button" onClick={() => void rotate(n.path)}>
                      Rotate
                    </button>
                    <button
                      type="button"
                      className="danger"
                      onClick={() => void revoke(n.path)}
                    >
                      Revoke
                    </button>
                  </>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  )
}
