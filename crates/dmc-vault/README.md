# dmc-vault

Encrypted KV and hierarchical key tree. This crate is the **storage crypto layer**, not the runtime.

Access is gated by a key tree derived from a one-time master secret. Values are sealed under path DEKs. Logical roles, streams, and triggers live in `dmc-core`.

## Security model

- Master secret is generated once, shown once, and kept only in RAM.
- Disk stores salt, unlock proof, wrapped DEKs, AEAD ciphertext, sealed roles.
- Wrong master key → unlock fails; ciphertext stays unreadable.
- Path keys: `HKDF(parent, salt, path)` → child KEK; DEKs are random and envelope-wrapped.

## Quick start

```bash
# from DataModelCore/
cargo run -p dmc-core --bin dmc-vault-server
```

Open http://127.0.0.1:5173 (API: http://127.0.0.1:18787) after building the UI in `ui/`.

1. First run → **Create database** → copy the master key offline.
2. Later runs → **Unlock** with that key.
3. **Lock** in the sidebar wipes RAM keys without deleting disk data.

DB file: `data/store.dbs.json` (gitignored), via `default_db_path()`.

## Workspace

- `dmc-core` — runtime (streams, channels, roles, triggers, audit, admin HTTP)
- `dmc-vault` — encrypted KV + key tree
- `dmc-storage` — table/row paths + snapshot transactions
- `dmc-sql` — PostgreSQL-dialect SQL subset
- `dmc-pgwire` — PostgreSQL Simple Query adapter
