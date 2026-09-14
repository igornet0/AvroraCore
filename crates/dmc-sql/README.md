# dmc-sql

SQL layer over `dmc-storage` / `dmc-vault`. Alembic and SQLx stay **outside** the engine: they are clients that send SQL over the wire.

```
SQLx / Alembic / psql
        │ SQL
        ▼
dmc-pgwire  (PostgreSQL Simple Query, default 127.0.0.1:15432)
        │  registered as a Tcp channel on dmc-core
        ▼
dmc-sql     parser → catalog → executor
        │
        ├─ catalog (sys_tables, sys_columns, system_migrations)
        ├─ key tree (CREATE/ALTER TABLE → path keys)
        └─ dmc-storage rows over EncryptedKv → atomic JSON snapshot
```

Session capabilities are bound from `dmc-core` via `SqlEngine::bind_capability`.

## Catalog ↔ key tree

`CREATE TABLE public.employees (id UUID PRIMARY KEY, name TEXT, salary DECIMAL)` creates:

- catalog rows in `system.sys_tables` / `system.sys_columns`
- key-tree nodes `db/main/schema/public/table/employees` and `.../col/{id,name,salary}`
- row payloads at `.../table/employees/row/<pk>`

## Run the SQL port

```bash
# from DataModelCore/
cargo run -p dmc-pgwire -- --data data/sql.dbs.json --listen 127.0.0.1:15432 --create
# prints a master key; later:
cargo run -p dmc-pgwire -- --data data/sql.dbs.json --unlock <hex>
```

```bash
psql "host=127.0.0.1 port=15432 user=dbs dbname=main"
```

The encrypted-KV admin UI is served by `dmc-core` (`dmc-vault-server`) on `:18787`.

## Supported SQL (this slice)

- `CREATE/DROP TABLE`, `ALTER TABLE ADD/DROP COLUMN`
- `CREATE/DROP INDEX` (metadata + key node only; no B-tree yet)
- `CREATE/DROP SCHEMA`, `CREATE/DROP VIEW` (view stores definition only)
- `INSERT`, `UPDATE`, `DELETE`, `SELECT` (single table, `=` / `AND` in `WHERE`)
- `BEGIN` / `COMMIT` / `ROLLBACK` (in-memory checkpoint + one atomic snapshot on commit)
- Types: `UUID`, `TEXT`/`VARCHAR`, `INTEGER`/`BIGINT`, `BOOLEAN`, `TIMESTAMP`, `DECIMAL`/`NUMERIC`, `BYTEA`
- Builtin `SELECT version()`, `current_database()`, `NOW()` / `CURRENT_TIMESTAMP`
- `SET ...` is a no-op (client compatibility)
