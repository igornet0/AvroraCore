# AvroraCore

Encrypted data store plus the **Avrora** runtime: streams, channels, roles, triggers, subsystems, and reference-level overlays.

**How DBMS + client work:** [English](../docs/en/dbms-and-client.md) · [Русский](../docs/ru/subd-i-klient.md)

```
Avrora Client (TLS 1.3 control) / Avrora UI / pgwire
        │
        ▼
dmc-core (Avrora)  streams · channels · triggers · overlay · subsystems
    │
    ├─ dmc-security  (identity · sessions · AuthZ)
    ├─ dmc-storage
    └─ dmc-vault   (immutable base ciphertext + key tree)
```

Processing writes **overlays**; base sealed data stays static. Reads resolve `overlay ∘ base`.

## Local run

```bash
make avrora          # build UI + start Avrora on :18787
make avrora-dev      # API + Vite hot reload (:5173)
make sql             # SQL adapter
make test
```

Open http://127.0.0.1:18787 (or Vite http://127.0.0.1:5173).

Env: `AVRORA_ADDR`, `AVRORA_DATA`, `AVRORA_CONTROL_ADDR` (default `0.0.0.0:7432`), `AVRORA_CONTROL_DIR`.

First-time control plane:

```bash
cargo run -p dmc-core --bin avrora -- init
# prints bootstrap token (file mode 0600)
# capability rotation defaults: enabled at 01:00 server local time
cargo run -p dmc-core --bin avrora -- auth rotation show
cargo run -p dmc-core --bin avrora -- auth rotation set --time 03:00
cargo run -p dmc-core --bin avrora -- serve
```

Daily at the configured local time, Avrora reissues live vault-user capabilities (`cap_*`, except `cap_root`) when the vault is unlocked. If the vault is locked, the run is deferred until unlock.

```bash
avrora auth rotation show
avrora auth rotation set --time 01:00 --enabled true
avrora auth rotation set --enabled false
avrora auth rotation run-now   # vault must be unlocked in this process
avrora status                  # includes capability_rotation=…
```

Then enroll from [DataClient](../DataClient/README.md) (`avrora-client bootstrap`).

### UI access (key + Google Authenticator)

1. First visit: set an **access key** (≥8 chars), scan the TOTP QR in Google Authenticator, confirm with a 6-digit code.
2. Later: enter access key + current 2FA code. A Bearer session (~12h) unlocks the management API.
3. Vault create/unlock is **not** done in the browser. Use Avrora Client (USB KeyPass + Master Password on the client host).

Auth file next to the DB: `*.ui-auth.json` (access-key hash + TOTP secret). Separate from vault crypto.

### Four secrets

| Secret | Layer | Storage |
|--------|--------|---------|
| Access Key | UI / control authentication | remembered by the operator |
| TOTP Secret | Second factor | `*.ui-auth.json` |
| Master Password | Unwraps Master Key | client only |
| Master Key (32 bytes) | Vault encryption | server RAM after unlock; Argon2id-wrapped KeyPass on **client** USB |

`Access Key ≠ Master Password ≠ Master Key`.

### USB KeyPass (client)

On `avrora-client db create` the server generates a Master Key, returns it once over mTLS, and the client wraps it with Argon2id(Master Password) → AES-256-GCM:

```
{usb}/avrora/keypass.json
{usb}/avrora/encrypted-master-key.bin
```

The server does not scan USB volumes. Unlock: client unwraps locally and sends Master Key bytes over the control plane.

### Control Plane

Length-prefixed JSON over TLS 1.3 (optional mTLS after device bootstrap). Bootstrap token is one-shot. Control sessions last 15 minutes and are bound to the enrolled device. After unlock, the same socket carries `DataMsg` (put/get, consume/ack, DLQ, lag) bound to a runtime user session. HTTP `:18787` remains UI/dev.

**Phase 1–4 complete:** encrypted journal, identity/capability, durable delivery, retry, DLQ, idempotent producer, batch ACK, backpressure v1, consumer lag, remote DataClient over mTLS.

**Phase 5:** 5.1–5.5 implemented; **5.6 design** [ADR-011](../docs/ru/adr-011-compaction.md) (storage-preserving compaction). Roadmap: compaction impl → path partitioning (5.7) → consumer groups (5.8).

## Crates

| Crate | Role |
|-------|------|
| `dmc-core` | **Avrora** runtime + admin UI |
| `dmc-security` | Identity, sessions, AuthZ (in-process; shared library) |
| `dmc-vault` | Encrypted KV + key tree |
| `dmc-storage` | Table/row layout |
| `dmc-sql` | SQL subset |
| `dmc-pgwire` | PostgreSQL wire adapter |
