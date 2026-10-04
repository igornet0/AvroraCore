# AvroraCore — аудит состояния СУБД (REPORT V1)

> Фактический аудит по исходному коду, тестам и запуску бинарников. README, ADR и комментарии
> **не** принимались как доказательство реализации — только как перечень заявлений, которые проверялись.
>
> Обозначения: **IMPLEMENTED** — есть в коде, используется в рабочем пути и покрыто тестами;
> **PARTIAL** — есть, но неполно / не подключено / не покрыто / с дефектами;
> **NOT IMPLEMENTED** — отсутствует; **NOT VERIFIED** — проверить по коду/тестам не удалось.
> «Подтверждено динамически» — воспроизведено запуском собранного бинарника в ходе аудита.

---

## 0. Краткое резюме

* Кодовая база большая: **28 крейтов + `test/`**, ~74 тыс. строк Rust в `src/`, ~48 тыс. строк тестов,
  **1 593 теста** (`#[test]`/`#[tokio::test]`), unsafe-кода нет.
* В репозитории фактически **три независимых стека хранения/доступа**, а не одна СУБД:
  1. **Avrora runtime** (`dmc-core` + `dmc-journal` + `dmc-vault` + `dmc-security`): зашифрованный
     append-only журнал (AVJL), key tree, overlays, streams/subscriptions/retry/DLQ/consumer groups,
     control plane TLS 1.3 + mTLS, HTTP admin UI. **Самая зрелая часть.**
  2. **SQL Core** (`dmc-model`, `dmc-sql-front/bind/plan/phys/exec`, `dmc-materialized`, `dmc-storage`
     row store, `dmc-server`, `dmc-ipc`, `dmc-remote`, `dmc-client`, `dmc-ops`, `dmc-backup`, `dmc-cli`):
     полноценный SQL-конвейер (parser → binder → logical plan → CBO → physical → executor, MVCC, индексы),
     **но данные хранятся на диске в открытом виде**, а «vault» в этом стеке — только логический флаг.
  3. **Legacy SQL** (`dmc-sql` на `sqlparser` + `dmc-storage::engine` поверх `EncryptedKv`) и **`dmc-pgwire`**,
     который обслуживает именно legacy-движок **без аутентификации и без TLS**.
* `cargo check` — OK; `cargo test --workspace` — **1 588 passed / 2 failed / 3 ignored**
  (2 падения — дефект тестовой обвязки: тест вызывает `target/debug/dmc`, который `cargo test` не собирает;
  после `cargo build -p dmc-cli` оба теста проходят). `cargo fmt --check` — **FAIL** (392 файла),
  `cargo clippy -D warnings` — **FAIL**.
* Найдено **3 CRITICAL** и **6 HIGH** проблем безопасности/надёжности (раздел 6), часть подтверждена динамически.
* README/ADR **рассинхронизированы** с кодом в обе стороны (раздел 4).

---

## 1. Методика и что запускалось

### 1.1 Окружение
* `cargo 1.98.0`, `rustc 1.98.0` (2026-08), macOS (Darwin 25.2.0). Docker доступен.
* Workspace **не самодостаточен**: `crates/dmc-core/Cargo.toml` зависит от
  `../../../AvroraClient/crates/{avrora-proto,avrora-client}` (соседний репозиторий). Аудит этого
  репозитория (AvroraClient) не проводился — **NOT VERIFIED**.

### 1.2 Выполненные команды и результаты

| # | Команда | Результат | Комментарий |
|---|---------|-----------|-------------|
| 1 | `cargo fmt --all -- --check` | **FAIL** (exit 1) | Diff в **392 файлах AvroraCore** (+13 файлов соседнего AvroraClient, т.к. он path-dependency) |
| 2 | `cargo check --workspace --all-targets` | **PASS** | |
| 3 | `cargo clippy --workspace --all-targets -- -D warnings` | **FAIL** (exit 101) | Остановился на первых крейтах: `dmc-vault` (4), `dmc-model` (4), `dmc-protocol` (4 ошибки). Зависимые крейты clippy не проверил |
| 4 | `cargo clippy --workspace --all-targets` (без `-D`) | **FAIL** (exit 101) | deny-by-default `clippy::approx_constant` в `crates/dmc-sql-exec/tests/phase6_runtime_data.rs:40-41`; до остановки — **≥192 уникальных warning** (59 collapsible_if, 19 unused import, 14 dead fn, 13 unused var…). Покрытие clippy неполное (dmc-core/dmc-server и др. не дошли) |
| 5 | `cargo test --workspace --no-fail-fast` | **PARTIAL** (exit 101) | 209 тестовых бинарников; **1 588 passed, 2 failed, 3 ignored**, 28 doc-test наборов |
| 6 | `cargo build -p dmc-cli --bin dmc` + `cargo test -p dmc-integration-tests --test cli_smoke` | **PASS** (2/2) | Подтверждает, что 2 падения в п.5 — только отсутствие собранного бинарника |
| 7 | `cargo test -p dmc-core dod_acceptance -- --ignored` (make test-slow) | см. §9 | slow acceptance (consumer groups, partitions) |
| 8 | `cargo test -p dmc-storage large_scan_batch -- --ignored --exact` (make test-slow) | см. §9 | |
| 9 | `docker compose config -q` (prod-like и dev) | **PASS** | Валидность compose-файлов. **Сборка образа не запускалась** → Docker-образ **NOT VERIFIED** |
| 10 | `npm run lint` (`crates/dmc-core/ui`) | PASS, 9 warnings | `react(set-state-in-effect)` |
| 11 | `npx tsc -b` (`crates/dmc-core/ui`) | PASS | Тестов UI нет |
| 12 | Ручные динамические проверки `target/debug/dmc` (§1.3) | выполнены | |

**Не запускались:** `make stress`/`stress-full` и `cargo bench` (release-сборка, длительно) — производительность **NOT VERIFIED**;
сборка Docker-образа; тесты AvroraClient; UI e2e (их нет).

### 1.3 Динамические проверки (выполнены в `$TMPDIR`, данные удалены)

| Проверка | Как | Результат |
|----------|-----|-----------|
| Шифрование данных SQL Core на диске | `dmc serve --dev` → `CREATE TABLE items…`, `INSERT … VALUES (4242424242, 77)` → поиск значения в `data/` | Значение найдено **в открытом виде** в `state_events.json`, `rows/statistics.json` и бинарно (`i64 LE`) в `rows/table_1/segments/000001.dat`. **Шифрования нет.** |
| Рестарт SQL Core в dev-режиме | остановить, `dmc serve --dev` на том же `data_root`, `query … --unlock` | `UnlockFailed`: при каждом старте создаётся **новый** vault со случайным master, а сохранённый `.dmc-dev-master.hex` не перезаписывается → после рестарта БД недоступна через API (при этом данные читаемы с диска напрямую) |
| Production-режим `dmc serve` (без `--dev`) | `status`/`sql` под `analyst` | `AuthenticationFailed: unknown credential` — пустой `AuthService`, **нет API/SQL для создания пользователей и GRANT** → production-режим неработоспособен. Unlock material при этом **записан на диск** (`.dmc-dev-master.hex`) |
| AuthZ для созданных таблиц | `CREATE TABLE canary` → `INSERT` под тем же пользователем | `AuthorizationDenied` — создатель таблицы не получает прав; `GRANT` в SQL отсутствует |
| Устойчивость IPC-сервера | 64 байта мусора в unix-socket, затем `dmc status` | После одного некорректного фрейма **сервер перестаёт принимать соединения** (процесс жив, все последующие клиенты получают ошибку) |

---

## 2. Архитектура по факту

```
                ┌───────────── Avrora (dmc-core, bin `avrora`) ──────────────┐
 AvroraClient ─TLS1.3/mTLS─► control plane (:7432, JSON frames ≤1 MiB)        │
 Browser ─────HTTP (plain)─► axum admin API + UI (:18787, CORS *)             │
                             Runtime (один tokio Mutex) → dmc-journal (AVJL,   │
                             AES-256-GCM, CRC32C, fsync) → overlay/snapshot    │
                             dmc-vault key tree (HKDF + envelope DEK)          │
                             + co-hosted SQL Core IPC (dev auth analyst/pw)    │
                └──────────────────────────────────────────────────────────────┘
 dmc CLI ─unix socket─► SQL Core (dmc-server/dmc-ipc, 1 соединение за раз)
                         → sql-front/bind/plan/phys/exec → dmc-materialized
                         → state_events.json (plaintext JSON, rewrite on append)
                         → dmc-storage row segments (plaintext, fsync per row)
                         vault = эфемерный KeyTree, к данным не применяется
 psql ──TCP (no auth, no TLS)──► dmc-pgwire (:15432) → dmc-sql (legacy, sqlparser)
                                 → dmc-storage::engine → EncryptedKv → один JSON-файл
 dmc-remote (TLS для SQL Core) — только библиотека + тесты, ни одним бинарём не поднимается
```

---

## 3. Что реализовано (по слоям)

### 3.1 Слои СУБД

| Слой | Статус | Доказательства | Ограничения |
|------|--------|----------------|-------------|
| Encrypted storage | **PARTIAL** | Avrora: `dmc-journal/src/codec.rs` (`encrypt(path_dek, payload, aad)`), `dmc-vault/src/store/mod.rs`, snapshot sealed blobs (`persist.rs`). Legacy SQL поверх `EncryptedKv` | SQL Core хранит всё в открытом виде (подтверждено динамически); `dmc-storage/src/{segment,codec}.rs` не шифруют |
| KV / data model | **IMPLEMENTED** | `EncryptedKv` put/get/delete/list с capability-проверкой; Avrora `put_data/get_data/delete_data/list_keys` (`runtime.rs:1779-1890`) | Весь KV в памяти (`HashMap`), снапшот — один JSON |
| Tables / rows | **PARTIAL** | SQL Core: `dmc-storage` RowStore/TableStore, сегменты с CRC, MVCC-версии (`row_store.rs`, `version.rs`); тесты `phase6_row_store`, `phase6_mvcc` | Plaintext; legacy `dmc-sql` — строки как KV-записи в одном JSON |
| Transactions / atomicity | **PARTIAL** | SQL Core: `ActiveTransaction` + `TxnOverlay` (`dmc-sql-exec/src/transaction.rs`), коммит одним `TransactionCommit` state event (`materializer.rs:208`), тест `phase6_atomicity` | Сервер обрабатывает одно соединение за раз → конкурентные транзакции между клиентами не проверены. **pgwire: одно состояние транзакции на всех клиентов** (`dmc-pgwire/src/server.rs`, общий `Arc<Mutex<SqlEngine>>`) — BEGIN одного клиента захватывает записи других |
| WAL / journal | **PARTIAL** | Avrora AVJL: append → `sync()` (flush+fsync) **до** apply (`runtime.rs:3162-3166`, `journal.rs:1003-1059`) — корректный write-ahead | SQL Core использует **не AVJL**, а `FileStateEventLog` (`event_log.rs:95-136`): весь лог переписывается JSON-файлом на каждый append (O(n²)), без fsync каталога. ADR-016 утверждает обратное |
| Crash recovery | **PARTIAL** | `Journal::recover` усекает CRC-невалидный хвост (`journal.rs:764-934`); crash-injection matrix (`crash_injection.rs`, `journal_crash_recovery_matrix.rs`, `phase5_group_crash_recovery.rs` 22 теста); SQL Core `recover_from_watermark`, `dmc-ops` startup recovery | Все «kill -9» — **in-process симуляция** (thread-local crash points), реальных kill/power-loss тестов нет |
| Durability | **PARTIAL** | AVJL fsync + dir fsync (`FsyncPolicy::Always`), snapshot publish `write_sync_rename` (`snapshot.rs:221`), сегменты строк fsync на каждую запись | `DbSnapshot::save` (vault/legacy SQL, base snapshot) — `fs::write`+`rename` **без fsync**; state event log без fsync каталога; UI auth file без fsync |
| Locking / concurrency | **PARTIAL** | Avrora: один `tokio::Mutex<RuntimeInner>` (сериализация всех операций); SQL Core: `Arc<Mutex<CoreServerState>>` + `accept_and_serve_one` | Фактически однопоточная СУБД; конкурентность клиентов SQL Core отсутствует (следующий клиент ждёт закрытия предыдущего соединения, read-timeout нет) |
| Indexes | **PARTIAL** | `dmc-storage/src/index/*` (BTreeMap в памяти + манифесты), index scan/lookup в executor, тесты `phase6_indexes`, `phase6_index_scan` | Не страничный B-tree; индекс целиком в RAM; legacy `dmc-sql` индексы — только метаданные (README `dmc-sql` это признаёт) |
| Query execution | **IMPLEMENTED** | `dmc-sql-exec`: scan/filter/project/join/aggregate/sort/limit/insert/update/delete; 186 тестов | Только через SQL Core IPC |
| SQL parser / planner / executor | **IMPLEMENTED (subset)** | Собственный lexer/parser (`dmc-sql-front`), binder, logical plan + optimizer + CBO + cost model (`dmc-sql-plan`, 112 тестов), physical plan | Нет `GRANT/REVOKE`, `CREATE USER`, `ALTER TABLE`, views, подзапросов (AST `Statement` — 13 вариантов). Legacy `dmc-sql` — отдельный парсер на `sqlparser` |
| PostgreSQL wire protocol | **PARTIAL** | `dmc-pgwire`: startup + Simple Query, RowDescription/DataRow/ErrorResponse; 1 тест `tests/simple_query.rs` | Нет аутентификации, TLS, Extended Query (Parse/Bind — `0A000`), лимитов размера сообщений; работает с **legacy** движком, а не с SQL Core |
| Authentication | **PARTIAL** | Avrora UI: access key + TOTP (`dmc-security/src/authentication/mod.rs`), control sessions 15 мин, device-bound; SQL Core: `AuthService` + сессии с TTL | SHA-256 без KDF; SQL Core пароли в памяти открытым текстом, не персистятся; pgwire — без аутентификации |
| Authorization | **PARTIAL** | Avrora capabilities/roles (`dmc-security/src/authorization/mod.rs`, 1096 строк), `cap.authorize` в KV; SQL Core `auth_gate.rs` + grants, тест `phase7_sql_auth`, security matrices | HTTP admin работает от `admin_session` (root) для всех данных (`routes/data.rs:38-100`); в SQL Core нет управления грантами; pgwire — без AuthZ |
| Encrypted key hierarchy | **PARTIAL** | Master → HKDF root KEK → wrapped root DEK; дочерние KEK по пути, DEK envelope (`key/tree.rs`), domain-separated journal/metadata KEK (`kdf.rs`) | Ревокация — флаг состояния (KEK детерминированно выводится из master); ротация DEK не перешифровывает существующие записи `EncryptedKv` (`get` вернёт `AeadFailed` при несовпадении generation — `store/mod.rs`); в SQL Core иерархия не используется для данных |
| Backup / restore | **IMPLEMENTED (local)** | `dmc-backup` (create/verify/restore/recover, SHA-256 манифесты, 82 теста), Avrora backup + scheduler (`dmc-core/src/backup`, `server/backup_scheduler.rs`), CLI `dmc backup …` | Только локальная ФС; SHA-256 без подписи/HMAC; бэкап SQL Core содержит plaintext; нет PITR/off-site |
| Compaction | **PARTIAL** | `dmc-journal/src/{compaction,compactor,compaction_write,compaction_publish}.rs`, crash-safe publish, GC, тесты `journal_compaction`, `phase5_compaction*` | Только API `Runtime::compact_journal/publish_compaction`; политика **по умолчанию disabled**; нет ни планировщика, ни HTTP/control-эндпоинта. Компакции/vacuum для сегментов SQL Core нет |
| Replication | **NOT IMPLEMENTED** | — | Явно вне V1 (ADR-017 §12) |
| Streaming / events | **IMPLEMENTED** | Avrora streams/subscriptions/triggers, `consume/ack/ack_batch`, `replay`, lag, backpressure | `dmc-runtime` hub streams — in-memory `broadcast(256)` (lossy), конфигурация hub не персистится; «channels» — только реестр метаданных, сокеты не открываются |
| Consumer delivery semantics | **IMPLEMENTED (at-least-once)** | Durable offsets/pending deliveries (metadata KEK), retry policy, DLQ, consumer groups (lease/rebalance/heartbeat); ~250 тестов `phase3_*`, `phase4_*`, `phase5_group_*` | Idempotent producer имеет окно: запись в журнал (fsync) → затем `persist_producer_state` (`runtime.rs:1793-1840`); крэш между ними → дубликат при повторе. Exactly-once не заявлен и не реализован |

### 3.2 Прочие подсистемы

| Подсистема | Статус | Доказательства / замечания |
|------------|--------|----------------------------|
| Avrora runtime (overlays, subsystems, triggers) | **IMPLEMENTED** / subsystems — демо-генераторы | `runtime.rs` (3583 строки), `overlay.rs`; subsystems генерируют данные по шаблону (`start_subsystem`) |
| Control Plane | **IMPLEMENTED** с дефектами | TLS 1.3 only (`control/tls.rs:109`), ALPN, Ed25519 challenge bootstrap, client cert выпускается CA, session 15 мин привязана к device, `MAX_FRAME=1 MiB` (avrora-proto). Unlock только через session-bound `UnlockBlob`, legacy plaintext unlock отклоняется (`handler.rs`, тест `phase7_legacy_unlock`) |
| TLS/mTLS (SQL Core remote) | **PARTIAL** | `dmc-remote` (rustls, TLS1.3, политика «plaintext запрещён в production», 27 тестов), но **не подключён ни к одному бинарю** |
| DataClient / SDK | **PARTIAL** | `dmc-client` (local IPC + remote TLS, 3 интеграционных теста), `dmc-tauri` — адаптер без Tauri-приложения (8 тестов). README ссылается на `../DataClient` — **каталога нет** |
| UI | **PARTIAL** | React 19 + Vite, `tsc` и `oxlint` проходят (9 warnings), **тестов нет**, отдаётся по plain HTTP |
| Docker | **PARTIAL / NOT VERIFIED** | compose валиден; образ не собирался; prod-like стек публикует pgwire без auth на `0.0.0.0` |
| Observability | **PARTIAL** | `dmc-observability`: структурные логи (tracing), metrics/audit фасады с запретом high-cardinality меток, health/readiness/diagnostics в протоколе; **нет экспортёра метрик** (Prometheus/OTel), audit SQL Core — только tracing sink |
| Ops lifecycle | **IMPLEMENTED** | `dmc-ops`: config validation, layout, startup recovery, limits, graceful shutdown, failure policy (107 тестов) |
| Migrations / versioning | **PARTIAL** | `format_version` проверки (state log, manifests), `migrate_v1_to_v2` для vault; версия workspace `0.0.2`, но **`Cargo.lock` не синхронизирован** (в lock `0.1.0`; cargo переписал lock при сборке) → `--locked` сборка упадёт |
| Error handling / fail-closed | **PARTIAL** | Vault locked → `VaultLocked`; unlock failure → generic `unlock failed`; но: `materialize_checkpoint` молча пропускает ошибки сериализации users/capabilities (`runtime.rs:3071-3080`); `dmc-pgwire` и `bootstrap_core_state_inner` используют `expect/unwrap` (panic); IPC-сервер «fail-stop» на любой ошибке соединения (§1.3). В `src/` ~622 вызова `unwrap/expect` |

---

## 4. Заявлено в README/документации, но отсутствует или работает не полностью

| Заявление (источник) | Факт |
|----------------------|------|
| «Phase 5: 5.1–5.5 implemented; 5.6 design; Roadmap: compaction impl → 5.7 → 5.8» (README) | Устарело в обратную сторону: compaction (5.6), partitioning (5.7) и consumer groups (5.8), а также Phase 6/7 (SQL Core, IPC, backup, ops) **есть в коде и в тестах** |
| ADR-011: «design only — **no production code** until sign-off» | Код компакции присутствует и протестирован (library/runtime API), но не операционализирован (нет планировщика/эндпоинта, по умолчанию выключен). Вердикт: **PARTIAL**, документ не соответствует коду |
| ADR-016/017: SQL — materialized state поверх **encrypted durable journal (AVJL)**; Key mgmt «Never persist Master Key» (ADR-022) | SQL Core использует отдельный plaintext JSON event log; master/unlock material **пишется на диск** кодом `dmc serve`/`avrora serve` |
| ADR-017: «TLS mandatory for remote; plaintext remote запрещён» | pgwire слушает plain TCP без аутентификации и в Docker публикуется на `0.0.0.0:15432`; HTTP admin — plain HTTP на `0.0.0.0:18787` |
| ADR-017 Production DoD: «remote SELECT → concurrent transaction → crash -9 → restart…» | Remote-сервер SQL Core не поднимается бинарём; конкурентных клиентов нет; реальных kill -9 тестов нет; рестарт dev-инстанса ломает unlock (§1.3) |
| README `dmc-sql`: «CREATE/DROP VIEW», «ALTER TABLE» | Есть только в legacy `dmc-sql`; в SQL Core отсутствуют |
| README: «Then enroll from DataClient (`../DataClient/README.md`)», docs по ссылкам `../docs/...` | `../DataClient` отсутствует; документация лежит **вне репозитория** (`../docs`) |
| README «Docker … Production-like (random secrets on first boot)» | pgwire master key сохраняется в `sql.master.key` в том же volume и передаётся через argv; pgwire без auth |
| `make test` = `cargo test --workspace` | Падает (2 теста) без предварительной сборки `dmc` |

---

## 5. Что протестировано и как

| Набор | Кол-во тестов (по атрибутам) | Способ | Результат |
|-------|------------------------------|--------|-----------|
| dmc-core | 315 (2 ignored) | in-process интеграционные (tokio), временные каталоги, симуляция крэшей через drop runtime | PASS |
| dmc-journal | 170 | интеграционные + crash-injection points | PASS |
| dmc-sql-exec / plan / bind / front / phys | 186 / 112 / 33 / 40 / 28 | unit + интеграционные над in-memory/файловым materializer | PASS |
| dmc-server | 152 | in-process протокол, security matrix, unlock gate/blob, zeroization, audit/metrics | PASS |
| dmc-ops | 107 | startup/shutdown/recovery/limits | PASS |
| dmc-backup | 82 | writer/verify/restore/recovery | PASS |
| dmc-materialized / dmc-storage | 70 / 67 (1 ignored) | файловые тесты | PASS |
| dmc-security / dmc-vault | 41 / 17 | unit/integration | PASS |
| dmc-remote / dmc-ipc / dmc-protocol | 27 / 20 / 34 | реальные TLS/unix-socket соединения в процессе | PASS |
| dmc-client / dmc-tauri | 3 / 8 | SDK против in-process сервера | PASS |
| dmc-pgwire | 1 | Simple Query | PASS |
| `test/` (integration) | 14 | spawn сервера в потоке + SDK; `cli_smoke` вызывает бинарь | 12 PASS, **2 FAIL** (нет бинаря) → PASS после сборки |
| UI | 0 | только `tsc` + `oxlint` | — |
| Fuzz / property / loom / CI | 0 | нет `proptest`, `cargo-fuzz`, `.github` CI | — |

Что **не** покрыто тестами: реальный kill -9/power-loss; конкурентные клиенты SQL Core; pgwire auth/TLS (отсутствуют);
сценарий «рестарт SQL Core → unlock тем же ключом»; шифрование данных SQL Core на диске; malformed-frame DoS IPC;
Docker-образ; UI.

---

## 6. Security audit

### 6.1 Найденные проблемы

| ID | Severity | Проблема | Доказательство |
|----|----------|----------|----------------|
| S-1 | **CRITICAL** | **SQL Core хранит все пользовательские данные на диске в открытом виде**; «vault unlock» — только логический гейт: `VaultRuntime::create_locked` создаёт **новый случайный KeyTree на каждый старт** и нигде его не персистит и не применяет к данным | `dmc-server/src/vault_runtime.rs:26-33`, `dmc-ops/src/startup.rs:199`, `dmc-storage/src/{segment,codec}.rs`, `dmc-materialized/src/event_log.rs`; **подтверждено динамически** (§1.3) |
| S-2 | **CRITICAL** | **pgwire без аутентификации и TLS**: `AuthenticationOk` отправляется безусловно, SSLRequest → `N`; prod-like Docker публикует порт на `0.0.0.0:15432` → полный доступ к БД по сети | `dmc-pgwire/src/server.rs` (handle_conn), `docker-compose.yml` (сервис `sql`) |
| S-3 | **CRITICAL** | **Master key хранится рядом с данными в штатных (не только dev) путях**: `dmc serve` без `--dev` пишет unlock material в `data_root/.dmc-dev-master.hex` на каждом старте; `avrora serve` пишет его в `control/dmc-data/.dmc-dev-master.hex` и **автоматически разблокирует vault** из `.avrora-dev-master.hex`, если файл есть (`try_dev_unlock` не зависит от dev-флага); entrypoint/Makefile хранят `sql.master.key` в том же volume и передают ключ через argv (`--unlock HEX`, виден в `ps`) | `dmc-cli/src/serve.rs` (ветка production), `dmc-core/src/server/mod.rs:118-260`, `docker/entrypoint.sh` (`run_sql`), `Makefile` (`sql`, `sql-bg`) |
| S-4 | **HIGH** | `avrora serve` (production-бинарь) поднимает SQL Core IPC с **жёстко зашитой учёткой `analyst/pw`** | `dmc-core/src/server/mod.rs:129` → `bootstrap_core_state_locked_with_hub` → `dev_auth_service()` (`dmc-server/src/bootstrap.rs:109-118`). Смягчение: сокет создаётся с правами 0600 |
| S-5 | **HIGH** | HTTP admin UI/API по **plain HTTP**, в Docker на `0.0.0.0`, `CORS allow_origin(Any)`; access key, TOTP и Bearer-токены передаются открыто; все операции с данными через UI выполняются от root `admin_session` (capability-модель обходится, аудит обезличен) | `dmc-core/src/server/mod.rs:88-107`, `routes/data.rs:38-100`, `Dockerfile`/compose env |
| S-6 | **HIGH** | Слабая защита учётных данных UI: `SHA-256(salt‖access_key)` без KDF; нет rate-limit/lockout ни в HTTP, ни в control plane; `AuthLogin` в control plane выполняется **до** проверки device-сертификата (оракул подбора для неаутентифицированного TLS-клиента); TOTP-код переиспользуем в окне валидности | `dmc-security/src/crypto/mod.rs:5`, `authentication/mod.rs:240-310`, `control/handler.rs` (`AuthLogin` → `auth_ok_from_token`) |
| S-7 | **HIGH** | **DoS SQL Core IPC**: любой некорректный фрейм → `accept_and_serve_one` возвращает `Err` → цикл сервера делает `break`; процесс жив, но сокет больше не обслуживается. Плюс одно соединение за раз под глобальным mutex без read-timeout — простаивающий клиент блокирует всех | `dmc-cli/src/serve.rs` (loop/break), `dmc-core/src/server/mod.rs:155-163`, `dmc-ipc/src/server.rs:38-43`; **подтверждено динамически** |
| S-8 | **HIGH** | pgwire: одно `SqlEngine` и одно состояние транзакции на все соединения (нарушение изоляции/атомарности между клиентами); длина сообщения от клиента используется для `vec![0u8; len as usize]` без верхней границы (отрицательный `i32` → огромный `usize`) | `dmc-pgwire/src/server.rs` (`Arc<Mutex<SqlEngine>>`, `payload_len`) |
| S-9 | **HIGH** | SQL Core: пароли хранятся в памяти открытым текстом, сравнение не constant-time, сообщения различают «unknown credential» и «invalid credential» (перечисление пользователей); в production нет способа создать identity/grant → эксплуатировать можно только dev-учётку | `dmc-security/src/auth/credential.rs:22-56`; подтверждено динамически |
| S-10 | MEDIUM | Ревокация ключей — только флаг `NodeState::Revoked`; KEK пути детерминированно выводится из master через HKDF → держатель master может расшифровать «отозванное»; ротация DEK в `EncryptedKv` не перешифровывает старые записи | `dmc-vault/src/key/tree.rs:247-300, 366-412`, `store/mod.rs` (`get`) |
| S-11 | MEDIUM | Bootstrap control plane: TOCTOU между `devices.is_empty()` и `insert` (два параллельных BootstrapBegin), private key клиента генерируется на сервере и передаётся по сети, enroll возможен только для первого устройства, API ревокации устройства нет | `control/handler.rs:380-480`, `control/tls.rs:117-145`, `control/devices.rs` |
| S-12 | MEDIUM | Control plane и pgwire: нет лимитов соединений и idle-timeout (неограниченный `tokio::spawn` на accept) | `control/mod.rs:101-115`, `dmc-pgwire/src/server.rs` |
| S-13 | MEDIUM | Файл UI-аутентификации (`*.ui-auth.json`, содержит TOTP secret) пишется `fs::write` с правами по umask (обычно 0644), без fsync | `dmc-security/src/credentials/mod.rs:40-49` |
| S-14 | MEDIUM | В production-бинарь вкомпилированы фиксированные dev-секреты (master keys, access key, TOTP), они же закоммичены в `docker/env.dev` | `dmc-core/src/control/dev.rs`, `dmc-security/src/dev.rs`, `docker/env.dev` |
| S-15 | MEDIUM | Master key печатается в stdout при `dmc-pgwire --create` и попадает в лог `.sql-create.log` в volume | `dmc-pgwire/src/bin/dmc-pgwire.rs`, `docker/entrypoint.sh` |
| S-16 | LOW | `AuthSession` derive(Debug) включает `unlock_binding_key` (риск утечки в логи; фактического логирования не найдено) | `dmc-security/src/auth/session.rs:17-27` |
| S-17 | LOW | Сравнение bootstrap-токена не constant-time; `ReplayGuard` для UnlockBlob растёт без ограничения | `control/handler.rs:403`, `dmc-server/src/state.rs` |

### 6.2 По пунктам чек-листа

| Пункт | Оценка |
|-------|--------|
| Cryptographic primitives | AES-256-GCM (random 96-bit nonce, AAD = путь/домен), HKDF-SHA256, Argon2id (m=19456,t=2,p=1) для KeyPass, Ed25519 для bootstrap, rustls TLS 1.3 — **адекватно**. SHA-256 для access key — **неадекватно** (S-6). Лимит числа шифрований на один DEK с random nonce не контролируется — NOT VERIFIED |
| Key lifecycle / master key handling | PARTIAL: KeyPass/UnlockBlob протокол корректен (session-bound AEAD, replay guard, legacy plaintext отклоняется), но master пишется на диск (S-3), SQL Core vault эфемерен (S-1) |
| Secret exposure / logging of secrets | PARTIAL: `KeyMaterial` Debug редактирован, `StartedCore` Debug скрывает unlock_material; но S-15, S-16, entrypoint печатает dev-креды |
| Memory handling | PARTIAL: `KeyMaterial` `ZeroizeOnDrop`, тест `phase7_zeroization`; но `UnlockMaterial` копируется (`*master.as_bytes()`), `KeyTree` клонируется (`#[derive(Clone)]`) — полнота зачистки NOT VERIFIED; mlock не используется |
| Authentication | PARTIAL (S-6, S-9, S-2) |
| Authorization / capability model | PARTIAL: модель в Avrora runtime реальная и тестируется; обход через HTTP admin (S-5); в SQL Core нет управления грантами |
| Session lifetime | IMPLEMENTED: UI ~12 ч, control 15 мин + device binding, SQL Core TTL + revoke |
| TLS/mTLS | IMPLEMENTED для control plane (TLS1.3, mTLS опционален — `allow_unauthenticated`, требование устройства проверяется на уровне приложения); SQL Core remote TLS — только библиотека; pgwire/HTTP — без TLS |
| Bootstrap flow | PARTIAL (S-11) |
| Replay protection | UnlockBlob — IMPLEMENTED (nonce per session); TOTP — отсутствует (S-6); idempotency key producer — с окном (§3.1) |
| Privilege escalation | HTTP admin = root (S-5); dev-учётка в prod (S-4); иных путей эскалации не найдено — полноты NOT VERIFIED |
| Fail-closed | PARTIAL: vault-гейт fail-closed; IPC-сервер «fail-stop» (S-7); тихий пропуск ошибок при checkpoint users/capabilities |
| Secure defaults | **FAIL**: plain HTTP/pgwire на 0.0.0.0 в Docker, CORS *, авто-unlock из файла, dev-учётка |
| File permissions | PARTIAL: master/dev файлы и IPC-сокет 0600; ui-auth.json, данные SQL Core, снапшоты — по umask |
| Error messages | PARTIAL: unlock — generic; SQL Core auth раскрывает существование пользователя (S-9); pgwire возвращает текст внутренних ошибок |
| Recovery paths | Recovery SQL Core оставляет vault Locked (по ADR-024), но см. S-1/S-3; восстановление бэкапа SQL Core — plaintext |

---

## 7. Gaps

**Архитектурные.** Три независимых стека данных (Avrora/AVJL, SQL Core, legacy SQL+pgwire) без общей модели хранения,
ключей и аутентификации; pgwire привязан к legacy-движку; SQL Core не использует ни AVJL, ни vault; workspace зависит
от соседнего репозитория; документация вне репозитория.

**Storage.** Полная перезапись JSON-файлов на каждую операцию (state event log SQL Core, `DbSnapshot` legacy/vault) —
O(размер БД) на запись; KV и индексы целиком в RAM; нет vacuum/compaction для сегментов SQL Core.

**DBMS.** Нет конкурентного обслуживания клиентов; нет управления пользователями/правами в SQL; pgwire без Extended Query;
нет ALTER/VIEW/подзапросов в SQL Core; нет репликации (вне V1).

**Reliability.** Fail-stop IPC-сервера; рестарт dev SQL Core ломает unlock; окно дубликатов idempotent producer;
отсутствие fsync для части метаданных; нет реальных crash/power-loss тестов; `Cargo.lock` рассинхронизирован; нет CI.

**Security.** См. §6 (3 CRITICAL, 6 HIGH, 6 MEDIUM, 2 LOW).

---

## 8. Оценка готовности

### 8.1 Методика
Для каждого направления зафиксирован список проверяемых критериев. Критерий = **1** (выполнен и подтверждён кодом+тестами),
**0.5** (частично / только в одном из стеков / не подключён / не проверен в реальном процессе), **0** (нет).
Readiness = сумма / число критериев. Субъективных поправок нет.

| Area | Status | Readiness | Критерии (score) | Evidence | Missing |
|------|--------|-----------|------------------|----------|---------|
| Storage | PARTIAL | **63%** (5/8) | шифрование всех данных 0.5; fsync пути записи 0.5; восстановление после torn write 0.5; append-only формат без перезаписи 0.5; checksums 1; версионирование/миграции 1; единый движок 0; тесты 1 | AVJL, RowStore, CRC, format_version | шифрование SQL Core, единый движок, отказ от full-rewrite JSON |
| Encryption/Vault | PARTIAL | **56%** (4.5/8) | AEAD 1; иерархия/envelope 1; master не персистится 0; zeroization 0.5; ротация с перешифровкой 0.5; криптографическая ревокация 0.5; покрытие всех data planes 0; тесты 1 | `dmc-vault`, `phase7_zeroization`, UnlockBlob | S-1, S-3, S-10 |
| Security/AuthZ | PARTIAL | **40%** (4/10) | стойкий хеш секретов 0; персистентное хранилище учёток SQL Core 0; MFA 0.5; защита от перебора 0; AuthZ на всех входах 0; TTL/ревокация сессий 1; TLS1.3+device binding control plane 1; secure defaults 0; управление identity/grants 0.5; security-тесты 1 | security matrices, capabilities | S-2…S-9 |
| Journal/Recovery | PARTIAL | **75%** (6/8) | WAL fsync до apply 1; CRC tail recovery 1; durable snapshot publish 1; идемпотентный replay 1; crash-safe compaction publish 1; SQL Core на том же журнале 0.5; реальные kill-9/power-loss тесты 0; dir fsync везде 0.5 | `journal.rs`, crash matrix | SQL Core на AVJL, процессные crash-тесты |
| Runtime | PARTIAL | **58%** (3.5/6) | streams/subscriptions/triggers API 1; journal-backed delivery 1; overlays 1; персистентность конфигурации hub 0; channels как реальные транспорты 0; конкурентность (не один mutex) 0.5 | `runtime.rs`, `dmc-runtime` | persist hub, реальные channels |
| Streams/Delivery | IMPLEMENTED | **86%** (6/7) | at-least-once+ack 1; retry 1; DLQ 1; idempotent producer 0.5; consumer groups 1; lag/backpressure 1; нагрузочная проверка 0.5 (stress не запускался) | ~250 тестов phase3–5 | окно дубликатов producer, perf |
| SQL (SQL Core) | PARTIAL | **70%** (7/10) | parser 1; binder 1; planner/CBO 1; executor 1; DML/DDL базовые 1; атомарный commit 1; изоляция при реальной конкуренции 0.5; GRANT/USER/ALTER 0; расширенный SQL (views, subqueries) 0.5; доступность через стандартный протокол 0 | 400+ SQL-тестов | конкурентность, DCL, pgwire→SQL Core |
| pgwire | PARTIAL | **22%** (2/9) | startup/simple query 1; extended query 0; auth 0; TLS 0; изоляция сессий 0; лимиты сообщений 0; типы/RowDescription 0.5; тесты 0.5; связь с SQL Core 0 | `dmc-pgwire` | почти всё |
| Control Plane | PARTIAL | **72%** (6.5/9) | TLS1.3 1; bootstrap challenge 1; device binding 1; session TTL 1; frame limit 1; DoS-лимиты 0; multi-device/ревокация 0; гонка bootstrap 0.5; тесты 1 | `control/*`, `control_plane.rs` | S-11, S-12 |
| Client | PARTIAL | **60%** (3/5) | SDK local IPC 1; remote TLS client 1; тесты 0.5; Tauri app 0.5; серверный remote listener 0 | `dmc-client`, `dmc-tauri` | подключить `dmc-remote` к бинарю |
| Backup/Restore | PARTIAL | **64%** (4.5/7) | create/verify/restore/recover 1; checksums 1; шифрование бэкапов 0.5; подлинность (HMAC/подпись) 0; off-site/PITR 0; планировщик 1; тесты 1 | `dmc-backup` (82 теста) | подпись, шифрование SQL Core, PITR |
| Compaction | PARTIAL | **57%** (4/7) | policy/candidate 1; artifact+publish crash-safe 1; GC 1; тесты 1; операционализация 0; соответствие документации 0; compaction SQL Core 0 | `dmc-journal/compaction*` | планировщик/эндпоинт, ADR-011 |
| Observability | PARTIAL | **70%** (3.5/5) | структурные логи 1; экспорт метрик 0; health/readiness 1; durable audit 0.5; тесты 1 | `dmc-observability`, phase7_* | Prometheus/OTel, durable audit |
| UI | PARTIAL | **50%** (2/4) | сборка/типизация 1; lint без warnings 0.5; тесты 0; TLS 0.5 (только за reverse proxy, не предусмотрен) → 2/4 | `crates/dmc-core/ui` | тесты, TLS |
| Docker/Deploy | PARTIAL | **25%** (1/4) | compose валиден 1; образ собран и проверен 0 (NOT VERIFIED); secure defaults 0; секреты вне volume 0 | compose, entrypoint | S-2, S-3, S-5 |
| Testing | PARTIAL | **25%** (2/8) | объём unit/integration 1; зелёный `cargo test` по умолчанию 0.5; fmt 0; clippy 0; процессные crash-тесты 0; stress в регулярном прогоне 0.5; fuzz/property 0; CI 0 | 1 593 теста | CI, fmt/clippy, fault injection |
| Documentation | PARTIAL | **50%** (3/6) | README 1; ADR-корпус 1; соответствие коду 0; документация в репозитории 0; runbooks/key ceremony 0.5; API docs 0.5 | README, 25 ADR в `../docs` | синхронизация, перенос в repo |

### 8.2 Overall readiness

* **Overall implementation: 80%** — доля заявленных возможностей (28 пунктов из README + ADR-002…026), присутствующих в коде
  и достижимых через API (IMPLEMENTED=1, PARTIAL=0.5): 22.5/28. Функционально проект широкий.
* **Production readiness: 27%** — 3/11 критериев: нет открытых CRITICAL (0); secure defaults (0); шифрование всех данных (0);
  долговечность подтверждена реальными крэш-тестами (0); CI + чистые fmt/clippy (0); зелёный `cargo test` (0.5);
  многоклиентская конкурентность (0); эксплуатация — health/метрики/бэкапы (0.5); документированный деплой и key ceremony (0.5);
  обновления/миграции (0.5); DoS-лимиты на всех входах (0.5).
* **Security readiness: 42%** — 8.5/20: критерии Security/AuthZ (4/10) + Encryption/Vault (4.5/8) + «нет открытых CRITICAL» (0) + «нет открытых HIGH» (0).
* **DBMS readiness: 63%** — 12/19 слоёв из §3.1 (replication исключён как вне скоупа V1; IMPLEMENTED=1, PARTIAL=0.5,
  с правилом: «1» только если слой долговечен и достижим через поддерживаемый клиентский путь).

Показатели независимы: высокий процент реализации (80%) не превращается в готовность к production (27%) из-за CRITICAL/HIGH
проблем безопасности, plaintext-хранилища SQL Core и отсутствия CI/процессных crash-тестов.

---

## 9. Результаты slow acceptance

| Тест | Команда | Результат | Время (debug) |
|------|---------|-----------|---------------|
| `group_final_dod_acceptance` (`crates/dmc-core/tests/phase5_group_final.rs`) | `cargo test -p dmc-core dod_acceptance -- --ignored` | **PASS** | 512.9 s |
| `partition_final_dod_acceptance` (`crates/dmc-core/tests/phase5_partition_final.rs`) | то же | **PASS** | 166.2 s |
| `large_scan_batch` (`crates/dmc-storage/tests/phase6_row_store.rs`) | `cargo test -p dmc-storage large_scan_batch -- --ignored --exact` | **PASS** | 61.1 s |

Итого с учётом slow-тестов: **1 591 passed**, 2 failed (обвязка `cli_smoke`, проходят после сборки `dmc`); все 3 ignored-теста запущены отдельно и прошли.
Все slow-тесты — in-process acceptance; реальные крэши процесса они не моделируют.

---

## 10. Backlog

Формат: **Problem → Why → Required work → Verification**.

### P0 — блокирует production (8)

1. **SQL Core хранит данные в открытом виде; vault эфемерен (S-1)** → нарушение базового обещания «encrypted data store», бэкапы тоже plaintext →
   персистировать KeyTree (как `DbSnapshot`), шифровать payload сегментов/event log/статистики path-DEK с AAD (table/row/version),
   либо перевести SQL Core на AVJL → тест: insert canary → grep по `data_root` и бэкапу пуст; рестарт → unlock тем же ключом → данные читаются; неверный ключ → `UnlockFailed`.
2. **Master/unlock material на диске и авто-unlock (S-3)** → компрометация диска = компрометация данных → убрать запись `.dmc-dev-master.hex`
   из non-dev путей, `try_dev_unlock` только при явном dev-флаге, pgwire ключ не через argv/файл в volume → тест: `dmc serve`/`avrora serve` без dev не создают файлов с ключом; e2e unlock только через KeyPass/UnlockBlob.
3. **pgwire без аутентификации/TLS (S-2)** → открытый доступ по сети → либо удалить из prod-compose, либо реализовать SCRAM-SHA-256 + TLS
   и переключить на SQL Core с AuthZ → тест: psql без пароля/без TLS отклоняется; AuthZ-матрица через pgwire.
4. **Dev-учётка `analyst/pw` в `avrora serve` (S-4)** → дефолтные креды в production → убрать `dev_auth_service` из non-dev пути → тест: login `analyst/pw` в prod-режиме отклоняется.
5. **Fail-stop IPC-сервера и отсутствие конкурентности (S-7)** → один клиент выводит СУБД из строя → обрабатывать ошибки соединения без выхода из цикла,
   обслуживать соединения конкурентно (thread-per-conn/async), read/idle timeout → тест: malformed frame + последующий успешный запрос; N параллельных клиентов.
6. **Нет управления пользователями/грантами в production SQL Core (S-9)** → prod-режим неработоспособен → CREATE USER/GRANT/REVOKE или control API,
   хранение хешей (Argon2id) в зашифрованном каталоге, constant-time compare, единое сообщение об ошибке → тест: создать пользователя, выдать grant, рестарт, логин.
7. **Рестарт SQL Core ломает unlock** (§1.3) → потеря доступности данных → следствие п.1; отдельный регресс-тест на рестарт → тест: `serve --dev` ×2 + query.
8. **pgwire: общая транзакция на все соединения и неограниченная аллокация (S-8)** → нарушение изоляции и DoS → сессия на соединение, верхний предел длины сообщения → тест: две сессии, BEGIN в одной не влияет на другую; сообщение с len=-1 / 2 GiB отклоняется.

### P1 — необходимо для production (10)

1. **HTTP admin по plain HTTP, CORS *, root-сессия (S-5)** → TLS (или только loopback), строгий CORS, операции от capability пользователя → тест: доступ с чужого origin, AuthZ-матрица HTTP.
2. **Слабый хеш access key, нет rate-limit, TOTP replay, AuthLogin до проверки устройства (S-6)** → Argon2id, lockout/backoff, last-used TOTP step, проверка устройства до login → тест: 10 неверных попыток → блок; повтор TOTP-кода отклоняется.
3. **Durability метаданных** → fsync файла и каталога для `DbSnapshot::save`, state event log, ui-auth, checkpoint → тест: fault-injection fs (например, через `LD_PRELOAD`/eatmydata-аналог) или проверка вызовов.
4. **Процессные crash-тесты** → добавить kill -9 реального процесса во время записи/компакции/коммита, проверку инвариантов после рестарта → прогон в CI N итераций без расхождений.
5. **Масштабируемость хранения** → заменить перезапись JSON на append-only сегменты для SQL Core event log и vault snapshot → бенчмарк: латентность записи не растёт линейно с размером БД.
6. **CI + качество** → GitHub Actions: fmt, clippy `-D warnings`, `cargo test --locked`, slow tests nightly; исправить 392 fmt-файла и clippy; синхронизировать `Cargo.lock`; вендорить/версионировать зависимость от AvroraClient → зелёный CI.
7. **Тестовая обвязка `cli_smoke`** → использовать `env!("CARGO_BIN_EXE_dmc")` (перенести тест в `dmc-cli`) или собирать бинарь → `cargo test --workspace` зелёный с нуля.
8. **Подключить `dmc-remote` к бинарю (TLS listener для SQL Core)** с конфигом сертификатов → e2e remote SELECT через TLS, plaintext в production отклоняется.
9. **Control plane: лимиты соединений/таймауты, гонка bootstrap, multi-device и ревокация (S-11, S-12)** → атомарный «consume token», генерация ключа на клиенте (CSR), API revoke device → тест: два параллельных bootstrap — успешен один.
10. **Idempotent producer: атомарность** → писать idempotency-запись в той же журнальной записи/транзакции → тест: crash между append и persist → повтор не создаёт дубликат.

### P2 — улучшения (8)

1. Криптографическая ревокация (re-wrap/перешифровка поддерева) и перешифровка при ротации DEK (S-10).
2. Экспорт метрик (Prometheus/OTel), durable audit log для SQL Core.
3. Операционализация компакции журнала: планировщик, control/HTTP-эндпоинт, обновить ADR-011; vacuum сегментов SQL Core.
4. Подпись/HMAC манифестов бэкапа, шифрование бэкапов SQL Core, off-site таргеты.
5. Убрать dev-секреты из production-бинаря (feature-флаг `dev`), master key не печатать в stdout (S-14, S-15); `AuthSession` Debug без ключа (S-16).
6. Синхронизировать README/ADR с кодом, перенести `docs/` в репозиторий, исправить ссылку на DataClient.
7. Тесты UI (unit + e2e), исправить 9 lint-warnings.
8. Сокращение `unwrap/expect` в рабочих путях (~622 в `src/`), явные ошибки вместо panic в `dmc-pgwire`/bootstrap.

### P3 — future (6)

1. Объединение стеков: один движок хранения (AVJL) для KV, событий и SQL; удаление legacy `dmc-sql`.
2. pgwire Extended Query, prepared statements, COPY, полноценный каталог `pg_catalog` для ORM.
3. Расширенный SQL: ALTER TABLE, views, subqueries, CTE, constraints/foreign keys.
4. Страничный дисковый B-tree, buffer pool, out-of-core выполнение.
5. Репликация/HA (вне V1 по ADR-017), PITR.
6. Fuzzing (протокол, парсер SQL, декодеры сегментов), property-based тесты MVCC, loom для конкурентных частей.

**Итого: P0 = 8, P1 = 10, P2 = 8, P3 = 6.**

---

## 11. Сводка проверок

| Категория | Кол-во | Список |
|-----------|--------|--------|
| Failed | 4 | `cargo fmt --check`; `cargo clippy -D warnings`; `cargo clippy` (deny-by-default); `cargo test --workspace` (2 теста `cli_smoke`, обвязка) |
| Skipped | 4 | stress (`make stress`), `cargo bench`, сборка Docker-образа, тесты AvroraClient |
| Not verified | 6 | Docker-образ; производительность; AvroraClient (path-dependency); полнота zeroization секретов; лимит шифрований на DEK; отсутствие иных путей эскалации привилегий |

> Побочный эффект аудита: `cargo` переписал `Cargo.lock` (версии `0.1.0` → `0.0.2`); файл возвращён к закоммиченному состоянию (`git checkout Cargo.lock`).
> Других изменений в репозитории, кроме этого отчёта, не вносилось.

---

Audit date: 2026-10-03
Commit: 0ec23fb0bcd8f86a3784dc2de22496057a4f0ee9
Working tree: clean (до аудита); после аудита — только новый файл `REPORT_V1.md`
Tests: PARTIAL
