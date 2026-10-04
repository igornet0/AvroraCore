# CLIENT_OWNED Identity / Authentication Contract

> **Статус документа: решения D1–D5 утверждены (§6A); реализация идёт по шагам §7.**
> Статусы системы не меняются до полного DoD: `OPERATOR_BLIND_NOT_PROVEN`,
> `REFERENCE_PATH_PROVEN = false`, production readiness `NOT_READY`.
>
> Связанный документ: [`cryptographic-ownership.md`](cryptographic-ownership.md) (§20–§21 —
> CLIENT_OWNED модель, ключи, envelopes, DMC IPC).

---

## 1. Аудит транспортов (что есть в коде сейчас)

| | DMC IPC | HTTP `:18787` | Control Plane `:7432` | pgwire `:15432` |
|---|---|---|---|---|
| Код | `dmc-server` + `dmc-ipc` | `dmc-core/src/server` (axum) | `dmc-core/src/control` | `dmc-pgwire` (отдельный бинарь) |
| Процесс / состояние | `CoreServerState` (`Mutex`, одно соединение за раз) | event-plane `Runtime` | event-plane `Runtime` | собственный `dmc_sql::SqlEngine` |
| Хранилище данных | SQL plane (`dmc-sql-exec`, `StateMaterializer`, `rows/`) | event journal (vault) | event journal (vault) | **отдельный** файл `sql.dbs.json` (legacy engine) |
| Identity store | `dmc_security::auth::AuthService` (identities, `KeyCustody`, SQL grants) | `dmc_security::AuthManager` — **один оператор** | `AuthManager` + `DeviceRegistry` (один enrolled device) | **нет** |
| Аутентификация | пароль в кадре `Authenticate` | access key (Argon2id) + TOTP → Bearer | Ed25519 challenge при bootstrap устройства, затем mTLS + access key + TOTP | **нет**: `AuthenticationOk` безусловно (`server.rs:61-66`) |
| Сессия | bearer `session_id`, TTL 12 ч, **не привязан к соединению** | Bearer token ~12 ч | control session 15 мин, привязана к device | — |
| Транспортная защита | Unix socket (права файла) | **plain HTTP**, `CorsLayer::allow_origin(Any)` | TLS 1.3 / mTLS | plain TCP |
| CLIENT_OWNED данные | ✅ (Stage 4) | ❌ нет маршрута к SQL plane | ❌ нет маршрута к SQL plane | ❌ другой engine и другое хранилище |
| Кто расшифровывает данные | CLIENT_OWNED: только клиент; прочее: сервер | сервер (`rt.admin_session()` в каждом `/data` запросе) | сервер (event plane, server-owned vault) | сервер (`SqlEngine::open(data, master)`) |

### Identity-системы (их четыре, и они не связаны)

1. **`AuthService`** (`dmc-security::auth`) — identities SQL-плоскости: `IdentityId`, имя,
   hashed password, `KeyCustody {Server, Client}`, `subject_id`, `tenant`, SQL grants.
   Единственная система, знающая CLIENT_OWNED subjects.
2. **`AuthManager`** (`dmc-security::authentication`) — один оператор UI/control plane
   (access key + TOTP). Пользователей нет.
3. **Runtime access** (`dmc-core` event plane) — пользователи/роли/capabilities `cap_*`.
   `DataRequest::OpenUserSession{user_id}` открывает сессию **любого** пользователя без
   его участия (достаточно control session оператора) — модель SERVER_OWNED по замыслу.
4. **`DeviceRegistry`** (control plane) — устройства с Ed25519 public key и mTLS
   сертификатом.

## 2. Findings (существующее состояние)

| # | Находка | Серьёзность для CLIENT_OWNED |
|---|---|---|
| F1 | Production `dmc serve` стартует с **пустым** `AuthService` (`dmc-ops/src/startup.rs`: `AuthService::new()`); в протоколе нет enrollment; identities и SQL grants не персистируются. CLIENT_OWNED identities существуют только в тестах (in-process `enroll_client_owner`). | **Блокирует production** |
| F2 | DMC IPC: аутентификация паролем; пароль не связан с CLIENT_OWNED ключами (это правильно для конфиденциальности, но значит, что AUTH-BINDING не выполняется: сессия не доказывает владение ключом K). Session id — bearer, не привязан к соединению. | Высокая |
| F3 | HTTP — консоль одного оператора: plain HTTP, CORS `*`, каждый `/data` запрос выполняется как `admin_session` event plane, сервер возвращает расшифрованные данные. Маршрутов к SQL plane / key directory нет. | Транспорт для CLIENT_OWNED отсутствует |
| F4 | Control plane: bootstrap устройства — корректный Ed25519 challenge-response (`handler.rs` `bootstrap_begin/finish`), **но** mTLS private key устройства генерирует сервер и отправляет клиенту (`tls.rs::issue_client_cert`, `client_key_pem`) → сервер может выдать себя за устройство. Bootstrap одноразовый (одно устройство). | Высокая, если использовать mTLS как идентичность CLIENT_OWNED |
| F5 | pgwire: отдельный legacy engine и хранилище; аутентификации нет. Master Key передавался **в argv** (`--unlock <hex>`, `--master-hex`) → виден в `ps`, `/proc/*/cmdline`, истории shell; `--create` печатал ключ в stdout, а `make sql-bg` и `docker/entrypoint.sh` перенаправляли stdout в лог-файлы → ключ в логах. | **Ключ: исправлено (§2.1)**; аутентификация — открыто (D4) |
| F6 | У CLIENT_OWNED subject есть только X25519 KEM-ключ (HPKE). Он не умеет подписывать; ключа аутентификации нет. | Блокирует AUTH-BINDING |
| F7 | `AuthService::disable_identity` не отзывал сессии, а `validate_session`/`principal_for` не проверяли статус identity → сессия отключённой identity продолжала выполнять SQL до 12 ч (key directory проверял статус, SQL — нет). | **Исправлено (§2.1)** |

### 2.1 Исправлено в ходе аудита (не требует архитектурного решения)

**F7 — сессии отключённой identity.**
* Threat model: уволенный/скомпрометированный пользователь с уже выданной сессией.
* Invariant: любая проверка сессии в `AuthService` (`validate_session`, `principal_for`,
  `unlock_binding_key`) отказывает, если identity не `Active`; `disable_identity` отзывает
  все её сессии.
* Implementation: `dmc-security/src/auth/service.rs` (`require_live_identity`),
  `session.rs` (`revoke_identity_sessions`).
* Test: `dmc-security/tests/ownership_security.rs::disabled_identity_sessions_stop_working_on_every_session_path`
  (падает без исправления); строки A5 в `client_owned_attack_matrix.rs` (SQL и key API →
  `SessionInvalid`).
* Residual risk: длительный SQL-запрос, начатый до отключения, завершится.

**F5 — Master Key pgwire в argv и в логах.**
* Threat model: локальный пользователь/процесс читает `ps`/`/proc/*/cmdline`; любой, кто
  читает логи или историю shell.
* Invariant: ключ принимается только из файла без доступа group/other; создаётся только
  в файл 0600 (без перезаписи); никогда не печатается; ошибки не содержат ключ.
* Implementation: `crates/dmc-pgwire/src/keyfile.rs` (`--unlock-file`,
  `--create --master-key-out`, `--create --master-hex-file`; `--unlock`/`--master-hex`
  отклоняются); `Makefile` (`sql`, `sql-bg`) и `docker/entrypoint.sh` переведены на файлы,
  выдёргивание ключа из лога удалено, env-ключ пишется под `umask 077`.
* Test: `dmc-pgwire keyfile::tests::*` (argv отклоняется без эха ключа, ровно один режим,
  0600/без перезаписи/отказ при 0644); ручная e2e-проверка бинаря.
* Residual risk: уже существующие лог-файлы (`$(SQL_LOG)`, `$AVRORA_HOME/.sql-create.log`)
  от прошлых запусков могут содержать ключ — их нужно удалить/ротировать ключ вручную.
  Аутентификации pgwire по-прежнему нет (D4).

## 3. Термины

* **subject** — `SubjectId` CLIENT_OWNED (cryptographic owner данных).
* **identity** — запись `AuthService` (`IdentityId`), `custody = Client`, `subject_id`, `tenant`.
* **auth key** `A_s^v` — ключ аутентификации subject `s` версии `v` (§6 D1).
* **KEM key** `K_s^v` — существующий X25519 HPKE ключ (envelopes).
* **key bundle** — `(s, tenant, v, A_s^v.pub, K_s^v.pub)`; его fingerprint — то, что
  закрепляют TOFU и сверяют out-of-band.
* **session** — серверное состояние после успешной аутентификации; даёт только право
  выполнять авторизованные операции, никаких ключей.

## 4. Контракт (нормативный)

### 4.1 AUTH-BINDING

**Свойство.** Если сервер создал сессию `σ` для subject `s`, то за время `[t_issue, t_expire]`
challenge'а, выданного сервером *в этом транспортном канале*, была предъявлена подпись под
этим challenge закрытым ключом, соответствующим ACTIVE auth key `A_s^v`, зарегистрированному
за `s` в key directory; и `σ` связана с `(s, tenant, v, канал)`.

**Чего аутентификация не выдаёт и не может выдать:** private key, root, recovery code,
DEK (ни в каком виде, включая envelopes «на всякий случай»), plaintext, Master Key,
`cap_root`, mTLS private key. Ответ на успешную аутентификацию содержит только
`session_id`, срок действия и номер версии ключа.

* Threat model: злоумышленник с паролем/украденным session id другого канала; сервер,
  пытающийся получить ключевой материал через протокол аутентификации.
* Invariant: `session(σ).subject = s ⇒ ∃ valid Sig(A_s^v, challenge(σ.channel))`;
  ни одно сообщение протокола аутентификации не имеет поля с private/DEK/plaintext типом.
* Test (план): подпись другим ключом / ключом RETIRED / ключом другого subject — отказ;
  исчерпывающий destructuring новых вариантов протокола (как `client_owned_type_boundary.rs`).
* Residual risk: binding «subject ↔ человек» устанавливается при enrollment (§6 D2) и против
  злонамеренного сервера защищается только out-of-band сверкой fingerprint партнёрами.

### 4.2 AUTHZ-SEPARATION

```
Identity ≠ Authentication ≠ SQL authorization ≠ Cryptographic ownership ≠ DEK possession
```

* Аутентификация устанавливает только `session → subject`.
* Авторизация (SQL grants, `ClientKeyDirectory` политика owner/grantee) решает, *можно ли
  выполнить операцию*; успешная аутентификация не добавляет прав.
* Cryptographic authority (возможность расшифровать) определяется только тем, у кого есть
  DEK — то есть клиентом, открывшим HPKE envelope своим KEM private key. Сервер не участвует
  и не может участвовать: у него нет кода и данных для открытия envelopes
  (`client_owned_type_boundary.rs`).
* Следствие: оператор/администратор любого плана (HTTP, control plane, SQL superuser) с любыми
  правами получает только ciphertext, envelopes и метаданные.
* Test (план): матрица «аутентифицирован, но не авторизован», «авторизован в SQL, но не owner/
  grantee», «администратор всех планов + Master Key» → только ciphertext.

### 4.3 Replay protection

Challenge (сервер → клиент), байтовая строка с доменом:

```
"avrora/client-auth/v1\0"
  ‖ lp(server_instance_id)      // случайный id процесса сервера (не секрет)
  ‖ lp(transport)               // "dmc-ipc" | "http" | "control" | "pgwire"
  ‖ lp(channel_binding)         // §4.3.1
  ‖ nonce[32]                   // CSPRNG
  ‖ lp(subject) ‖ lp(tenant) ‖ u32(auth_key_version)
  ‖ u64(issued_at_ms) ‖ u64(expires_at_ms)   // TTL ≤ 60 s
```

* **nonce**: одноразовый; сервер хранит выданные-непогашенные nonce до истечения TTL и
  удаляет при первом использовании (успешном или нет) → повтор = отказ.
* **expiration**: подпись после `expires_at_ms` — отказ; часы сервера — единственный источник.
* **session binding**: сессия хранит `channel_binding`; запрос с тем же `session_id` из
  другого канала — отказ (закрывает F2 bearer-replay).
* **transport binding** (§4.3.1): подпись для одного транспорта/канала не принимается другим.
* Threat model: перехват и повтор подписи; повтор между транспортами; украденный session id.
* Invariant: каждая принятая подпись соответствует ровно одному выданному, ещё не
  погашенному, неистёкшему challenge в том же канале.

#### 4.3.1 Channel binding по транспортам

| Транспорт | channel_binding |
|---|---|
| DMC IPC | `connection_id`, выделенный сервером при accept (Unix socket, локально) |
| Control plane | TLS exporter (`RFC 5705/8446`, label `"EXPORTER-avrora-client-auth"`) — требует решения D3 |
| HTTP | TLS exporter при TLS; без TLS — **нет надёжного binding** (§6 D3) |
| pgwire | зависит от D4 |

### 4.4 Key rotation

* Auth key и KEM key ротируются **вместе** одной новой версией key bundle `v+1`
  (одна HKDF-ветка из device root, как сейчас `avrora/client-kem/v1/kv{n}`).
* Continuity: новый bundle регистрируется сообщением, подписанным **старым** ACTIVE auth key
  (`v`) и **новым** (`v+1`); сервер переводит `v` в RETIRED. Это даёт серверу и партнёрам
  проверяемую цепочку `v → v+1`.
* TOFU/fingerprint: правила Stage 4 сохраняются — партнёр видит `KeyChanged` до явной сверки
  (`pin_verified`), подсовывание старой версии после принятия новой → `KeyRollback`; сокрытие
  DEK версии → `Rollback`. Цепочка подписей — дополнительная информация для клиента, **не**
  замена сверки (злонамеренный сервер может сам зарегистрировать цепочку, если владеет
  старым ключом — он им не владеет; но может подменить ключ при первом контакте).
* Аутентификация после ротации принимает только ACTIVE версию; RETIRED auth key — отказ.

### 4.5 Revocation

* **identity revoke / disable** (существующий `IdentityDisabled`): все новые операции
  отклоняются, включая аутентификацию; существующие сессии проверяются на каждом запросе.
* **grant revoke** (Stage 4 семантика, без изменений): сервер удаляет grant и envelopes;
  **DEK, уже полученные grantee, не отзываются**; новые данные защищаются ротацией DEK +
  client-side re-encryption.
* **auth key revoke** (потеря устройства): владелец (с другого устройства или по recovery
  code) регистрирует новую версию bundle; если старый ключ скомпрометирован, цепочка
  continuity (§4.4) невозможна без участия оператора — см. §6 D2 (recovery-путь).

### 4.6 Ошибки и журналирование

Ответы на неудачную аутентификацию одинаковы для «нет subject», «неверная подпись»,
«истёк challenge», «повтор» (единый код `AuthenticationFailed`), чтобы не было оракула
перечисления. В журнал/аудит пишутся subject id, транспорт, причина (enum), но не подпись,
не nonce, не challenge целиком.

## 5. Как контракт ложится на транспорты (после решений §6)

```
transport request
   → channel binding
   → challenge / signature   (AUTH-BINDING, §4.1, §4.3)
   → session(subject, tenant, key version, channel)
   → authorization            (SQL grants / directory policy, §4.2)
   → ownership check          (sealed columns, envelope owner/recipient)
   → operation (ciphertext only)
```

Один и тот же код проверки (`dmc-security`) для всех транспортов; транспортные адаптеры
только доставляют challenge/подпись и channel binding. Это и есть основа cross-transport
contract tests.

## 6. Варианты решений (утверждены — см. §6A)

### D1. Ключ аутентификации

Нужен ключ, которым клиент может доказать владение (F6).

* **A (рекомендуется).** Ed25519 auth key, выводимый из того же device root:
  HKDF info `"avrora/client-auth/v1/kv{n}"`. Регистрируется вместе с KEM key как key bundle
  v2 (новый формат с версией; v1 читается). Подпись — на клиенте (`dmc-client-crypto`),
  проверка на сервере только публичным ключом. Библиотека `ed25519-dalek 2` уже используется
  сервером (`dmc-core`, bootstrap устройства). Новый trusted party **не нужен**; новый root
  **не нужен**. Изменение: fingerprint bundle покрывает оба ключа → новые TOFU pins
  (версионировано).
* B. Challenge через существующий KEM ключ: сервер HPKE-запечатывает nonce на `K_s`, клиент
  возвращает его. Минусы: один ключ для двух целей (нарушение key separation), сервер должен
  линковать HPKE (ослабляет текущую проверку `hpke_and_x25519_are_used_only_by_the_client_crate`).
* C. Оставить пароль. AUTH-BINDING не выполняется — контракт §4.1 невозможен.

### D2. Кто связывает subject с человеком (enrollment authority)

Сейчас identities создаёт процесс сервера in-process (F1). Это неизбежно оставляет серверу
возможность завести «фальшивую Alice».

* **A (рекомендуется).** Одноразовый enrollment invite, выпускаемый оператором (аналог
  bootstrap token control plane): `invite(subject, tenant, expires)` → клиент генерирует
  root локально, предъявляет invite + key bundle + подпись challenge (proof of possession) →
  сервер связывает subject. Пароль для CLIENT_OWNED identities **не используется** (нет
  offline guessing). Защита от «фальшивой Alice» — только out-of-band сверка fingerprint
  партнёрами (как сейчас TOFU). Recovery: по recovery code (тот же root) — новые ключи той же
  ветки; при утрате recovery code — новый invite = новый subject (старые данные недоступны,
  fail closed).
* B. Внешний IdP (OIDC и т.п.). **Новый доверенный участник** — по правилам задачи не
  вводится без отдельного решения.
* C. Оператор создаёт identities с паролями (текущая модель). Не даёт AUTH-BINDING.

### D3. Единая identity-модель для HTTP и control plane

HTTP и control plane сейчас работают с другим состоянием (event-plane `Runtime`) и другой
identity-системой (один оператор). Вторая независимая модель запрещена задачей.

* **A (рекомендуется).** CLIENT_OWNED-операции HTTP/control plane — тонкие адаптеры к тому же
  `CoreServerState`/`ClientKeyDirectory`/`AuthService` (общий `Arc<Mutex<…>>` в процессе
  `dmc serve`), тот же модуль проверки подписи. Требования: control plane — channel binding
  через TLS exporter; HTTP — CLIENT_OWNED маршруты **только по TLS** (или только loopback),
  без CORS `*` для них; иначе HTTP помечается как не поддерживающий CLIENT_OWNED. mTLS-ключ
  устройства (F4) для CLIENT_OWNED аутентификации **не используется** (его знает сервер).
* B. Объявить HTTP и control plane операторскими плоскостями без CLIENT_OWNED
  (`UNSUPPORTED`), с тестом, что ни один их маршрут не достигает SQL plane / key directory.
  Минимальная поверхность атаки; cross-transport consistency = «только DMC (и pgwire) несут
  CLIENT_OWNED, остальные отказывают».
* C. Отдельные identities на транспорт — отвергается (противоречит задаче).

### D4. pgwire

pgwire — другой engine и другое хранилище (F5); стандартные PostgreSQL-клиенты поддерживают
только парольные механизмы (SCRAM-SHA-256), которые не дают AUTH-BINDING.

* **A (рекомендуется).** Перевести pgwire на тот же `CoreServerState` (dmc-sql-exec, sealed
  columns guard, `AuthService`) и реализовать собственный SASL-механизм
  (`AVRORA-ED25519-V1`: challenge §4.3, channel binding = connection id / TLS exporter).
  Стандартный `psql` такой механизм не знает — нужен клиент Avrora (или драйвер с плагином).
* B. pgwire с SCRAM-SHA-256 поверх тех же identities: аутентифицирован, но **не**
  AUTH-BINDING; CLIENT_OWNED данные остаются ciphertext (конфиденциальность не страдает), но
  P5/P10 для pgwire = `NOT_PROVEN`. Нужен пароль у CLIENT_OWNED identity (противоречит D2-A).
* C. pgwire остаётся legacy и помечается `UNSUPPORTED` для CLIENT_OWNED; отдельно чинится F5.

Независимо от выбора: F5 (Master Key в argv) — существующий security bug; исправление
(чтение из файла 0600 / stdin / KeyPass) предлагается сделать первым шагом этапа pgwire.

### D5. Сессии DMC IPC (без нового trust assumption — для подтверждения)

Привязать `session_id` к `connection_id` (закрывает bearer-replay F2) и перевести
CLIENT_OWNED identities на §4.1 после D1/D2. Парольная аутентификация остаётся для
SERVER_OWNED identities.

## 6A. Утверждённые решения и конкретный дизайн

| | Решение | Суть |
|---|---|---|
| D1 | **A** | отдельный Ed25519 authentication key; X25519/HPKE остаётся только encryption key |
| D2 | **A** | одноразовый operator-created invite + клиентский proof-of-possession |
| D3 | **A** | HTTP и control plane — thin adapters над `CoreServerState`/`AuthService`/key directory |
| D4 | **A** (цель) | pgwire на том же `CoreServerState`, аутентификация по D1 — **только после architectural gate** |
| D5 | реализовать | сессия DMC привязана к соединению |

### 6A.1 Ключи (D1)

* Оба ключа выводятся из device root через HKDF-SHA256 с **разными** info-метками
  (domain separation):
  * X25519 (encryption, существующий): `avrora/client-kem/v1` (v1), `avrora/client-kem/v1/kv{n}` —
    метка не меняется, иначе существующие identities потеряли бы ключи;
  * Ed25519 (authentication, новый): `avrora/client-owned/ed25519/v1/kv{n}` для всех n ≥ 1.
* Один ключ — одно назначение: X25519 никогда не подписывает, Ed25519 никогда не шифрует.
* Key bundle = `ClientPublicKey` с полем `auth_public_key` (32 B). Fingerprint bundle с
  auth key считается в отдельном домене `avrora/client-key-bundle/v2` и покрывает оба ключа;
  bundle без auth key (Stage 4) сохраняет прежний fingerprint и **не может аутентифицироваться**.
* Подпись — `ed25519-dalek` на клиенте; сервер проверяет `verify_strict` только публичным
  ключом. Серверные крейты не содержат `SigningKey` (проверяется тестом границы типов).

### 6A.2 Enrollment (D2)

* `IdentityInviteCreate{session_id, name, tenant, ttl_ms}` — оператор с грантом
  `CREATE` на `Resource::System`. Сервер назначает `subject = SubjectId::random()`,
  генерирует token (32 B CSPRNG), хранит только `SHA-256("avrora/invite/v1\0" ‖ token)`,
  срок, имя, tenant, subject, состояние. Token возвращается оператору **один раз**.
* `IdentityEnroll{invite_id, token, key, signature}` (без сессии): клиент сам сгенерировал root,
  подписывает Ed25519-ключом выражение
  `"avrora/client-owned/enroll/v1\0" ‖ lp(invite_id) ‖ token_hash ‖ lp(subject) ‖ lp(tenant) ‖ lp(name) ‖ bundle_fingerprint`.
  Сервер проверяет: invite существует, не использован, не истёк, token (constant-time по
  хэшу), `key.subject/tenant` = назначенные, версия 1, подпись. Затем атомарно: invite →
  `USED`, создаётся identity `custody = Client` **без пароля**, bundle регистрируется.
* Свойства: одноразовость и срок — состояние invite; привязка к subject — назначается при
  создании; повтор — invite уже `USED`; private key в invite нет; proof-of-possession сервер
  создать не может (нет private key клиента). 5 неудачных попыток → invite сжигается.
* **Разделение:** operator-controlled enrollment («этот subject выдан этому invite») ≠
  cryptographic proof of key ownership («предъявитель владеет этим ключом»). Ни то, ни другое
  не доказывает физическую личность; против подмены сервером — по-прежнему TOFU/fingerprint.

### 6A.3 Аутентификация и сессии (контракт §4, D5)

* `ClientAuthBegin{subject, tenant}` → challenge (§4.3, TTL 60 s, transport, channel =
  connection id). Для неизвестного subject выдаётся неотличимый challenge, который не может
  быть принят (нет оракула перечисления).
* `ClientAuthFinish{nonce, signature}` → nonce гасится при первой попытке; проверяются
  канал, срок, ACTIVE auth key, статус identity → сессия.
* Сессия хранит `session_id, identity_id, subject_id, channel (connection_id), issued_at,
  expires_at, state`. **Каждая** проверка сессии внутри сетевого запроса сравнивает канал
  сессии с каналом запроса (канал задаётся транспортом на время запроса; сессия, созданная в
  запросе, привязывается к его каналу). Закрытие соединения отзывает его сессии. Протокола
  rebind нет: новое соединение = новая аутентификация.
* Парольный `Authenticate` остаётся для SERVER_OWNED identities и тоже привязывается к каналу.

### 6A.4 HTTP (D3)

* Отдельный CLIENT_OWNED-адаптер: слушает **только loopback** (отказ стартовать на
  не-loopback адресе; TLS для HTTP в коде нет — не-loopback невозможен). CORS не включается;
  с admin-HTTP снимается `allow_origin(Any)`.
* HTTP не имеет соединений, поэтому вместо bearer-токена каждый запрос **подписан**
  Ed25519-ключом: `"avrora/client-owned/http-request/v1\0" ‖ lp(session_id) ‖ u64(seq) ‖
  lp(method) ‖ lp(path) ‖ SHA-256(body)`; `seq` строго возрастает (повтор = отказ). Канал HTTP-
  сессии — `http:<channel_id>`, выданный при `auth/begin`; DMC-соединение такой канал
  использовать не может, и наоборот.
* Адаптер пропускает только allowlist запросов (аутентификация, key directory, envelopes,
  grants, SQL) и вызывает тот же `handle_control`/`handle_data`.

### 6A.5 Control plane (D3)

Существующий Ed25519 device bootstrap и mTLS остаются для operator/device plane. mTLS-ключ
устройства (генерируется сервером) **не** является доказательством CLIENT_OWNED identity.
CLIENT_OWNED-запросы control plane проходят тот же контракт §6A.3 с каналом =
TLS-соединение. Оператор control plane не получает операции «открыть сессию от имени
subject». Протокол control plane (`avrora-proto`) находится в другом репозитории
(`../AvroraClient`) — способ переноса сообщений фиксируется на шаге control plane.

### 6A.6 pgwire (D4)

Миграция legacy engine только после gate (сравнение engine/хранилища/транзакций/
авторизации/CLIENT_OWNED/backup/обходов). Если gate не пройден — `BLOCKED`, без SCRAM как
компромисса и без `AuthenticationOk` без проверки.

## 7. План после решения (порядок задачи)

1. D1/D2/D5: auth key в `dmc-client-crypto`, проверка в `dmc-security`, enrollment invite,
   challenge store, сессии с channel binding, персистентность identities/grants/directory
   под `data_root/ownership` (уже входит в backup-компонент `ownership`).
2. HTTP (по D3) → атаки HTTP; control plane → атаки; pgwire (по D4, начиная с F5).
3. Cross-transport contract tests; identity backup/restore e2e; memory-exposure анализ;
   расширение attack matrix; SQL/logging/reliability аудит; документация; полный прогон.

## 8. Статус

`OPERATOR_BLIND_NOT_PROVEN`, `REFERENCE_PATH_PROVEN = false` — без изменений.
