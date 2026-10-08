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
subject».

Реализация (`dmc-core/src/control/core_tunnel.rs`): протокол `avrora-proto` (другой
репозиторий) не менялся. Туннельные кадры — тот же length-prefixed JSON, но формы
`{"CoreControl": ControlRequest}` / `{"CoreData": DataRequest}`, которая не может разобраться
как `ControlMsg` (`{"type","body"}`). Канал = `control:<random>` на TLS-соединение; при
закрытии — `close_channel` + откат осиротевшей транзакции. Пропускается только общий
allowlist (`dmc_server::transport_policy`, тот же, что у HTTP) плюс `ClientAuthBegin/Finish`
и `IdentityEnroll`. Тест: `test/tests/client_owned_control_plane.rs` (строки P1–P8:
access-key/TOTP-токен оператора, SQL-сессия оператора и event-plane runtime-сессия не
принимаются как CLIENT_OWNED; операторские запросы туннель не пропускает; D5 между
TLS-соединениями; закрытие соединения откатывает транзакцию; обычные `ControlMsg` на том же
listener работают; без core туннель отказывает) + скан расшифрованных кадров, файлов, логов.

### 6A.6 pgwire (D4)

Миграция legacy engine только после gate (сравнение engine/хранилища/транзакций/
авторизации/CLIENT_OWNED/backup/обходов). Если gate не пройден — `BLOCKED`, без SCRAM как
компромисса и без `AuthenticationOk` без проверки.

## 9. D4 gate — `PGWIRE_SQL_PLANE_AT_REST_CONFIDENTIALITY_REGRESSION` (gate пройден на reference path — §9.7; pgwire ещё не переведён)

Тест: `crates/dmc-pgwire/tests/d4_at_rest_gate.rs`. Маркер уникален на каждый прогон
(`PGWIRE_AT_REST_CONFIDENTIALITY_MARKER_<pid>_<ns>`), ищется в raw, hex/HEX и base64 при
всех трёх выравниваниях; сканер сначала доказывает, что находит маркер во всех этих
кодировках (negative control).

### 9.1 Фактический путь хранения

| | Legacy pgwire (сейчас) | SQL plane (цель D4-A) |
|---|---|---|
| Цепочка | `dmc-pgwire` → `dmc_sql::SqlEngine` → `dmc_storage::StorageEngine` → `dmc_vault::EncryptedKv` → `DbSnapshot` → **один файл** `sql.dbs.json` | `CoreServerState` → `dmc-sql-exec` → `StateMaterializer` → `rows/table_N/segments/*.dat`, `state_events.json`, `rows/statistics.json`, snapshot → backup (`journal/`, `storage/`) → restore (`live/`) |
| Ключи | Master Key → `KeyTree` → DEK на путь | шифрования at rest нет (только sealed-колонки: CLIENT_OWNED §21, SERVER_OWNED `encrypt-migrate` §16) |
| Backup | инструмента нет; бэкап = копия файла | `BackupCreate` / `restore_backup` / `recover` |

### 9.2 OLD PATH — что зашифровано и где

Значения не-ключевых колонок: `EntryRecord.blob` = AEAD под DEK пути из `KeyTree` (Master Key).
**Не** зашифровано (найдено в коде, `dmc-storage/src/paths.rs`, `dmc-sql/src/executor.rs`
`row_id_for`): путь записи — имена схемы/таблицы/колонки и **значения первичного ключа**
(row id = PK-значения через `|`). Т.е. legacy — это шифрование *значений*, а не полное
шифрование хранилища. Тест печатает, где лежит PK-маркер (`legacy baseline — primary-key
value at rest`).

### 9.3 NEW PATH — что лежит открытым и где

Наблюдение (`cargo test -p dmc-pgwire --test d4_at_rest_gate -- --include-ignored`):

```
SQL plane — primary storage/journal: rows/statistics.json, rows/table_0/segments/000001.dat, state_events.json   (raw)
SQL plane — backup:  backup-d4/journal/segments/000001.json, backup-d4/storage/tables/table_0/segments/000001.dat (raw)
SQL plane — restore: journal/segments/000001.json, storage/tables/table_0/segments/000001.dat,
                     live/rows/statistics.json, live/rows/table_0/segments/000001.dat, live/state_events.json      (raw)
```

Значение обычной `TEXT`-колонки лежит открытым текстом в сегменте строк, в журнале событий,
в **статистике планировщика** и во всех копиях бэкапа/восстановления. Legacy-путь при той же
записи маркера не оставляет нигде (`d4_reference_legacy_pgwire_encrypts_at_rest` — PASS,
реальный бинарь, перезапуск с key-файлом, файлы + копия + stdout/stderr).

### 9.4 Security impact

Любой, кто читает диск, бэкап или каталог восстановления (host admin, backup operator, вор
носителя) без Master Key, восстанавливает все значения не-sealed колонок, которые сейчас в
legacy-хранилище зашифрованы. Перевод pgwire на SQL plane **ослабил бы** конфиденциальность
at rest для существующих pgwire-данных. CLIENT_OWNED sealed-колонки не затронуты (там
ciphertext), но это другая модель (§21 cryptographic-ownership).

### 9.5 Required decision — варианты (не выбраны)

**A. Шифрование at rest внутри SQL plane** (прозрачное, ключи из vault).
* Ключи: Master Key → `KeyTree` (уже есть в `dmc-vault`) → DEK на таблицу + отдельные DEK для
  журнала, статистики, индексов, снапшота; версии DEK для ротации (rewrap без перешифровки).
* Покрыть **каждый** писатель на диск: сегменты строк, `state_events.json`/journal segments,
  materialized snapshot, `statistics.json`, index store, `sealed_columns.json` (метаданные),
  backup (`journal/`, `storage/`), restore staging и `live/`. Иначе — ровно запрещённая
  ситуация «зашифрованная таблица + открытые журнал/индекс/статистика».
* Выполнение запросов, сортировка, фильтры, индексы, транзакции работают по plaintext в
  памяти (шифрование на границе сегмент/страница/запись журнала) — семантика SQL не меняется.
* Crash recovery: AEAD на запись журнала/сегмент с привязкой (таблица, сегмент, offset) в AAD;
  повреждение = fail closed; recover проверяет теги.
* Бэкап/restore копируют ciphertext; restore требует Master Key (как legacy).
* Цена: AEAD на каждую запись/чтение сегмента; миграция существующих plaintext-данных —
  только явная команда (как `encrypt-migrate`).
* Acceptance: этот gate (все файлы, все кодировки, вкл. статистику) → PASS.

**B. Отдельный зашифрованный storage path для pgwire** (оставить legacy engine).
* Плюс: шифрование значений уже есть.
* Минусы, проверенные по коду: нет аутентификации (F5/D4), нет SQL-авторизации, нет
  CLIENT_OWNED policy/sealed columns, одна транзакция на всех клиентов (`Arc<Mutex<SqlEngine>>`),
  нет backup-инструмента, PK и имена — открытым текстом, данные отдельно от SQL plane →
  нет межтранспортной согласованности (P10) и две модели хранения.

**C. Явная sealed-модель данных** (зашифрованы только объявленные колонки).
* Уже есть: CLIENT_OWNED sealed (клиент, §21) и SERVER_OWNED `encrypt-migrate` (§16).
* Открытым остаётся всё необъявленное: PK, owner-колонка, обычные колонки, имена, статистика
  по ним, журнал с их значениями.
* Над sealed-значениями (недетерминированный AEAD) невозможны равенство, диапазоны, ORDER BY,
  агрегаты, JOIN, индексы; searchable encryption в проекте нет и не изобретается.
* Эквивалентности legacy не даёт, пока не объявлены все колонки — а это ломает запросы
  (PK объявить нельзя).

**Рекомендация:** A как условие D4-A (gate-тест — acceptance), C остаётся отдельным слоем
поверх (CLIENT_OWNED). B — только как временное состояние «pgwire не поддерживает
CLIENT_OWNED», не как цель. Решение за вами; до него pgwire не мигрирует, `AuthenticationOk`
без проверки остаётся задокументированным F5-открытым пунктом (ключ из argv уже исправлен).

### 9.6 Решение D4-A и план реализации

Решение: **A — прозрачное шифрование at rest внутри SQL plane** (B и C не реализуются).

**Контракт (acceptance):** любое значение, которое по confidentiality contract должно быть
зашифровано, не восстанавливается из persistent storage без ключа. Явно разрешённые
открытые метаданные: имена schema/table/column/index, идентификаторы (table/column id),
счётчики и размеры, digest-и манифестов бэкапа. Значения строк (включая PK), значения в
журнале событий, снапшоте, статистике (min/max/гистограммы), ключи индексов — шифруются.
Gate `d4_gate_sql_plane_at_rest_equivalence` проверяет именно это и снимается с `#[ignore]`
только когда проходит целиком.

**Находка, определяющая дизайн:** у SQL plane нет персистентной иерархии ключей —
`VaultRuntime::create_locked` вызывает `KeyTree::create_new()` при **каждом** старте, ничего
не сохраняя; Master Key каждого запуска одноразовый и ничего на диске не шифрует.

**Выбор custody (без нового trust assumption):** данные открываются только после
`VaultUnlock` клиентом — Master Key по-прежнему никогда не лежит на хосте сервера (как
сейчас). Альтернатива «ключ из файла при загрузке» (как legacy `--unlock-file`) ввела бы для
SQL plane новое допущение и не выбирается.

**Writers (инвентаризация по коду):**

| # | Writer | Файл(ы) | Содержит значения | Схема шифрования |
|---|---|---|---|---|
| W1 | `dmc-materialized/event_log.rs` | `state_events.json` | да (все DataEvent) | файл целиком, AEAD |
| W2 | `dmc-materialized/persist.rs` | materialized snapshot | да | файл целиком |
| W3 | `dmc-materialized/statistics_catalog.rs` | `rows/statistics.json` | да (min/max) | файл целиком |
| W4 | `dmc-storage/segment.rs` | `rows/table_N/segments/*.dat` (append) | да | **по записи**, AAD = таблица‖сегмент‖offset |
| W5 | `dmc-storage/index/index_store.rs` | индексные данные | да (ключи) | файл целиком |
| W6 | `dmc-storage/manifest.rs` | манифесты таблиц | метаданные | открыто (разрешено), проверяется gate |
| W7 | `dmc-materialized/protect.rs` | `sealed_columns.json`, staging | id колонок | открыто (разрешено) |
| W8 | `dmc-backup/writer.rs` | `journal/segments/*.json`, `storage/tables` | да | шифрование тем же ключом; копии — ciphertext |
| W9 | `dmc-backup/restore.rs`, `recovery.rs` | restore staging, `live/` | да | copy-as-ciphertext; `recover` требует ключи |
| W10 | `dmc-model/persist.rs`, `materializer.rs` | (проверить, используется ли SQL plane) | ? | — |

**Этапы:**
1. Персистентное хранилище ключей (`data_root/vault/keytree.json`, 0600): создаётся один раз,
   Master Key выдаётся один раз (KeyPass пишется только при создании); рестарт → тот же ключ;
   неверный ключ → `UnlockFailed`. Узлы DEK `storage/{events,snapshot,stats,rows,index}`.
2. `StorageCipher` на существующих примитивах `dmc-vault` (AES-256-GCM, без новой криптографии),
   формат с magic+версией, AAD = назначение + относительный путь (+ offset для сегментов).
3. Отложенное открытие: до `VaultUnlock` данные не читаются (каталог, health, backup — «Locked»).
4. W1–W5, W8–W9 переводятся на cipher; запись без ключа — ошибка (fail closed). Отдельного
   «plaintext production» режима нет.
5. Явная команда миграции существующих plaintext data root (не автоматическая).
6. Gate без `#[ignore]` + полный прогон.

Наблюдаемые последствия: каталог и readiness до unlock показывают «Locked»; KeyPass/Master Key
выдаётся один раз при создании хранилища; restore требует Master Key исходной установки.

**Этап 1 — выполнен.**
* `dmc-vault::key::store` (`save_key_tree` / `load_locked_key_tree`, `KeyTree::locked_from_persisted`):
  на диск пишется только соль, unlock-proof и метаданные узлов с уже обёрнутыми DEK; 0600 с
  момента создания, атомарная замена; битый файл — ошибка.
* `VaultRuntime::open_or_create` / `CoreServerState::open_persistent_with_hub`; production
  `start_core` использует `layout.vault_root()/keytree.json`. Узлы `storage/{events,snapshot,
  statistics,rows,index}` создаются вместе с хранилищем ключей. `StartedCore.unlock_material`
  стал `Option`: `Some` только при создании; `dmc serve` пишет KeyPass/dev-файл только тогда.
* Тесты: `dmc-vault key::store::tests`, `dmc-ops/tests/d4_persistent_key_store.rs` (Master Key
  один раз, рестарт без нового ключа, тот же ключ открывает, чужой — `UnlockFailed`, DEK
  стабильны, файл без секретов, битое хранилище — отказ старта без замены); существующие
  restart-тесты `dmc-ops` переведены на контракт «ключ один на установку».

Открыто после этапа 1 (закрывается этапами 3–5):
* Эфемерный конструктор `new_locked_with_hub` остаётся для dev-bootstrap/тестов/инструментов
  восстановления — до этапа 4 его нужно убрать из любых путей, пишущих данные.
* Удаление `keytree.json` при существующих данных приводит к созданию нового хранилища (пока
  данные открыты — без потери конфиденциальности); этап 4 добавит маркер зашифрованного
  хранилища и отказ старта.
* `vault/keytree.json` ещё не входит в бэкап; restore на новом хосте должен переносить его.

**Этап 2 — выполнен.** `dmc-vault::storage_cipher` (только существующий AEAD крейта:
AES-256-GCM, случайный 96-битный nonce; новой криптографии нет).

```
sealed = "AVSC" ‖ format(1) ‖ purpose ‖ key_generation(u32) ‖ nonce(12) ‖ ciphertext+tag
AAD    = "avrora/storage/v1\0" ‖ "AVSC" ‖ format ‖ purpose ‖ key_generation ‖ lp(context)
```

* Отдельный DEK на назначение (`StoragePurpose::{Events, Snapshot, Statistics, Rows, Index}` →
  узел `storage/<purpose>`); назначение ещё и в AAD. `dmc-server` берёт пути узлов из этого же
  перечисления (один источник).
* `context` привязывает шифртекст к месту: `file_context(<путь относительно data root>)` для
  файлов, `row_record_context(<таблица>, <сегмент>, <offset>)` для записей сегмента — перенос
  в другой файл/таблицу/сегмент/offset не открывается.
* `key_generation` в заголовке — для будущей ротации (сейчас открывается только текущее
  поколение). Предел: ~2^32 шифрований на ключ при случайных nonce — ключ назначения нужно
  ротировать раньше (ротация — отдельная задача, не реализована).
* `UnlockGate::storage_cipher()` — только когда vault открыт; `Debug` без ключей, ключи
  обнуляются при drop.
* Тесты: `dmc-vault storage_cipher::tests` (3: каждый однобитный flip, перенос записи,
  смена назначения, усечение, чужой ключ, неизвестный формат, legacy-plaintext, раздельные DEK),
  `dmc-ops d4_persistent_key_store::storage_cipher_is_stable_across_restarts_and_absent_while_locked`
  (запечатано до рестарта — открывается после тем же Master Key; locked — шифра нет; ключи
  другой установки не открывают).

Этап 2 ещё не шифрует ни одного файла: writers подключаются на этапах 3–4.

**Этап 3 — выполнен (отложенное открытие хранилища).**
* `dmc_server::StorageOpener` + `CoreServerState::set_storage_opener`: production `start_core`
  больше не читает данные — хранилище открывается в `apply_vault_unlock` (opener получает
  `StorageCipher`), при ошибке открытия vault снова блокируется (fail closed, ключи стёрты).
* `VaultLock`, `simulate_restart`, shutdown-wipe закрывают хранилище: открытая транзакция
  откатывается (не коммитится), `ctx` (журнал, каталог, данные) сбрасывается из памяти.
* Пока хранилище запечатано: readiness `Ready` (vault `Locked`), SQL/DDL — `VaultLocked`
  (как раньше), **CatalogList и BackupCreate — `VaultLocked`** (новое), shutdown-flush — no-op.
  CLIENT_OWNED аутентификация и key directory работают без unlock (им данные не нужны).
* При старте остаётся только структурная проверка журнала (без ключей).
* Изменённое наблюдаемое поведение отражено в тестах `dmc-ops` (startup/shutdown/limits/
  recovery): там, где тест читал журнал сразу после старта, он теперь проверяет, что хранилище
  запечатано, и сверяет журнал после unlock тем же Master Key. Проверки не ослаблены.
* Тест: `dmc-ops/tests/d4_deferred_open.rs` — locked: ничего не прочитано, Ready, SQL/каталог/
  backup → `VaultLocked`, чужой ключ не открывает; unlock открывает; lock откатывает транзакцию и
  сбрасывает данные; повторный unlock — закоммиченное на месте, незакоммиченного нет; хранилище,
  которое нельзя открыть, оставляет vault запертым.

Открыто после этапа 3: recovery из бэкапа (`recover`) по-прежнему выполняется при старте — на
этапе 4, когда данные зашифрованы, он должен переехать за unlock; dev/test bootstrap
(`bootstrap_core_state_*`) открывает хранилище сразу (эфемерный vault) — закрывается на этапе 4.

**Этап 4 — в работе (по одному writer/reader).** Каждый writer получает cipher-вариант
(`*_with` / `*_with_cipher`); старые конструкторы = `None` (plaintext, только dev/test и
pre-D4 data root). Production переключается на шифрование одним шагом в конце этапа 4 (вместе
с маркером зашифрованного хранилища, отказом старта при пропавшем `keytree.json` и `recover`
после unlock), чтобы не появлялись data root со смесью plaintext/ciphertext. Общие правила
чтения для всех writers:

| на диске | ключи есть | результат |
|---|---|---|
| sealed | да | расшифровано (чужой ключ / подмена → ошибка) |
| sealed | нет | ошибка «storage keys required» (никогда не читается как пусто) |
| plaintext | да | ошибка «explicit migration required» (неявной конвертации нет) |
| plaintext | нет | plaintext (dev/test, pre-D4) |

* **4.1 — W1 event log** (`state_events.json`): файл целиком, `Events`, контекст
  `state_events.json`; без plaintext temp-файла. Тест `dmc-materialized/tests/d4_event_log_encryption.rs`.
* **4.2 — W2 snapshot, W3 statistics**: файл целиком (`Snapshot` / `Statistics`), буферы
  plaintext обнуляются. Тест `d4_snapshot_statistics_encryption.rs`.
* **4.3 — W4 сегменты строк** (`rows/table_N/segments/*.dat`): заголовок сегмента версии 2;
  каждая запись — кадр `len u32 LE ‖ sealed(Rows, row_record_context("table_N", segment, offset))`.
  Ключи передаются `StateMaterializer` → `TableStore::{create,open}_with_cipher` →
  `RowStore` → `SegmentWriter`/чтение/сканирование; `abort_batch` переоткрывает таблицу с теми же
  ключами. Сегмент v1 с ключами и v2 без ключей — отказ (до добавления записи). При сканировании
  отрезается только неполный хвост (crash во время append); полный кадр, который не открывается,
  — ошибка `Corrupt`, файл не трогается. Тест `d4_row_segment_encryption.rs` (5): в сегментах
  нет значений (raw/hex/base64), ни один файл data root больше не содержит значения строки;
  обмен двух записей местами, повтор записи, flip бита, поддельный кадр, перенос каталога
  таблицы под другой id — отказ; привязка к таблице/сегменту/offset/назначению; без ключей и с
  чужими ключами — отказ; plaintext-сегмент с ключами — отказ без изменений; `abort_batch` и
  reopen остаются зашифрованными.
* **4.4 — W5 индексы** (`rows/index_N/index.data`: ключи = значения индексируемых колонок в
  hex): файл целиком, `Index`, контекст `index_N/index.data` (привязка к id индекса). Ключи:
  `StateMaterializer` → `IndexStore::{create,open}_with_cipher` / `build_index_from_table_with`;
  `abort_batch` переоткрывает с теми же ключами; temp-файл пишется уже зашифрованным. С ключами
  отсутствующий `index.data` при существующем манифесте — ошибка (раньше — пустой индекс, который
  молча «теряет» строки). Тест `d4_index_encryption.rs` (3): файл запечатан, значений нет
  (raw/hex/base64), ни один файл data root не содержит значений; lookup/validate после reopen;
  без ключей / чужие ключи / подмена / данные другого индекса / удаление — отказ; plaintext с
  ключами — отказ без изменений; `abort_batch` сохраняет шифрование.

* **4.5 — W8–W9 backup / restore / recover** (`dmc-backup`). Аудит до изменений: journal
  segment бэкапа — все события в JSON (значения в открытом виде); `catalog.json` — открытый;
  сегменты пересобирались `StateMaterializer::in_memory` без ключей во временный
  `staging/.rebuild_rows` (plaintext сегменты, статистика и индексы во временных файлах);
  `ownership/identities.json` (верификаторы паролей) копировался как есть; целостность —
  SHA-256 в открытом `manifest.json` (атакующий пересчитывает); recover писал `live/`
  без шифрования. Изменено:
  * Если хранилище открыто с ключами, бэкап зашифрован (`manifest.encrypted`, `backup_id`):
    journal segment (`Events`), `catalog.json`, `ownership/identities.json` (`Snapshot`)
    запечатаны с контекстом `backup/<database>/<backup_id>/<N>/<путь>`; сегменты строк
    пересобираются с ключами (`in_memory_with_cipher`), scratch-каталог — только ciphertext и
    удаляется на любом пути; `identities.json` никогда не копируется в открытом виде.
  * **Аутентифицированный манифест** `manifest.sealed` = AEAD-копия `manifest.json` (тот же
    ключ `Snapshot`, контекст привязан к database‖backup_id‖N; новой криптографии и нового
    trust assumption нет). С ключами `manifest.json` обязан совпасть с ней полностью, поэтому
    все перечисленные SHA-256 (включая сегменты, манифесты таблиц, ownership) аутентичны.
  * `verify_backup` (без ключей): структура, digests, «всё, что должно быть запечатано, —
    запечатано», наличие `manifest.sealed`; проверка содержимого помечается
    «content sealed: verified only with storage keys». `verify_backup_with(keys)`: + аутентификация
    манифеста + расшифровка в памяти и все прежние проверки содержимого. Plaintext-бэкап с
    ключами — «explicit migration required». Для plaintext-бэкапов без ключей проверки прежние.
  * Restore копирует ciphertext, ключи не использует, vault не открывает; `manifest.backup_id`
    обязан совпасть с запрошенным id. Recover (`recover_with`) требует ключи: без них
    `KeysRequired` (сервер → `VaultLocked`) до записи чего-либо; `live/` пишется зашифрованным
    (журнал, snapshot, сегменты, индексы, статистика). Сервер передаёт ключи **открытого**
    хранилища (plaintext production не меняется до финального переключателя).
  * Тест `dmc-backup/tests/d4_backup_encryption.rs` (6): нет значений и файла учётных данных
    ни в бэкапе, ни в staging/scratch/temp; restore — только ciphertext; recover без ключей /
    с чужими — отказ без `live/`; с ключами — Ready, `live/` зашифрован, открывается только с
    ключами; bit flip (digests не тронуты) — отказ уже на restore; bit flip в каждом
    запечатанном компоненте и в сегменте **с пересчитанными digests**, обмен сегментов между
    таблицами, изменение поля манифеста — restore проходит, recover отказывает; downgrade
    `encrypted:false`, удалённый `manifest.sealed` — отказ без ключей; старый бэкап на месте
    нового — отказ (identity), он же переименованный — отказ на recover, компонент старого
    бэкапа в новом — отказ; явный restore старого под своим id — легитимный откат до его N;
    другая установка — отказ; plaintext-бэкап с ключами — отказ (negative control: сканер
    находит значения в plaintext-бэкапе); незавершённый stage, усечённая копия, остатки
    прерванного restore/recover — без plaintext, не блокируют, повтор с ключами завершает.

  **Требует архитектурного решения (не закрыто локальным патчем):**
  1. **Свежесть / откат.** `manifest.sealed` доказывает целостность и принадлежность бэкапа, но
     не то, что он последний: удаление бэкапов, замена бэкапа его же более старой версией с тем
     же id (после удаления и пересоздания), откат `restores/<id>` к более раннему состоянию не
     обнаруживаются. Нужно внешнее состояние: монотонный реестр (id, N, digest
     `manifest.sealed`) в зашифрованном live-хранилище и/или подпись клиента. Это то же
     решение, что и аутентифицированные манифесты таблиц/индексов live-хранилища (4.3–4.4).
  2. **Проверка без ключей неполна по построению.** Без ключей нельзя отличить
     согласованно подделанный бэкап (пересчитанные digests) от подлинного: restore его
     скопирует, отказ произойдёт на recover. Plaintext при этом не появляется; но статус
     `valid` в `BackupVerify`/`BackupList` без открытого хранилища означает только
     «структурно цел».
  3. ~~**`vault/keytree.json` не входит в бэкап.**~~ — закрыто в D4-E (§9.12): обёрнутое
     хранилище ключей входит в зашифрованный бэкап и аутентифицируется `manifest.sealed`.
  4. В открытом `manifest.json` остаются метаданные: N, число событий/таблиц/индексов,
     id таблиц, **имена индексов** и id колонок, `next_row_id`, размеры файлов, `created_at`.
  5. Восстановленный `live/ownership/identities.json` — открытый (как у живого сервера:
     SERVER_OWNED верификаторы паролей нужны до unlock). Отдельный вопрос модели identity.
  6. ~~`start_core` вызывает `recover` без ключей при старте~~ — закрыто в 4.6.
  7. Бэкапы отдельного legacy-движка `dmc-core` (pgwire) этот шаг не затрагивает.

* **4.6 — recovery только после unlock.** Аудит: `dmc-ops::start_core` вызывал
  `recover(data_root)` при старте с запертым vault (чтение SQL-данных до unlock; для
  зашифрованной цели — отказ старта); opener открывал `live/` без ключей;
  `rebuild_materialized_from_event_log` и `StateMaterializer::in_memory` молча подставляли
  пустую статистику при нечитаемом (запечатанном) файле, а писатели без ключей могли
  **перезаписать запечатанный файл открытым** (`write_state_event_log_with(.., None)` над
  зашифрованным журналом делал это без чтения). Изменено:
  * Старт: при ожидающем восстановлении — только проверка метаданных (`manifest.json`,
    `recovery/metadata.json`, согласованный N), без SQL-данных и без ключей; ядро Ready + Locked,
    `recovery_required = true`, ничего не пишется. `on_startup = manual_fail` — как раньше.
  * `OpsStorageOpener` на `VaultUnlock`: досрочное восстановление (`recover_with` с ключами,
    если артефакт зашифрован), затем открытие `live/` с теми же ключами. Ошибка → vault снова
    заперт (fail closed), `live/` не создаётся; повторный unlock повторяет попытку.
  * Структурная проверка журнала при старте принимает запечатанный файл как непрозрачный
    (его целостность проверяет AEAD при unlock); открытый журнал по-прежнему разбирается.
  * `sealed_io::refuse_plaintext_over_sealed`: снимок, статистика и журнал без ключей не
    заменяют запечатанный файл. `rebuild_materialized_from_event_log_with` — строгий (без
    подстановки пустой статистики); прежняя функция делегирует ему без ключей.
  * Тесты: `dmc-ops/tests/d4_recovery_after_unlock.rs` (4) — зашифрованная restore-цель с
    хранилищем ключей установки: при старте ничего не восстановлено и не прочитано; неверный
    Master Key — отказ до восстановления; верный — восстановлено с ключами, `live/`
    запечатан, данные читаются; lock → restart → снова только после unlock; без своего
    хранилища ключей (чужие ключи) — отказ, vault заперт, `live/` нет; подмена — отказ при
    unlock и при повторе; битые метаданные — отказ старта без чтения данных.
    `dmc-materialized/tests/d4_keyless_writer_guard.rs` — писатели без ключей не перезаписывают
    запечатанные файлы, keyless rebuild отказывает. Пять тестов
    `phase7_ops_recovery_startup.rs` переведены на новый контракт (recovery на unlock) и
    дополнительно проверяют, что до unlock нет `live/`, `.recover/` и `recovery/state.json`.

  Открыто после 4.6: перенос `vault/keytree.json` вместе с бэкапом — ручной (см. 4.5, п. 3);
  без него зашифрованная restore-цель невосстановима. Пока ожидается восстановление, health
  показывает Ready + Locked (нет `recovery/state.json`); статус ожидания виден в
  `StartedCore.recovery_required`.

* **Финальный шаг этапа 4 — production только с шифрованием** (`dmc-ops::start_core`).
  * `OpsStorageOpener` открывает хранилище и любую restore-цель **только** с ключами.
    Профиль конфигурации на это не влияет (`dmc serve` использует профиль Development —
    исключение по профилю оставило бы production без шифрования).
  * Классификация data root при старте, без ключей и без чтения SQL-содержимого: маркер
    `encrypted-storage.json` (публичный: версия формата и схема, без ключей) → зашифрован;
    restore-цель → по `manifest.encrypted`; иначе запечатанный журнал/снимок/статистика →
    зашифрован, открытые → pre-D4 plaintext; ничего → новый.
  * plaintext-бэкап как data root → отказ старта `StartupError::Storage("… explicit migration
    required")`. pre-D4 plaintext data root — с этапа 5 стартует Locked с `migration_required`
    и открывается только после явной миграции (см. этап 5).
  * Зашифрованный data root без `vault/keytree.json` → отказ старта (`StartupError::Vault`):
    новое хранилище ключей и новый Master Key поверх данных не создаются; удаление маркера
    не помогает (распознаётся по запечатанным файлам).
  * Маркер пишется после создания хранилища ключей (сбой между ними не «замуровывает»
    пустой data root).
  * Тесты: `dmc-ops/tests/d4_production_at_rest.rs` (3) — production-путь (`start_core`,
    persistent key store, SQL через control plane, CREATE INDEX, BackupCreate/Restore/Recover,
    lock, restart): тот же сканер и то же требование, что у D4 gate, — значений нет нигде в
    data root (хранилище, журнал, бэкапы, restore + recover), negative control; удалённое
    хранилище ключей (и маркер) — отказ без пересоздания, возврат исходного — работает;
    plaintext data root — отказ без изменений. `phase7_ops_recovery_startup.rs`: фикстуры —
    зашифрованные бэкапы исходной установки с переносом её хранилища ключей; добавлен
    `plaintext_backup_is_refused_at_startup`; `invalid_checkpoint…` портит открытые метаданные
    журнала (каталог теперь запечатан). `d4_recovery_after_unlock`: restore-цель без своего
    хранилища ключей теперь отклоняется уже при старте (строже).
  * **Официальный D4 gate не изменён и остаётся `#[ignore]`.** Его прогон с `--ignored` всё
    ещё падает: harness использует dev/test bootstrap (`bootstrap_core_state_locked`:
    эфемерный vault, хранилище открывается сразу и без ключей) и keyless `recover`. Это не
    production reference path; решение для этапа 6 — перевести harness gate на `start_core`
    или перевести dev bootstrap на зашифрованное хранилище (затрагивает ~32 тестовых файла и
    `dmc serve --dev`, co-host `AVRORA_DEV=1`).

  Остаётся после этапа 4: ~~явная команда миграции~~ (выполнено, этап 5 ниже); dev/test пути без ключей (`bootstrap_core_state_*`,
  `JournalBackend::open/in_memory`, CLI `encrypt-migrate`); решения по свежести/откату
  (аутентифицированные манифесты, реестр бэкапов) и по переносу хранилища ключей.

**Этап 5 — явная миграция plaintext → encrypted — выполнен.**

Решение о канале ключей: миграция — явная операция control plane
`StorageMigrateEncrypt { session_id, blob, purge_plaintext_backups }`, а не офлайн-утилита.
Ключи хранилища приходят ровно так же, как при `VaultUnlock`: KeyPass на стороне клиента →
unlock blob, привязанный к сессии, одноразовый. Офлайн-CLI потребовал бы вводить Master
Key / пароль KeyPass на хосте сервера — новый канал ввода ключей (новое допущение доверия),
поэтому отклонён. Только DMC IPC (не входит в allowlist `transport_policy`).

* Старт на pre-D4 plaintext data root: Ready + Locked, `StartedCore.migration_required`;
  хранилище ключей создаётся (Master Key выдаётся один раз), маркер — нет. Обычный
  `VaultUnlock` такое хранилище **не открывает и не конвертирует** (vault снова заперт).
  Plaintext-бэкап в роли data root по-прежнему отклоняется при старте.
* Полномочия: `GRANT` на `system` (администратор, Administrator-A). Аудит:
  `audit.storage.migrated` / `audit.storage.migration_failed`, отказ в полномочиях —
  `audit.authorization.denied`; без путей и значений.
* Ход миграции (`dmc-ops::migrate`):
  1. проверка: только plaintext pre-D4 store; незашифрованные бэкапы/restore-цели (и непустые
     остатки staging) — отказ, если не задан `purge_plaintext_backups`;
  2. сборка в `<data_root>/.migrate-d4/new`: журнал переписывается запечатанным и
     воспроизводится (сегменты, индексы, статистика, снимок — с ключами); исходник только
     читается;
  3. проверка нового хранилища (повторное открытие с ключами): tip журнала, каталог, правила
     защищённых колонок, **каждая строка каждой таблицы**, каждый индекс (`validate`);
  4. переключение: фаза `switching` записывается, деревья `journal/` и `storage/` уходят в
     сторону, зашифрованные встают на место, пишется маркер, затем удаляются plaintext-деревья
     и (по запросу) незашифрованные бэкапы; хранилище открывается, vault разблокирован.
  Любой отказ/сбой до переключения → vault заперт, исходное хранилище нетронуто.
* Прерывание: при старте `building` (или нечитаемое состояние) — частичная сборка
  удаляется, plaintext нетронут; `switching` — доводится до конца без ключей (сборка уже
  проверена).
* Клиент/CLI: `ControlClient::storage_migrate_encrypt`, `KeyPassHandle::storage_migrate_encrypt`,
  `dmc vault migrate-storage --user … --keypass-dir … [--purge-plaintext-backups]` (пароли
  запрашиваются, не из argv).
* Тесты `dmc-ops/tests/d4_explicit_migration.rs` (5): plaintext store стартует Locked и не
  открывается обычным unlock (файлы байт-в-байт, рестарт — то же); явная миграция — значений
  нигде нет, журнал запечатан, маркер есть, данные и индекс работают, рестарт — обычное
  зашифрованное хранилище, повторная миграция — отказ; не администратор, неверный ключ,
  blob чужой сессии, повтор blob (одноразовость даже после отказа) — отказ, ничего не тронуто;
  незашифрованный бэкап без purge — отказ, с purge — удалён, значений нет; прерывание в
  `building` — сброс, в `switching` (первое дерево уже перенесено) — доведено при старте.
  `d4_production_at_rest::plaintext_data_root_requires_explicit_migration` переведён на
  контракт этапа 5 (старт Locked + отказ unlock вместо отказа старта).

Ограничения этапа 5: удаление файлов не стирает носитель (блоки ФС, снапшоты, внешние
копии старого plaintext — вне контроля инструмента); незашифрованные бэкапы не
перешифровываются, а удаляются (или блокируют миграцию); в процессе миграции весь журнал
находится в памяти сервера (как при обычном открытии).

Остаётся открытым после 4.3–4.4:
* **Целостность сегмента целиком не гарантируется**: AEAD по записи защищает
  конфиденциальность, целостность и позицию каждой записи, но не полноту/свежесть — усечение
  хвоста по границе кадра или подмена всего сегмента его более старой копией (rollback) не
  обнаруживаются (манифест таблицы не аутентифицирован). Нужен аутентифицированный манифест
  (MAC/AEAD длины и поколения сегментов) — отдельное решение, не реализовано.
* Видно без ключей: число записей (версий строк) в сегменте, длина каждой (≈ размер строки),
  порядок и момент появления (append-only: UPDATE/DELETE видны как новые кадры). Скрыты:
  значения, `row_id`, флаги (live/deleted), MVCC-последовательности.
* Манифест таблицы (`manifest.json`: id колонок, типы, размеры сегментов, `next_row_id`) — открыт
  (W6, метаданные). Манифест индекса открыт и содержит **имя индекса** (DDL-метаданные,
  выбранные пользователем) и id колонок.
* Индексные данные: rollback `index.data` к более старой запечатанной версии того же индекса
  не обнаруживается (та же проблема свежести, что и у сегментов); размер файла ≈ число/длина
  ключей.
* Backup/restore/recover шифруются, если хранилище открыто с ключами (4.5); recovery идёт
  только после unlock (4.6); production всё ещё открывает хранилище без cipher
  (финальный переключатель этапа 4), поэтому production-бэкапы пока plaintext;
  `dmc-sql-exec::MaterializedDataSource` и dev/test bootstrap используют plaintext-конструкторы.

### 9.7 Этап 6 — gate (D4-A)

* `#[ignore]` снят: `d4_gate_sql_plane_at_rest_equivalence` выполняется в каждом прогоне.
* Harness SQL plane переведён на **production reference path**: `dmc_ops::start_core`
  (хранилище ключей, открытие на `VaultUnlock`, только с шифрованием) вместо dev/test
  bootstrap; восстановление — `recover_with(ключи установки)`, как production `BackupRecover`
  (keyless `recover` по построению отказывает зашифрованному бэкапу). Пользователь получает те
  же права, что dev bootstrap выдавал неявно (`CONNECT`, `USAGE`). **Сканер, маркер, negative
  control и все три утверждения не изменены** (diff ограничен harness).
* Результат: SQL plane — хранилище/журнал `[]`, бэкап `[]`, restore + recover `[]`.
  Legacy reference — значения не-ключевых колонок не найдены, **значение первичного ключа
  найдено** (`sql.dbs.json`, raw) — как и раньше.
* Дополнительно (production-путь): `dmc-ops/tests/d4_production_at_rest.rs`
  `primary_key_values_are_not_plaintext_at_rest` — TEXT PRIMARY KEY (row ids, PK-индекс) в
  SQL plane не виден ни в хранилище, ни в бэкапе: здесь SQL plane строже legacy.
* Что gate **не** доказывает: метаданные (длины/число записей, имена индексов, манифесты),
  свежесть/откат, конфиденциальность в памяти процесса и на других транспортах; dev/test
  bootstrap (`bootstrap_core_state_*`) по-прежнему пишет без шифрования — не reference path.
  Статусы `OPERATOR_BLIND_NOT_PROVEN`, `REFERENCE_PATH_PROVEN = false`, `NOT_READY` не меняются.

### 9.8 D4 — production pgwire переведён на SQL plane

**Аудит legacy pgwire (до):** `AuthenticationOk` без проверки; SQL-авторизации нет; одна
транзакция и одно хранилище на всех клиентов (`Arc<Mutex<SqlEngine>>`); Master Key в
серверном key-файле; отдельное хранилище `sql.dbs.json` с открытыми значениями PK;
production-развёртывание (Docker `sql`) — `dmc-pgwire` на `0.0.0.0:15432`.

**Архитектура (по контракту D4-A, §6A.6):** `dmc_pgwire::sql_plane` — тонкий адаптер
PostgreSQL wire protocol над тем же `CoreServerState`, что DMC IPC.
* Единственные операции адаптера: `handle_control(ClientAuthBegin | ClientAuthFinish)` и
  `handle_data(ExecuteSql)` на канале `pgwire:<random>` своего TCP-соединения. Никаких
  других маршрутов (vault, backup, privilege, identity, runtime — только DMC IPC); session id
  от клиента не принимается никогда; на диск адаптер ничего не пишет.
* Аутентификация: только SASL `AVRORA-ED25519-V1` — client-first `{subject, tenant}` → challenge
  D1 (привязан к каналу соединения, одноразовый, TTL 60 s) → подпись Ed25519 → `ClientAuthFinish`
  → SASLFinal → `AuthenticationOk`. Любой иной механизм (SCRAM), пароль, запрос до
  аутентификации — `28000` и закрытие соединения; единый ответ (нет оракула). Стандартный
  `psql` механизм не знает — нужен клиент Avrora (решение D4-A).
* Всё остальное — в диспетчере, без копий логики: глобальный vault-гейт (`55000`), гранты
  identity (`42501`), владение транзакцией F8 (`40001`), sealed-column политика CLIENT_OWNED,
  D5-привязка сессии к каналу; закрытие соединения → сессии закрыты, транзакция откатана.
* Только loopback (в адаптере нет TLS; relay challenge исключён лишь там, где между клиентом и
  сервером никого нет — то же правило, что у HTTP, D3); лимиты: допуск соединений
  (`max_connections`), размер сообщения, таймаут аутентификации.
* Хост: `dmc serve --pgwire 127.0.0.1:15432` (тот же `Arc<Mutex<CoreServerState>>`, что DMC IPC;
  адрес проверяется до любого действия с диском; с `--dev` — отказ: dev bootstrap не
  reference path). Production-бинарь `dmc-pgwire` legacy engine больше не запускает (exit 2,
  ничего не создаёт, ничего не слушает). Legacy engine — только `dmc_pgwire::legacy` и бинарь
  `dmc-pgwire-legacy-reference` (baseline D4 gate; Dockerfile/Makefile его не собирают).
* `SqlCell.text` — каноническое текстовое представление значения (DMC-поле `value` прежнее).

**Тесты:** `dmc-pgwire/tests/sql_plane_pgwire.rs` (10) — SELECT/INSERT/UPDATE/DELETE, CREATE/DROP
TABLE, CREATE/DROP INDEX (поиск по индексу), PK (`23000`), NULL, ошибки (`42601`, неизвестная
таблица, пустой запрос), ALTER TABLE и FOREIGN KEY — чистый отказ; BEGIN/ROLLBACK/COMMIT,
ReadyForQuery `T/I`, изоляция (чужая открытая транзакция → `40001`, её данные не видны),
обрыв соединения в транзакции → откат; гранты per identity (`42501` для INSERT/UPDATE/DELETE/
DROP/CREATE без прав, без грантов — `42501`); только `AVRORA-ED25519-V1`: SCRAM, пароль, запрос
до аутентификации, чужой ключ для subject, подпись другого пользователя, подделанная подпись,
relay подписи между соединениями, повтор, неизвестный subject — `28000`; vault заперт → `55000`;
extended protocol → `0A000`; огромное/битое сообщение → закрыто только это соединение; один
и тот же store с DMC IPC (запись pgwire видна DMC и наоборот), журнал запечатан, маркер есть,
`sql.dbs.json` нет; sealed-column политика CLIENT_OWNED действует и для pgwire; составной
запрос `a; b` отклоняется целиком (`42601`, ничего не выполнено); не-loopback — отказ;
production-бинарь не запускает legacy. `dmc-cli/tests/serve_pgwire_cli.rs` (3, реальный `dmc
serve`): не-loopback и `--dev` — отказ до записи на диск; production предлагает только
`AVRORA-ED25519-V1`, пароль → `28000`, data root зашифрован. D4 gate:
`d4_gate_production_pgwire_at_rest_equivalence` — маркер (и как значение, и как PRIMARY KEY)
через production pgwire; хранилище/журнал/бэкап/restore+recover и **все файлы прогона** — `[]`.

**Известные ограничения (функциональные, не безопасность):**
* SQL plane не поддерживает `ALTER TABLE` в SQL (legacy поддерживал — регрессия для
  pgwire-клиентов; колонки меняются только DDL-операциями DMC IPC) и FOREIGN KEY (нет и в legacy).
* `SELECT` внутри открытой транзакции не видит её собственные незакоммиченные записи —
  существующее ограничение SQL plane на всех транспортах (движок даёт read-your-writes только
  через свой API; SQL-путь читает зафиксированное состояние).
* Имена колонок в результатах — `col_N`; теги CommandComplete без числа строк для DML;
  все колонки — text; только Simple Query; один оператор на запрос.
* Docker `sql`-режим и `make sql` запускают `dmc-pgwire`, который теперь отказывает
  (fail-closed): сетевой pgwire (не loopback) требует TLS + channel binding по TLS exporter —
  архитектурное решение, не реализовано.

### 9.9 D4-B — защищённые live-манифесты

**Аудит (до):** `manifest.json` таблицы — открытый, неаутентифицированный, `RowStore::open`
доверял его списку сегментов; усечение сегмента по границе кадра или откат сегмента к старому
префиксу не обнаруживались (AEAD защищает каждую запись, но не полноту); `index.data`
запечатан, но без поколения — откат к старой запечатанной копии не обнаруживался, а replay
журнала индекс **не чинит** (для уже существующих строк поддержка индекса пропускается →
поиск молча теряет строки); путь открытия восстановленного дерева (`open_recovered`) вообще
ничего не перепроверял.

**Инварианты (с ключами хранилища):**
1. Доверенный манифест таблицы — только запечатанный `manifest.sealed` (ключ `Rows`, контекст
   `file\0table_N/manifest.json`); отсутствует при наличии открытой копии, подделан, от другой
   таблицы, под чужими ключами → отказ. Открытая копия — только метаданные для keyless-читателей.
2. Каждый опубликованный сегмент существует и не короче опубликованного размера (сегменты
   append-only) → иначе отказ «missing or shorter than published».
3. Поколение индекса и его id — внутри запечатанного `index.data` (данные и поколение
   неразделимы); открытая копия манифеста индекса не доверяется.
4. Запечатанный snapshot хранит поколение каждой таблицы и индекса; при открытии (до replay и
   в `open_recovered`) хранилище старше записанного или отсутствующее → отказ «rollback».
   Исключение — таблицы/индексы, удалённые событиями журнала после snapshot.
5. Окна сбоя не считаются атакой: запечатанный манифест пишется раньше открытого (устаревшая
   открытая копия безвредна); snapshot сохраняется после публикации хранилищ (хранилище новее
   snapshot — допустимо).

**Без нового trust assumption:** те же ключи хранилища и тот же AEAD. Бэкап включает
`manifest.sealed` таблиц в аутентифицированный список файлов; recovery сохраняет snapshot с
поколениями.

**Тесты:** `dmc-materialized/tests/d4_protected_manifests.rs` (6) — открытая копия манифеста
подделана → без последствий; `manifest.sealed` удалён / изменён бит / от другой таблицы → отказ;
сегмент усечён по границе кадра / удалён → отказ (оба пути открытия); откат таблицы (согласованные
старые манифест + сегменты) и откат индекса → отказ «rollback» (оба пути); удалённый каталог
таблицы → отказ; поколение индекса берётся из запечатанных данных; окна сбоя (устаревшая
открытая копия, snapshot старше хранилищ, DROP TABLE/INDEX после snapshot) → открывается;
keyless-режим без изменений. `dmc-ops/tests/d4_production_at_rest.rs`
`rolled_back_table_keeps_the_vault_locked` — через `start_core`: откат таблицы → unlock
отказывает, vault заперт.

**Не закрыто D4-B (→ D4-D):** откат **всего** data root целиком (журнал + snapshot + хранилища
согласованно старые) неотличим изнутри сервера — нужно внешнее монотонное поколение. Данные,
дописанные после последней публикации манифеста (прерванный batch), по-прежнему читаются при
сканировании (поведение до D4-B; журнал — источник истины).

### 9.10 D4-C — реестр бэкапов

**Аудит (до), где бэкап считался доверенным:** (1) `create_and_publish` — бэкап «существует»,
просто лежа в `backups/backup-<id>`, ничего не записано вне `backups/`; (2) `restore_backup`
(операция `BackupRestore`) — проверка без ключей (открытые digests, наличие `manifest.sealed`,
`backup_id`): старая версия / другая копия с тем же id проходила, удаление не отличалось от
«не найден»; (3) `recover_with` (`BackupRecover`, восстановление при старте) — принимала
**любой** подлинный бэкап этой установки, включая старую версию того же id; (4)
`verify_backup_with` / `list_backups` — «valid» = согласованный; (5) старт с data root =
restore-цель — ничем не связан с проверенным бэкапом.

**Инвариант:** для каждого бэкапа, созданного с ключами хранилища, в зашифрованном
live-хранилище есть авторитетная запись
`backup_id → { generation, sha256(manifest.sealed), N }`; production restore/recover
принимает **только** ровно этот артефакт этой установки, любое расхождение → отказ.

* Реестр: `<storage root>/backup_registry.sealed` (live-хранилище, **не** рядом с бэкапами),
  `sealed_io` + ключ `Snapshot`, атомарная запись (во временном файле — только ciphertext).
  Нет файла → пустой реестр (ничего не принимается); изменён / пустой / открытый / под чужими
  ключами → ошибка.
* Generation реестра записывается и **внутрь** аутентифицированного манифеста бэкапа
  (`registry_generation`): бэкап и запись называют друг друга.
* Порядок создания: данные → аутентифицированный манифест (stage) → публикация → запись в
  реестре. Бэкап без записи (kill после публикации) не принимается.
* `restore_backup_registered` (операция `BackupRestore` с открытым зашифрованным хранилищем):
  только зашифрованный, проверка **с ключами** (аутентификация манифеста и содержимого),
  совпадение с реестром (id, generation, N, хэш `manifest.sealed`), затем копия ciphertext и
  запечатанная **restore-аттестация** (`recovery/registry-attestation.sealed`, контекст привязан к
  backup id) — до того, как цель станет видимой. Хранилище заперто → `VaultLocked`.
* `recover_registered` (операция `BackupRecover` и восстановление при старте): цель обязана иметь
  действительную аттестацию ровно для своего `manifest.sealed`; операция сервера дополнительно
  сверяется с живым реестром (бэкап с тех пор заменён → отказ). Затем `recover_with`.
* Библиотечные `restore_backup` / `recover_with` остаются строительными блоками (dev/test); ни
  одна production-точка входа с ключами их напрямую не вызывает.

**Тесты:** `dmc-backup/tests/d4_backup_registry.rs` (8) — штатный путь (реестр в live-хранилище,
запечатан, называет бэкап; restore → аттестация → recover Ready); `manifest.sealed` изменён /
заменён другим бэкапом / удалён → отказ, цель не тронута; бэкап удалён → отказ (реестр помнит, что
он был); старая версия на месте новой с тем же id → отказ; бэкап другой установки (и в её каталоге
бэкапов) → отказ; реестр изменён / чужой / пустой / удалён / старее бэкапа → отказ;
незарегистрированный бэкап → отказ; kill между этапами (stage без аутентифицированного манифеста,
полный stage без публикации, публикация без записи, оборванная запись реестра) → отказ, полный
прогон → принимается; recovery без аттестации / с чужой / изменённой аттестацией / после замены
бэкапа в реестре → отказ, `live/` не создаётся. Production-фикстуры
(`phase7_ops_recovery_startup.rs`, `d4_recovery_after_unlock.rs`) переведены на
зарегистрированный restore — нерегистрированный теперь отклоняется при unlock (проверено).

**Не закрыто D4-C:**
* Откат реестра **вместе** с бэкапом к старой согласованной паре — это откат live-хранилища
  целиком (→ D4-D, внешнее монотонное поколение).
* Восстановление при старте (data root = restore-цель) проверяет аттестацию, но не живой реестр
  исходной установки (он недоступен): устаревшая аттестация + соответствующая ей старая копия
  бэкапа принимаются (→ D4-D/E).
* `BackupVerify` / `BackupList` по-прежнему сообщают структурную/аутентифицированную
  валидность, без статуса регистрации.
* Нужен ли явный протокол удаления бэкапа (сейчас операции удаления нет).

### 9.11 D4-D — защита от отката всего data root (вариант 1: якорь клиента)

**Новое допущение доверия (утверждено, вариант 1):** свежесть хранилища удостоверяет
**клиент, выполняющий unlock**: он хранит наибольшее поколение, которое видел для этой
установки, и сервер не открывает хранилище старше. Сервер сам себе в этом не доверяет —
изнутри откат согласованной копии data root неотличим.

* Поколение = аутентифицированный tip журнала (растёт с каждой зафиксированной записью;
  откат data root целиком → более старый запечатанный журнал → меньший tip). Возвращается в
  `VaultUnlock` и `VaultStatus` (`generation`; 0, пока хранилище запечатано).
* Unlock blob v2: AEAD запечатывает `material ‖ min_generation`; версия в AAD — якорь нельзя ни
  изменить, ни снять подменой версии. v1 (старые клиенты) принимается без якоря.
* Проверка на сервере сразу после открытия хранилища при unlock (и при явной миграции):
  `generation < min_generation` → хранилище закрывается, vault снова заперт,
  `StorageRollbackDetected`; ничего не записывается.
* Клиент (`KeyPassHandle`): якорь — файл `anchor` рядом с KeyPass; после unlock только
  повышается; повреждённый файл — ошибка (не 0). Явное принятие отката (восстановление старого
  бэкапа): `dmc vault unlock --keypass-dir … --accept-rollback` — unlock без якоря, якорь
  сбрасывается на открытое поколение, предупреждение.
* Потеря состояния клиента = нет якоря = нет проверки для этого unlock (не ложный отказ).
  Отдельной серверной операции «переустановить поколение» нет — это был бы новый путь обхода.

**Тесты:** `dmc-ops/tests/d4_anti_rollback.rs` (5, через `start_core`): поколение растёт с
записями и возвращается; якорь = текущему — принимается, больше — `StorageRollbackDetected`, vault
заперт, хранилище закрыто; **откат всего data root** (копия корня вместе с хранилищем ключей) →
отказ, журнал не изменён, явное принятие → открывается старое состояние; якорь изменён в
blob / версия понижена до v1 → отказ; v1 без якоря → принимается (задокументированное
ограничение); старый бэкап, восстановленный как data root, → отказ для клиента, видевшего более
новое состояние, принимается до разрешённого им поколения (закрывает остаток D4-C).
`dmc-client/tests/d4_client_anchor.rs` — якорь только растёт, повреждённый файл — ошибка.

**Ограничения:** свежесть ограничена знанием unlock-клиента (откат к состоянию новее его якоря
не виден; клиент может обновлять якорь через `VaultStatus`); пока хранилище открыто, процесс
работает со своим состоянием — проверка выполняется при каждом unlock после рестарта;
CLIENT_OWNED-сессии (без unlock) якорь не передают; клиенты v1 и Tauri-хэндлы без каталога
KeyPass якорь не хранят.

### 9.12 D4-E — переносимость хранилища ключей и аварийное восстановление (COMPLETE)

**Аудит (до):** `vault/keytree.json` (соль, unlock proof, DEK, обёрнутые под KEK из Master Key)
в бэкап не входил; restore-цель становилась data root только после ручного копирования хранилища
ключей исходного хоста; при потере хоста бэкап был невосстановим даже с Master Key. Хранилище
ключей неизменно в течение жизни установки (`STORAGE_KEY_PATHS` создаются вместе с ним, повторной
записи нет).

**Инвариант:** зашифрованный бэкап + Master Key клиента достаточны, чтобы зарегистрированная
restore-цель открылась на любом хосте; без Master Key — ничего; ни Master Key, ни KEK, ни DEK в
бэкапе нет ни в каком кодировании; подменённое хранилище ключей не принимается.

**Без нового trust assumption:** переносится ровно тот же обёрнутый материал, который уже лежит
рядом с данными в live data root; конфиденциальность по-прежнему держится только на Master Key
(256 бит, у клиента). Escrow самого Master Key третьей стороне **не** реализован (это было бы
новое допущение).

* `BackupCreate`: `keystore/keytree.json` — побайтовая копия хранилища ключей установки
  (`CoreServerState::key_store_path`), только в зашифрованном бэкапе; роль `key_store` в манифесте
  с SHA-256 → аутентифицирован `manifest.sealed` вместе с остальными файлами. Без собственной
  криптографии: формат хранилища и AEAD прежние; добавлен только разбор из байтов
  (`dmc_vault::parse_locked_key_tree`).
* `verify`: запись `key_store` — только в зашифрованном бэкапе, ровно одна, ровно по этому пути;
  файл разбирается как запертое дерево ключей; посторонний файл в `keystore/` — ошибка.
* `restore` копирует `keystore/` в цель (как ciphertext остальных компонентов).
* `start_core`: у зашифрованного data root без `vault/keytree.json` — установка перенесённого
  хранилища (`install_key_store`, без ключей: размер и digest по открытому манифесту, разбор;
  существующее никогда не заменяется); нет перенесённого — прежний отказ (новое хранилище над
  зашифрованными данными не создаётся).
* Unlock: чужое хранилище не открывается Master Key клиента (unlock proof); затем до
  восстановления — установленное хранилище побайтово равно перенесённому
  (`ensure_key_store_matches`, при каждом unlock), а recovery с ключами аутентифицирует digest
  перенесённого через `manifest.sealed`. Любой отказ → vault заперт, `live/` не создаётся.

**Тесты:** `dmc-ops/tests/d4_key_store_portability.rs` (5, через `BackupCreate`/`BackupRestore`/
`start_core`/`VaultUnlock`): хранилище в бэкапе и restore-цели побайтово равно исходному, в манифесте
ровно одна запись `key_store`; Master Key, все DEK хранения и корня и все KEK на пути не найдены ни в
одном файле бэкапа и цели (raw / hex / HEX / base64 standard и URL-safe, все выравнивания;
negative control — сканер находит DEK в каждом кодировании); **чистый хост** (исходный data root
удалён): старт Locked, хранилище установлено, SQL → `VaultLocked`, данные не читаются; Master Key →
восстановление, generation = N, данные читаются, на диске ничего открытого, после рестарта снова
только после unlock; случайный ключ и Master Key другой установки → `UnlockFailed`; хранилище другой
установки (листинг пересчитан) → отказ и с Master Key A, и с Master Key B; изменённый обёрнутый DEK →
отказ; копия не совпадает с листингом → отказ старта, хранилище не установлено; то же дерево с другими
байтами (листинг пересчитан) → отказ (digest не аутентифицирован); в vault установлено не то, что
перенесено → отказ; посторонний файл в `keystore/` → отказ; контроль — нетронутая копия открывается.
Мутационная проверка: отключение побайтового сравнения или проверки посторонних файлов роняет
соответствующие случаи. Незарегистрированный restore (без аттестации) на чистом хосте по-прежнему
отклоняется (граница D4-C не ослаблена).

**Аварийное восстановление из одного каталога бэкапа — вариант B (утверждён): реестр
бэкапов у клиента.** Исходная установка потеряна до зарегистрированного restore; подтверждение
реестра D4-C утрачено вместе с её live-хранилищем, а бэкап своей записи содержать не может
(публикация → запись). Авторитет — клиент, тот же, что для свежести в D4-D; нового доверенного
участника нет.

**Инвариант:** аварийный restore может завершиться **только** если восстанавливаемый артефакт —
ровно тот, SHA-256 аутентифицированного `manifest.sealed` которого хранится в backup-якоре клиента
и передан клиентом внутри AEAD его unlock blob. Один якорь → один артефакт (без списка).

1. `BackupCreate` возвращает `manifest_sealed_sha256` — хэш именно `manifest.sealed` (пусто для
   незашифрованного бэкапа).
2. Клиент (`KeyPassHandle::record_backup` / `backup_create`, CLI `dmc backup create
   --keypass-dir`) хранит **один** backup-якорь рядом с KeyPass: `backup-anchor` =
   `<backup_id> <N> <sha256>`; более старый бэкап новее не заменяет; незашифрованный не
   авторизуется; повреждённый файл — ошибка.
3. Авторизация — только от клиента: unlock blob v3 (`UNLOCK_BLOB_VERSION_RESTORE`) запечатывает
   `material ‖ min_generation ‖ sha256`; версия в AAD — авторизацию нельзя ни изменить, ни снять
   понижением версии. Принимает её только `VaultUnlock`; остальные операции v3 отклоняют (не
   отбрасывают молча). Клиент: `vault_unlock_restoring_backup` / `dmc vault unlock --keypass-dir
   … --restore-authorized-backup` (`min_generation` = N бэкапа; это явный откат ровно до него —
   якорь поколения сбрасывается на открытое поколение).
4. Раскладка — офлайн и без ключей: `dmc backup stage-emergency --backup-dir … --data-root …`
   (`dmc_ops::stage_emergency_restore`): только зашифрованный бэкап, несущий хранилище ключей,
   только в пустой data root; копируется ciphertext, аттестация **не** пишется.
5. При unlock с авторизацией (`OpsStorageOpener::open_authorized`), до любой записи: установленное
   хранилище ключей = перенесённому; restore ожидается (иначе отказ — в том числе на живом
   хранилище и на уже восстановленной цели; если vault был открыт — запирается); проверка
   метаданных; `authorize_emergency_restore`: SHA-256 `manifest.sealed` = авторизованному, бэкап
   зашифрован и несёт хранилище ключей, полная проверка с ключами (подлинность манифеста, все
   digests, хранилище ключей), аутентифицированный N ≥ `min_generation` (иначе
   `StorageRollbackDetected`). Только после этого пишется та же запечатанная аттестация, что у
   зарегистрированного restore, и выполняется обычный `recover_registered`.
6. Другой бэкап той же установки (тот же Master Key, другой хэш) не принимается.
7. Существующее хранилище ключей не заменяется (раскладка — только в пустой каталог; установка
   при старте — только при отсутствии).
8. Любая неоднозначность → `UnlockFailed` (или `StorageRollbackDetected`, `UnlockBlobInvalid`),
   vault заперт, ни `live/`, ни аттестации.

**Тесты:** `dmc-ops/tests/d4_emergency_restore.rs` (5): исходный хост удалён, раскладка b2 из
внешней копии → старт Locked, хранилище ключей установлено; обычный unlock → отказ (D4-C); unlock с
авторизацией b2 → generation = N, данные читаются, аттестация записана, открытого текста нет;
после рестарта обычный unlock открывает, якорь живой установки → `StorageRollbackDetected`.
Хэш, возвращённый `BackupCreate`, = SHA-256 файла `manifest.sealed`. b1 под авторизацией b2 и
наоборот → `UnlockFailed`; содержимое b1 под `manifest.sealed` b2 (хэш совпадает) → отказ; вместе с
открытым манифестом b2 → отказ уже на старте; b1, переименованный в `backup-b2`, — отказ раскладки;
контроль — каждый со своей авторизацией открывается. Неавторизованный хэш → `UnlockFailed`;
изменённый в пути blob → `UnlockBlobInvalid`; v3, выданный за v2, → отказ; якорь выше N →
`StorageRollbackDetected` **до** восстановления (нет `live/`, нет аттестации); неверный Master Key
→ `UnlockFailed`; `open_unlock_blob_anchored` отклоняет v3. Авторизация на живом хранилище (запертом
и открытом) и на уже восстановленной цели → `UnlockFailed`, vault заперт. Раскладка в непустой
каталог (с хранилищем ключей) → отказ, оно не тронуто; бэкап без хранилища ключей и «открытый» бэкап
→ отказ; хранилище ключей поверх существующего при старте не пишется.
`dmc-client/tests/d4_client_backup_anchor.rs` — один якорь, старый не заменяет новый,
незашифрованный не авторизуется, повреждённый/усечённый/лишние поля — ошибка, без каталога — нет
якоря. Мутационная проверка: отключение сравнения хэша, проверки «restore ожидается», проверки
якоря до записи и отказа при открытом хранилище роняет соответствующие тесты.

**Ограничения:** авторизуется последний бэкап, созданный **этим** клиентом через KeyPass (бэкапы,
созданные другими клиентами или без `--keypass-dir`, аварийно не восстанавливаются этим клиентом);
потеря backup-якоря = аварийное восстановление невозможно (зарегистрированный restore по-прежнему
работает, пока жив исходный хост); ротации/истории якорей нет (по решению — один артефакт);
каталог бэкапа должен сохранить имя `backup-<id>` (проверка идентичности).

Escrow Master Key (утрата ключа клиентом) — отдельный вопрос, вне D4-E: при CLIENT_OWNED потеря
Master Key = потеря данных по построению.

### 9.13 D4-F — шифрование dev / test bootstrap

**Аудит (до), пути, пишущие SQL-данные без ключей:**
1. `dmc_server::bootstrap_core_state*` (около 190 вызовов в ~35 тестовых файлах, `test/src/support.rs`,
   первый старт `dmc serve --dev`, dev co-host DMC IPC в `dmc-core`): `StateMaterializer::open` **без
   ключей** сразу при старте — vault «заперт», а данные открыты и на диске, и в памяти; эфемерный
   vault не содержал узлов ключей хранения.
2. `dmc serve --dev`, повторный старт: открытый корень попадал в `start_core` как PlaintextLegacy →
   `migration_required` (dev-сервер после рестарта не открывался).
3. Dev co-host `dmc-core`: при каждом старте новый эфемерный vault поверх старых данных.
4. Остаются (не bootstrap): библиотечные keyless-конструкторы `StateMaterializer::open`,
   `JournalBackend::open/in_memory` (тесты, явная миграция D4-A этапа 5, инструмент миграции
   защищённых колонок `protect.rs` — читают открытые данные по назначению); legacy-движок `dmc-core`
   (только `dmc-pgwire-legacy-reference`, §9.8).

**Инвариант:** у любого dev/test/production входа, который поднимает SQL-ядро, хранилище открывается
только на `VaultUnlock` и только с ключами хранения vault; пока vault заперт, SQL-данные не читаются и
не создаются; на диске — только ciphertext; lock закрывает хранилище; открытое хранилище не
открывается и не конвертируется неявно.

**Без нового trust assumption:** ключи — DEK того же дерева ключей (у эфемерного vault — в памяти
процесса, у постоянного — `vault/keytree.json`, как в production). Dev-файл `.dmc-dev-master.hex`
(открытый Master Key, только `--dev` + `AVRORA_DEV=1`) — прежний dev-компромисс, не изменён.

* `bootstrap_core_state*`: `CoreServerState` с пустым контекстом + `DevStorageOpener`
  (`StorageOpener`): на unlock — `open_with_cipher(.., Some(ключи))`, при пустом журнале — засев
  каталога по умолчанию (и демо-таблицы `users`) уже запечатанным; иначе — как раньше. Эфемерный vault
  (`VaultRuntime::create_locked`) создаёт узлы `STORAGE_KEY_PATHS`.
* `bootstrap_core_state_persistent_with_hub`: то же с постоянным хранилищем ключей
  `root/vault/keytree.json` (Master Key — только при создании) — dev co-host `dmc-core`.
* `dmc serve --dev`: всегда `start_core(StartupOptions::dev())` — production-путь хранения
  (постоянное хранилище ключей, отложенное открытие, sealed) + dev-учётка и демо-таблица `users`
  (`StartupOptions::dev_users_table`, засевается в каталог при первом unlock). Рестарт — тот же
  ключ, без миграции.

**Тесты:** `dmc-ops/tests/d4_dev_bootstrap_encrypted.rs` (4): запертый bootstrap — хранилище не
открыто, файлов хранилища нет, SQL → `VaultLocked`; unlock — засеянные таблицы, данные читаются,
журнал запечатан, маркер не найден ни в одном кодировании (negative control: тот же маркер в открытом
хранилище находится); lock → `VaultLocked`, unlock → данные снова; неверный ключ → `UnlockFailed`,
ничего не записано; открытый (до D4-F) dev-корень → отказ, vault заперт, файл не изменён;
постоянный bootstrap — Master Key один раз, рестарт открывается только своим ключом, данные
запечатаны, хранилище ключей без Master Key; эфемерный bootstrap с другими ключами на том же корне
ничего не читает и не меняет; `start_core(dev())` — засев `users`, sealed, рестарт без миграции,
production-опции таблицу не засевают. `dmc-cli/tests/serve_dev_encrypted_cli.rs` — реальный
`dmc serve --dev`: хранилище ключей и dev-файл созданы, файлов SQL-хранилища до unlock нет;
рестарт на том же корне стартует (тот же ключ, тот же dev-файл). Мутационная проверка: dev-opener
без ключа роняет все тесты bootstrap.

Существующие тесты, неявно опиравшиеся на открытый bootstrap, переведены на контракт production (не
ослаблены): бэкап при запертом vault → `VaultLocked` (новый тест `backup_needs_an_unlocked_vault`),
остальные бэкап-тесты делают unlock (`phase7_backup_control`, `phase7_backup_final`, `phase7_audit`,
Tauri); восстановленные деревья открываются ключами исходной установки (`phase7_backup_final`,
`client_owned_key_api`, `client_owned_http` — «атакующий» с Master Key, по-прежнему только
ciphertext CLIENT_OWNED); диагностика запертого ядра журнал не сообщает (`None`), после unlock —
сообщает (`phase7_diagnostics`, `phase7_observability_final`).

**Остаётся:** публичные `CoreServerState::new_locked*` принимают уже открытый контекст — его
используют только тестовые фикстуры (production-входы — `start_core` и bootstrap — нет); keyless
библиотечные конструкторы (п. 4 аудита) остаются для тестов, явной миграции и `protect.rs`.

## 10. Identity persistence и network GRANT — `IDENTITY_PERSISTENCE_GRANT_GAP`

### 10.1 Текущая модель (проверено по коду)

| Сущность | Где живёт | Персистентность | Кто создаёт |
|---|---|---|---|
| identity (`IdentityId`, custody, subject, tenant) | `AuthService.identities` (память) | `ownership/identities.json` пишется после enrollment (`persist_identities`) | оператор через invite (D2) или in-process |
| password record (только SERVER_OWNED) | `AuthService.credentials` | в том же `identities.json` | in-process (`configure_credential`, `create_identity`) |
| key bundle (X25519 + Ed25519) | `ClientKeyDirectory` | `ownership/client/client-directory.json` | клиент при enrollment / rotation |
| SQL privilege | `AuthService.grants` (`GrantStore`) | **нигде** | **только in-process** (`grants_mut().grant`) |
| сессия | `InMemorySessionStore` | нет (по замыслу) | `Authenticate` / `ClientAuthFinish`, привязана к каналу (D5) |
| invite | `InviteStore` | `ownership/client/invites.json` (только хэш токена) | оператор с `CREATE` на `system` |

Binding: subject ↔ key — key directory; identity ↔ subject — `identities.json`;
identity ↔ privileges — только память; session ↔ identity/subject/канал — память.

### 10.2 Находки

1. **Production не загружает `identities.json`.** `dmc-ops::start_core` создаёт
   `AuthService::new()`; `load_identities` вызывается только CLI `encrypt-migrate`. После
   перезапуска все enrolled CLIENT_OWNED identities исчезают из `AuthService`: ключи и
   envelopes на диске есть, но аутентификация требует identity → пользователи заблокированы
   (данные не потеряны, доступ — да). Повторный enrollment выдаёт **новый** subject.
2. **Grants не персистируются** (`IdentityFile` = identities + credentials).
3. **Нет сетевого GRANT/REVOKE** ни в SQL (`GRANT` не парсится), ни в протоколе. Пользователь,
   enrolled по сети, не может получить SQL-привилегии ни через один транспорт; тесты выдают
   их in-process.
4. **Нет первого администратора в production**: `AuthService` пуст, поэтому некому выпускать
   invites и grants.

### 10.3 Минимальный безопасный механизм (дизайн, не реализован)

* Протокол: `PrivilegeGrant{session_id, grantee: IdentityId, resource, action}` /
  `PrivilegeRevoke{…}` / `PrivilegeList{session_id, grantee}` — только DMC IPC (не в
  allowlist HTTP/control-plane tunnel).
* Явная authority: новое действие `Action::Grant` на `Resource::System` (не перегружать
  `CREATE`). Проверка на сервере: caller имеет `GRANT` на `system`; запрет выдачи самому
  себе (`grantee != caller`), чтобы обычный пользователь не мог эскалировать даже при
  ошибочно выданном праве; `GRANT` на `system` может выдать только держатель того же права.
* Персистентность: `IdentityFile` v2 = identities + credentials + grants, атомарная запись
  (существующий `write_atomic`), загрузка в `start_core`, если файл есть; v1 читается.
* Revoke: удаляет grant; живые сессии перепроверяют права на каждом запросе (уже так:
  `authorize_sql` при каждом `ExecuteSql`).
* Audit: событие `PRIVILEGE_GRANT/REVOKE` (кто, кому, ресурс, действие) в существующий
  audit sink; без секретов.
* Self-revoke инвариант (F9) не затрагивается: privileges ≠ key envelopes.

### 10.4 Blocker: корень authority (trust anchor)

Чтобы GRANT работал в production, кто-то должен получить **первое** `GRANT` на `system`.
Это новое доверие, и выбирать его молча нельзя:

* **A.** Локальный bootstrap: команда `dmc identity bootstrap-operator` пишет первую
  SERVER_OWNED identity с `GRANT`+`CREATE` на `system` в `identities.json` (доступ к
  файловой системе хоста = корень authority), одноразово — пока файла нет.
* **B.** Одноразовый bootstrap-token, печатаемый при первом старте (как control plane
  `bootstrap.token`), обмениваемый по сети на первую operator-identity.
* **C.** Связать с существующим operator plane (access key + TOTP `AuthManager`) — две
  модели оператора сливаются, что D3 прямо запрещает для CLIENT_OWNED, но для SERVER_OWNED
  operator — открытый вопрос.

Конфиденциальность CLIENT_OWNED от этого выбора не зависит: любой оператор, в том числе
обладающий всеми grants и доступом к диску, получает только ciphertext (подмена ключей в
`client-directory.json` обнаруживается TOFU как `KeyChanged`). Выбор влияет на
**авторизацию и доступность**. Рекомендация: A (не требует сети до появления оператора,
повторяет модель bootstrap control plane).

### 10.5 Реализовано (решение Administrator-A)

* `IdentityFile` v2 = identities + verifiers + **grants** + bootstrap record; v1 читается;
  запись 0600 с момента создания (`secure_fs`), атомарно.
* Загрузка при старте (`dmc-ops::start_core` → `load_identity_directory`): битый файл или
  отсутствие файла после bootstrap → `StartupError::Identity` (fail closed, без пустой
  директории).
* `dmc identity bootstrap-operator --data-dir … --name … --password-stdin`: только на свежей
  установке (нет identities и нет маркера `ownership/bootstrap.consumed`), маркер занимается
  атомарно (`create_new`) до записи, вызывающий должен владеть data dir, пароль только из
  stdin, отказ при работающем сервере на сокете; повтор — отказ навсегда; `--force`/reset нет.
* Первый оператор: `GRANT`+`CREATE` на `system`, `CONNECT`/`CREATE` на БД, `USAGE`/`CREATE` на
  схему; **без** доступа к данным таблиц (выдать может только другой администратор).
* `PrivilegeGrant` / `PrivilegeRevoke` / `PrivilegeList` (только DMC IPC; не в allowlist
  HTTP/tunnel): нужен `GRANT` на `system`; самому себе — запрет; изменение персистится до
  ответа (при ошибке записи откатывается); аудит `audit.privilege.granted/revoked`
  (кто, кому, что) и `audit.authorization.denied` на отказы.
* Тесты: `dmc-security auth::bootstrap::tests` (5), `dmc-cli/tests/bootstrap_operator_cli.rs`
  (реальный бинарь), `test/tests/identity_persistence.rs` (production `start_core`, три рестарта,
  network grant/revoke, аудит, повторный bootstrap, потеря файла).

Блокер §10.4 снят этим решением. Остаётся: сессии не персистятся (по замыслу); восстановление
утраченного администратора — отдельный протокол (не реализован).

## 7. План после решения (порядок задачи)

1. D1/D2/D5: auth key в `dmc-client-crypto`, проверка в `dmc-security`, enrollment invite,
   challenge store, сессии с channel binding, персистентность identities/grants/directory
   под `data_root/ownership` (уже входит в backup-компонент `ownership`).
2. HTTP (по D3) → атаки HTTP; control plane → атаки; pgwire (по D4, начиная с F5).
3. Cross-transport contract tests; identity backup/restore e2e; memory-exposure анализ;
   расширение attack matrix; SQL/logging/reliability аудит; документация; полный прогон.

## 8. Статус

| Транспорт | Статус |
|---|---|
| DMC IPC | контракт D1/D2/D5 реализован; `client_owned_key_api.rs`, `client_owned_attack_matrix.rs` |
| HTTP | реализован (loopback, подписанные запросы); `client_owned_http.rs` |
| Control plane | реализован (туннель); `client_owned_control_plane.rs` |
| pgwire | at-rest gate §9 **пройден** (D4-A этап 6, §9.7); production pgwire переведён на SQL plane (§9.8), только loopback до D4-G (TLS) |

Открытые вопросы: сетевой pgwire по TLS (D4-G). Закрыто: pgwire на SQL plane (§9.8), защищённые
манифесты (§9.9), реестр бэкапов (§9.10), откат data root (§9.11), перенос хранилища ключей и
аварийное восстановление по авторизации клиента (§9.12, D4-E), dev/test bootstrap на зашифрованном
пути (§9.13, D4-F). Статусы без изменений:
`OPERATOR_BLIND_NOT_PROVEN`, `REFERENCE_PATH_PROVEN = false`, production readiness
`NOT_READY`.
