# AvroraCore — Auth + Cryptographic Data Ownership

> **Retention does not imply readability.**
> **Database administrators are not cryptographic owners of user data.**

Статус: v2 (client-side encryption, §20) поверх v1.1 (hardening) — вертикальный slice (библиотечный API + интеграция с persistence
через тесты) + закрытые P0-gaps + явная SQL-миграция защищённых колонок (§16).
Это **не** Zero-Knowledge-система и **не** operator-blind система в строгом смысле — см.
[Security boundary](#4-security-boundary) и [Known limitations](#12-known-limitations).

---

## 1. Audit исходной модели (Phase 1)

| Подсистема | Где | Что нашли |
|---|---|---|
| Event plane: vault | `dmc-vault` (`KeyTree`, `EncryptedKv`, `persist`) | AES-256-GCM, path-DEK wrapped под HKDF-KEK. **Все** KEK выводятся из одного Master Key. `cap_root` покрывает все пути. Кто разблокировал vault — читает всё. |
| Event plane: WAL | `dmc-journal` | Payload зашифрован path-DEK (AAD = path, seq, key_version, kind). Path, actor role/session, timestamps, wrapped node bundle — открытым текстом. |
| Master Key | `dmc-vault::keypass` | Argon2id(Master Password) → wrap Master Key. В RAM процесса после unlock. |
| SQL plane | `dmc-storage` row segments `*.dat`, `dmc-materialized` `state_events.json` / snapshot, index store, statistics, `dmc-backup` | **Plaintext at rest.** `VaultRuntime` в `dmc-server` — только lock/unlock-гейт, ключ не используется для данных. Подтверждено тестом-негативным контролем. |
| Auth (SQL) | `dmc_security::auth::AuthService` | **Пароли в plaintext в RAM**, сравнение `==` (не constant-time), `#[derive(Debug)]` печатал пароли. Сообщения ошибок различали «unknown» и «invalid» (enumeration). |
| Auth (UI) | `dmc_security::authentication` | Access key — однократный SHA-256 (быстрый хэш); TOTP-secret в файле открытым текстом. |
| Sessions | `AuthSession` | `Debug` выводил `unlock_binding_key`. |
| Dev keys | `dmc-core::server::try_dev_unlock`, `dmc-cli serve` | `avrora serve` авто-разблокировал vault из `.avrora-dev-master.hex` **без проверки dev-режима**. `dmc serve` в production-ветке пишет unlock material в файл. |
| Backup | `dmc-core::backup`, `dmc-backup` | Event plane: копия ciphertext-layout (+ BackupSAS шифрует поверх). SQL plane: копия plaintext-файлов. Ключ бэкапа выводится из Master Key. |
| Key wrapping | `KeyTree::wrap_key`, keypass, unlock blob | Envelope-примитивы существуют, но версионирования envelope и per-user authority нет. |

Вывод: существующая модель защищает данные **от того, у кого нет Master Key**, но не
**от того, у кого он есть** (DBA/оператор/процесс). Per-user криптографического владения не было.

### Что исправлено в этой работе
1. `AuthService`: Argon2id-verifier вместо plaintext-паролей, constant-time сравнение,
   единое сообщение «invalid credentials», redacted `Debug` для `Credential`,
   `PasswordCredentialVerifier`, `AuthSession`.
2. `avrora serve`: авто-unlock из файла только при `AVRORA_DEV=1|true`
   (`control::dev::dev_mode_enabled`), иначе vault остаётся Locked. `make avrora-dev` ставит флаг.
3. Новый слой cryptographic ownership (ниже).

### Что найдено, но **не** исправлено (вне scope этого slice)
См. [Known limitations](#12-known-limitations) — пункты L1–L8. Часть из них закрыта в v1.1 — см. §15.

---

## 2. Architecture

```
            ┌────────────── dmc-security ──────────────┐
 password → │ AuthService            (authentication)  │
            │   authenticate_with_key_unlock()          │──► Identity + CredentialUnlock
            │ SessionManager         (session)          │──► SessionId
            │ ownership::policy      (authorization)    │    decide(principal, owner, op)
            │ ownership::KeyManager  (key access)       │    open_session / seal / open_sealed
            │ ownership::EncryptedStorage               │    put / get → RecordBackend
            └───────────────────────────────────────────┘
                     │ uses primitives only
            ┌──────── dmc-vault::ownership ────────────┐
            │ credential  Argon2id → HKDF split         │
            │ envelope    KeyEnvelope (versioned, AAD)  │
            │ keyring     SubjectKeyring / Unlocked…    │
            │ record      SealedRecord (AES-256-GCM)    │
            │ store       KeyringStore (fsync+rename)   │
            └───────────────────────────────────────────┘
                     │ only sealed bytes leave this boundary
   Runtime::put_data (WAL, snapshots, compaction) · SQL Blob column · backups · BackupSAS
```

| Абстракция | Тип | Инвариант |
|---|---|---|
| AuthService | `dmc_security::auth::AuthService` | Хранит только verifier; пароль и wrap-key не сохраняются. |
| AuthorizationService (keys) | `ownership::policy::decide`, `KeyManager::authorize` | Default deny; роли/`cap_root`/grants каталога не являются входом. |
| KeyManager | `ownership::KeyManager` | Единственное место unwrap. Каждый вызов перепроверяет session + identity. |
| KeyEnvelope | `dmc_vault::ownership::KeyEnvelope` | Все метаданные в AAD. |
| CryptoContext | `RecordContext` + crypto session в `KeyManager` | tenant/owner/object/version связаны через AAD/header. |
| EncryptedStorage | `ownership::EncryptedStorage<B: RecordBackend>` | Backend видит только sealed bytes. |

Новая функциональность — **библиотечный API**: ни один сетевой путь (control plane,
HTTP, pgwire) его пока не вызывает, т.е. он не активируется в production неявно.

### Identity ≠ Data identity
`Identity { id, name, …, subject_id: Option<SubjectId>, tenant }`.
`SubjectId` — случайные 128 бит, **не выводится** из `IdentityId`/имени. В записях,
ключах и путях хранения используется только `SubjectId`. Маппинг `IdentityId → SubjectId`
есть только в identity directory (`runtime/ownership/identities.json`), т.е. псевдонимизация
защищает от тех, у кого нет этого файла, — **не** от DBA (см. L6).

---

## 3. Key hierarchy

```
password ──Argon2id(salt, 19 MiB, t=2)──► root ──HKDF──┬─► verifier      (хранится AuthService)
                                                       └─► kek-wrap key  (никогда не хранится)
                                                                │ open
  SubjectKek envelope (credential:<id>, epoch N) ───────────────┘
                     │
                     ▼
                KEK (random 256 bit, per subject, НЕ зависит от vault Master Key)
                     │ wrap (DataKey envelopes, kek:<epoch>)
        ┌────────────┼──────────────┐
        ▼            ▼              ▼
    DEK v1        DEK v2         DEK v3 …        (random 256 bit)
   RETIRED        ACTIVE        ROTATING
        │            │
        ▼            ▼
    SealedRecord (AES-256-GCM, random 96-bit nonce)
```

* Пароль **никогда** не используется как ключ данных.
* Смена пароля = перезаворачивание KEK envelope; DEK и данные не меняются
  (тест `password_change_rewraps_without_reencryption_and_crash_windows`).
* Keyring содержит HMAC-SHA256 (ключ = HKDF(KEK, "keyring-mac")) по всем метаданным:
  состояния ключей, версии, generation, список envelope'ов. Подмена/rollback без KEK
  детектируется (`KeyringTampered`).

### KeyEnvelope (format v1)
`format_version, kind {SubjectKek|DataKey|DelegatedDataKey}, tenant, owner, holder,
key_version, alg="aes-256-gcm", wrapped_by ("credential:<id>"|"kek:<epoch>"),
created_at_ms, nonce, wrapped_key`. Всё, кроме `nonce`/`wrapped_key`, входит в AAD.
`Debug` печатает только длину ciphertext.

### SealedRecord (format v1)
```
"AVSR" | fmt=1 | alg=1 | key_version u32 | owner 16B | record_version u64 | nonce 12B | ct+tag
AAD = "avrora/sealed-record/v1\0" ‖ header ‖ lp(tenant) ‖ lp(object_id)
```
Header читается без ключа (выбор DEK, подсчёт ссылок на версию). Tenant и object id не
хранятся в записи, но связаны через AAD: перенос ciphertext в другой объект/tenant ломает
аутентификацию.

---

## 4. Security boundary

| Сторона | Что держит |
|---|---|
| **Database process** | wrapped keyrings, verifiers, sealed records, vault Master Key (event plane), SQL plaintext в незащищённых колонках (SQL plane). **Во время активной crypto-сессии пользователя — его KEK/DEK в RAM и его пароль в момент логина.** |
| **Cryptographic authority** | Пароль (или другой credential) субъекта. Без него KEK не открывается. |

> **Database process currently handles authentication secrets and may hold decrypted key
> material in RAM during an active session.**

Zeroization (`zeroize`) и redacted `Debug` уменьшают время жизни и случайные утечки
секретов, но **не** защищают от memory dump / отладчика / подменённого бинаря.

**Честное ограничение:** authority пересекает границу процесса — пароль передаётся в
процесс при логине, ключи живут в RAM процесса на время сессии. Поэтому:

* **НЕ утверждается** «оператор не может расшифровать» против host-admin'а, который может
  снять memory dump процесса или подменить бинарь и дождаться логина пользователя.
* Утверждается: оператор/DBA **без** компрометации процесса во время сессии пользователя
  (диск, бэкапы, WAL, Master Key, `cap_root`, любые API БД) plaintext получить не может, кроме
  как офлайн-перебором пароля через Argon2id.

Для по-настоящему operator-blind модели см. [Next stage](#13-next-stage-operator-blind).

---

## 5. Authentication flow

```
Credential::Password{name, pw}
  → AuthService::authenticate_with_key_unlock
      PasswordRecord.check: Argon2id + HKDF → verifier (constant-time cmp)
      unknown identity → тот же KDF + та же ошибка ("invalid credentials")
      identity disabled → IdentityDisabled
  → (AuthenticatedIdentity, CredentialUnlock{credential_id, wrap_key})
  → AuthService::create_session(identity) → SessionId
```
`CredentialUnlock`: не `Clone`, redacted `Debug`, zeroize on drop. Сам по себе ничего не
авторизует.

## 6. Authorization flow

```
KeyManager::open_session(auth, session, unlock)
   validate_session → identity active → identity.subject_id/tenant
   unlock.credential_id == текущий credential identity
   keyring.load → unlock (KEK) → verify MAC → unwrap DEKs
   recovery: завершить ROTATING; удалить старые credential envelopes; удалить
             delegated keys с отозванным grant
KeyManager::{seal, open_sealed, rotate…, delegate…}
   live_principal: сессия ещё валидна? identity активна? → иначе ключи выкидываются из RAM
   policy::decide(principal, owner, owner_tenant, op, delegations)
       tenant ≠           → Deny(TenantMismatch)
       principal == owner → Allow(Owner)
       op == Read && live grant(owner→principal) → Allow(Delegated)
       иначе              → Deny(NotOwner)
```
Delegation требует **и** policy-grant (`delegations.json`), **и** delegated envelope в
keyring получателя (создать может только owner с открытыми ключами). Поддельный grant без
envelope ничего не даёт; удалённый grant блокирует доступ сразу.

Делегирование сейчас **online**: обе сессии (owner и grantee) должны быть открыты.

## 7. Encryption flow

```
EncryptedStorage::put(km, auth, session, owner, object, plaintext)
   record_version = prev.header.record_version + 1
   km.seal → authorize(Write) → active DEK → seal_record(AAD) → backend.put(sealed)
EncryptedStorage::get(...)
   backend.get → km.open_sealed → authorize(Read) → header.key_version → DEK → open_record
```
Любая ошибка — терминальна: нет fallback key, default key, plaintext-пути.

---

## 8. Backup security

* Event plane: keyrings и identities лежат в `runtime/ownership/` → входят в секцию
  `runtime` локального бэкапа и в BackupSAS-архив (`archive::pack_dir`). Данные — sealed
  records внутри уже зашифрованного (Master Key) WAL/snapshot.
* Оператор бэкапа, у которого есть **и** бэкап, **и** Master Key, разблокирует vault и
  через `cap_root` получает только `SealedRecord` (тест
  `owned_data_stays_ciphertext_through_wal_snapshot_backup_restore`).
* Бэкап без секции `runtime` восстанавливается, но без keyring'ов: расшифровка
  невозможна (`KeyringNotFound`), новый ключ **не** создаётся.
* Скрытого plaintext-экспорта нет.
* SQL plane (`dmc-backup`): копирует plaintext-файлы; защищены только значения,
  записанные как sealed (Blob). См. L1.

## 9. Recovery behavior (fail-closed)

| Ситуация | Результат |
|---|---|
| keyring отсутствует | `Ownership(KeyringNotFound)` — ключ не генерируется |
| keyring изменён / откатан | `Ownership(KeyringTampered)` |
| неверный/устаревший credential | `Ownership(WrongCredential)` / `KeyAccessDenied` |
| версия DEK уничтожена/неизвестна | `Ownership(KeyVersionUnavailable)` |
| ciphertext изменён / чужой контекст | `Ownership(DecryptFailed / ContextMismatch)` |
| torn `*.keyring.json.tmp` после краха | удаляется при `KeyringStore::open`; действует предыдущий keyring |

Crash consistency:
* Keyring пишется temp → fsync → rename → fsync(dir); optimistic concurrency по `generation`.
* Новая DEK сначала персистится как `ROTATING`, и только потом становится `ACTIVE`.
  Записи шифруются только `ACTIVE`-ключом ⇒ «запись есть, ключа нет» не возникает.
* Крах между шагами ротации: при следующем `open_session` ротация завершается
  (тест `crash_between_rotation_steps_is_recovered`).
* Смена пароля: (1) новый KEK envelope в keyring, (2) identities, (3) удаление старого
  envelope при следующем открытии. Крах после (1) — работает старый пароль; после (2) — новый.

## 10. Key rotation

Lifecycle: `ACTIVE → (новая ROTATING) → RETIRED → DESTROYED`.

* `rotate_data_key` = `begin_data_key_rotation` + `complete_data_key_rotation`.
* Старые записи читаются старой версией; новые пишутся новой (тест проверяет
  `key_version_references`). Переживает рестарт и restore из бэкапа.
* `destroy_retired_key(version, live_references)` отказывает, пока на версию ссылается
  хоть одна запись; `EncryptedStorage::reencrypt_owner` переводит записи на ACTIVE.
* `rotate_kek` — новый KEK, перезаворачивание DEK/delegated envelopes без
  перешифрования данных; остаётся только предъявленный credential.

**Важно:** ротация KEK/пароля не отзывает старые копии keyring'а в бэкапах — старый пароль +
старый keyring из бэкапа открывают DEK того времени. При компрометации нужны ротация DEK +
`reencrypt_owner` + `destroy_retired_key`, и даже это не трогает уже сделанные бэкапы.

---

## 11. Threat model

Обозначения: ✅ защищено, ❌ не защищено, ⚠️ частично.

| # | Attacker | Может получить | Не может получить | Assumptions |
|---|---|---|---|---|
| 1 | Database administrator (Master Key, `cap_root`, SQL grants, identity file) | метаданные, sealed records, SQL plaintext незащищённых колонок (L1), event-plane данные **не** под ownership, маппинг subject↔name (§17), может сбросить пароль (lockout = DoS); **не** может получить KEK (нет export API, §15) | ✅ plaintext owned-данных: KEK не выводится из Master Key; сброс пароля даёт `WrongCredential` (тест `administrator_has_no_cryptographic_authority`) | DBA не исполняет код внутри процесса во время сессии жертвы |
| 2 | Host administrator | всё из #1 + ❌ memory dump / подмена бинаря ⇒ ключи активных сессий и пароли при логине | ⚠️ ключи пользователей, которые не логинятся после компрометации | TEE/HSM нет |
| 3 | Backup operator | sealed records, keyrings, verifiers; с Master Key — расшифрованный event plane (но owned payload остаётся sealed) | ✅ owned plaintext; ⚠️ офлайн-перебор паролей через Argon2id | сильные пароли |
| 4 | Stolen backup | как #3 без Master Key: event plane — ciphertext; SQL plane — ❌ plaintext незащищённых колонок, ✅ sealed для мигрированных (§16) | ✅ owned plaintext | — |
| 5 | Stolen disk | как #4 | ✅ owned plaintext | процесс не работает / RAM не снята |
| 6 | Stolen WAL | path'ы (subject id, object id), размеры, timestamps, key versions | ✅ payload (path-DEK + sealed) | — |
| 7 | Compromised database process | ❌ всё, что проходит через процесс: пароли при логине, ключи активных сессий, plaintext их данных | ⚠️ ключи субъектов, которые не открывали сессию во время компрометации | — |
| 8 | Unauthorized authenticated user | свои данные; размеры/наличие чужих записей при доступе к storage | ✅ чужие DEK (тесты owner/tenant isolation, raw ciphertext swap) | корректная сессия |
| 9 | User with revoked credentials / disabled | — | ✅ новая сессия; активная crypto-сессия гасится на следующей операции | revoke через `AuthService` |
| 10 | Attacker with ciphertext only | длины, header (owner subject id, key/record version) | ✅ plaintext; ✅ незаметная подмена (AEAD + AAD) | AES-256-GCM, уникальный nonce |

Криптографические гарантии: AES-256-GCM (IND-CPA + INT-CTXT) для envelope'ов и записей,
HMAC-SHA256 для метаданных keyring, Argon2id (19 MiB, t=2, p=1) для паролей, HKDF-SHA256
для domain separation. Все примитивы — из `aes-gcm`, `argon2`, `hkdf`, `hmac`, `sha2`,
`subtle` (RustCrypto); собственной криптографии нет.

### PROTECTED
* plaintext owned payload в WAL, journal segments (включая rotation/compaction), base и
  runtime snapshots, keyring/identity файлах, локальных бэкапах, BackupSAS payload,
  restore-staging, восстановленном layout, SQL row segments / event log (если значение sealed);
* целостность и привязка записи к owner/tenant/object/record_version/key_version;
* целостность метаданных keyring (состояния, версии, envelope'ы);
* изоляция субъектов и tenant'ов на уровне ключей, независимо от прав в БД.

### NOT PROTECTED
* размер записей (sealed record = plaintext + 62 байта: header 34 + nonce 12 + tag 16), количество записей, timestamps;
* subject id и object id в путях хранения (`owned/<subject>/<object>`), key/record versions;
* маппинг identity ↔ subject для владельца identity-файла;
* граф делегирования (`delegations.json`);
* access patterns, тайминг WAL, факт логина;
* SQL plane без sealing (L1), индексы/статистика по SQL-колонкам;
* данные event plane, записанные не через KeyManager (защищены только Master Key);
* ключи и пароли внутри процесса во время активных сессий.

Полной анонимности система **не** обеспечивает. Соответствие конкретному законодательству
(GDPR/152-ФЗ и т.п.) **не** заявляется без отдельного юридического анализа.

---

## 12. Known limitations

* **L1 — SQL plane plaintext at rest (частично закрыто в v1.1).** Хранилище SQL само по
  себе не шифрует. Защищены только колонки, явно мигрированные `dmc encrypt-migrate` (§16)
  или изначально записанные sealed. Всё остальное (схема, незащищённые колонки, индексы и
  статистика по ним, owner-колонка) остаётся plaintext. Тест-негативный контроль:
  `dmc-materialized/tests/ownership_sql_rowstore.rs`, `dmc-backup/tests/ownership_sql_storage.rs`.
* **L2 — Ключи в RAM процесса** на время crypto-сессии; пароль проходит через процесс.
* **L3 — Офлайн-перебор**: keyring + identities.json позволяют перебирать пароль (цена Argon2id).
  Политика: ≥ 8 символов для key-credentials; recovery-код — отдельный credential
  (`KeyManager::add_credential`), пока без UI.
* **L4 — Delegation online** (обе сессии открыты). Новые версии DEK владельца после
  ротации не передаются автоматически — нужно повторное `delegate_read`. Отзыв не отменяет
  знание уже прочитанных данных.
* **L5 — Не подключено к сетевым API** (control plane / HTTP / pgwire / AvroraClient) —
  сознательно отложено до стабилизации контракта; `put_sealed` подготовлен (§18);
  identities.json — отдельное хранилище от `UserDirectory` event plane и от sealed users в
  vault snapshot.
* **L6 — Псевдонимизация слабая против DBA** (identities.json содержит маппинг) — аудит и
  варианты в §17; реализация после отдельного design review.
* **L7 — Остаток из аудита (v1.1 закрыл большую часть, см. §15):** `KeyMaterial::to_hex` /
  `from_hex` публичны (нужны для одноразового показа/ввода Master Key event plane);
  `KeyTree::dek` / `peek_dek` публичны в пределах vault (Master-Key-домен, не subject-ключи);
  dev-константы ключей в бинаре (используются только dev-путями под `AVRORA_DEV=1`);
  TOTP secret по природе хранится на сервере в открытом виде (0600) — TOTP не защищает от
  того, кто читает файл; bearer-токены UI не зануляются (in-memory `String`).
* **L8 — AES-GCM с random nonce**: безопасный предел ≈ 2³² записей на одну версию DEK —
  ротируйте DEK заранее; счётчик не персистится.

## 13. Next stage (operator-blind)

1. **Client-side sealing** в AvroraClient: `CredentialUnlock`/KEK/DEK выводятся и живут
   только на клиенте; сервер хранит keyring и `SealedRecord`, никогда не видит пароль/ключ.
   Существующий формат envelope/record переиспользуется без изменений.
2. **Асинхронное делегирование** (X25519/HPKE public key на subject) — без online-сессии
   получателя.
3. **External KMS / HSM** для tenant-KEK с attestation-политикой как альтернатива (1).
4. **SQL plane encryption** (L1) с явной миграцией.

---

## 15. v1.1 hardening (P0 / P0.5)

| # | Gap | Исправление | Какая возможность атакующего удалена | Тест |
|---|---|---|---|---|
| A | `KeyTree::export_kek` / `install_kek` публичны | Удалены. Ни `KeyTree`, ни `UnlockedKeyring` не дают читать KEK | Любой код с доступом к API (вкл. admin/backup-пути) не может вынуть KEK | `dmc-vault` doctests `compile_fail` ×4 + контроль; `ownership::store::tests::subject_kek_not_reachable_from_vault_or_backup_bytes` |
| B1 | `dmc serve` (production) писал unlock material hex в `.dmc-dev-master.hex` | Production: по умолчанию **ничего** не пишется, vault остаётся Locked; явный `--keypass-dir` → Argon2id-KeyPass (0600, пароль от оператора: prompt или `DMC_KEYPASS_PASSWORD`); устаревший plaintext-файл удаляется. `--dev` требует `AVRORA_DEV=1` | Кража диска/бэкапа data-root больше не даёт unlock SQL-vault | `dmc-cli serve::tests::*` (3) |
| B2 | `avrora serve` поднимал co-hosted DMC IPC с dev-учёткой `analyst/pw` и писал hex-ключ — в production | Co-host только при `AVRORA_DEV=1`; файл — 0600 с момента создания | Убраны default credentials и plaintext-ключ из production-пути | `control::dev::tests::dev_mode_requires_explicit_opt_in` (парсинг гейта; сам co-host отдельным тестом не покрыт) |
| C | UI access key: один SHA-256 | Argon2id через **ту же** `dmc_vault::ownership::credential` (без второй реализации); constant-time; единая ошибка для обоих факторов; оба фактора всегда проверяются. Миграция: v1-файл принимается (constant-time SHA-256) и **после первого успешного логина** переписывается в v2 | Офлайн-перебор access key по украденному файлу дорогой (Argon2id) | `authentication::tests::access_key_stored_as_argon2id_verifier_with_owner_only_file`, `legacy_sha256_file_upgrades_on_login_and_mode_is_tightened` |
| D | TOTP secret / UI-auth файл с режимом по умолчанию (часто 0644) | Запись через `secure_fs::write_secret_file` (0600 **с момента создания**, temp→fsync→rename→fsync dir); при загрузке более широкий режим ужесточается до 0600. Также все прочие копии: dev UI credentials, dev master, KeyPass, keyrings, identities, delegations | Другие локальные пользователи не читают секреты; нет окна write-then-chmod | `secure_fs::tests::*`, тесты C, `serve::tests::*` |
| P0.5 | Секреты в памяти / Debug | redacted `Debug`: `AuthFile`, `SetupBeginResponse`, `DevUiCredentials`, `DevoInitResult`, `UiAuthResetResult`, `UnlockSink`; zeroize-on-drop: `Credential` (пароль), `AuthSession.unlock_binding_key`, буферы hex/JSON секретных файлов, KeyPass-пароль CLI, plaintext-буферы миграции | Секреты не попадают в `{:?}`/логи/паники через эти типы | `secret_bearing_types_redact_debug`, существующие redaction-тесты |

Аудит логирования: новые модули не логируют; `dmc-observability` уже санитизирует события
(`sanitize`, `assert_no_secrets_*`). Сообщения ошибок не содержат ключей/паролей.
`secrecy` не вводился: `zeroize` уже в зависимостях и закрывает те же типы.

## 16. SQL plane encryption (design + explicit migration)

### Что защищается / что остаётся видимым

| Защищается (sealed, AES-256-GCM, ключ владельца строки) | Остаётся видимым (queryable metadata) |
|---|---|
| значения **явно выбранных** колонок (`TEXT`/`BLOB` → `BLOB`) | схема, имена таблиц/колонок, типы |
| | все незащищённые колонки, включая owner-колонку (subject id) |
| | row ids, количество строк, факт `NULL`, длина значения (+62 байта) |
| | timestamps/sequence событий, состав транзакций |
| | индексы/статистика незащищённых колонок |

Привязка: object id = `sql/{table_id}/{row_id}/{column_id}` в AAD — перенос значения в
другую строку/колонку/таблицу ломает расшифровку (тест row-swap).

### Индексы и операции над защищёнными колонками

| Операция | Статус | Почему |
|---|---|---|
| exact equality | ❌ на сервере | random nonce → одинаковые значения дают разный ciphertext. Детерминированное шифрование (SIV/HMAC-blind index) даёт равенство ценой утечки частот — не реализовано без отдельного обоснования |
| range / ORDER BY | ❌ | требует OPE/ORE — сильная утечка, не реализуется |
| full-text | ❌ | searchable encryption не реализуется самостоятельно |
| UNIQUE / PK | ❌ запрещено | миграция отказывается, если колонка в PK или индексе |
| aggregation | только `COUNT`, `IS NULL` | значения непрозрачны для сервера |
| фильтрация/сортировка | на клиенте после расшифровки | |

Миграция **отказывается** (а не ломает молча семантику), если колонка проиндексирована
или входит в первичный ключ.

### `dmc encrypt-migrate` (`dmc_materialized::protect::encrypt_migrate`)

```
dmc encrypt-migrate --source DATA --target NEW --layout ops|flat \
    --table public.notes --column body --owner-column owner \
    --identities runtime/ownership/identities.json --keyring-dir runtime/ownership/keyring \
    --owner alice --owner bob          # пароль каждого владельца запрашивается
    [--purge-source]
```

1. Валидация спецификации (тип, PK, индексы, owner-колонка).
2. Источник открывается обычным recovery-путём `StateMaterializer` (сервер должен быть
   остановлен); новых plaintext-копий при этом не создаётся.
3. Staging `.encrypt-migrate-staging-<target>` получает: историю каталога (защищённые
   колонки перетипированы в `BLOB`) и **только живые строки**; каждое защищённое значение
   запечатывается `ValueSealer` (`KeyManagerSealer`: нужен ключ владельца строки).
   Plaintext существует только в источнике и в RAM (zeroized буферы) — **в staging его нет**.
4. Нет ключа хотя бы одного владельца → abort, staging удаляется, ничего не публикуется.
5. `protection_manifest.json` (колонки, исходный тип, формат `avsr-v1`, схема object id,
   счётчики), повторное открытие и проверка, что каждая ячейка — `NULL` или sealed для
   своего владельца; fsync всех файлов и каталогов.
6. Commit point: `rename(staging → target)` + fsync родителя.
7. Crash до rename → staging удаляется при следующем запуске (`recover_encrypt_migration`);
   после → target полный. Источник не трогается.
8. Повторный запуск идемпотентен (уже sealed значения сохраняются как есть).
9. Удаление plaintext-источника — **отдельный явный шаг** (`--purge-source` /
   `purge_source`), только при валидном manifest в target.

Ограничения миграции: история MVCC не переносится (только live rows); старые бэкапы,
restore-каталоги и любые копии источника **остаются plaintext** и должны уничтожаться
отдельно; удаление файлов **не гарантирует** физического стирания на SSD / CoW /
журналируемых ФС. Существующие данные не переинтерпретируются молча: тип колонки меняется
явно, есть manifest и format id.

## 17. Identity mapping audit (P2)

| Вопрос | Ответ |
|---|---|
| Где хранится `subject_id → name` | `runtime/ownership/identities.json` (`AuthService::save_identities`): имена, `IdentityId`, `subject_id`, tenant, Argon2id-verifier'ы. 0600. |
| Кто может прочитать | владелец ОС-аккаунта процесса, root/host admin, любой с копией data dir или бэкапа |
| Входит ли в backup | да: секция `runtime` локального бэкапа и BackupSAS-архива |
| Входит ли в vault snapshot | нет (отдельный файл, не под Master Key) |
| Может ли DBA восстановить маппинг | **да** |
| Другие источники связи | `delegations.json` (граф subject→subject), owner-колонки SQL (subject id), пути `owned/<subject>/…` в WAL |

Варианты (выбор — после отдельного design review):
* **A. Encrypted identity mapping** — маппинг под ключом, недоступным DBA; но login должен
  найти запись по имени ⇒ нужен blind index (HMAC(имени)) — DBA с ключом индекса снова
  связывает; выигрыш ограничен.
* **B. External IdP** (OIDC и т.п.) — AvroraCore видит только pairwise pseudonymous `sub`;
  маппинг на человека — у IdP. Сдвигает доверие, не устраняет.
* **C. Client-held mapping** — клиент знает свой subject id (и ключи); сервер аутентифицирует
  по subject-ключу без имени. Совместим с client-side crypto (§18), сильнейший вариант.

## 18. Подготовка к operator-blind (без изменения протокола)

```
Сейчас:  Client → AvroraCore → KeyManager.seal → EncryptedStorage.put → storage
Готово:  Client(seal) → ciphertext → EncryptedStorage.put_sealed → storage   (без ключей)
         storage → ciphertext → Client(open_record)
```
* Формат `SealedRecord`/`KeyEnvelope` не зависит от того, где выполнено шифрование.
* `EncryptedStorage::put_sealed` принимает внешне запечатанные записи: проверяет только
  то, что проверяемо без ключа (живая сессия, identity владеет subject, tenant, header,
  монотонная версия). Тест `externally_sealed_records_are_stored_without_server_keys`:
  сервер хранит, не держит ключей и не может расшифровать.
* SQL-путь: `ValueSealer` — тот же шов; клиентская реализация заменит `KeyManagerSealer`.
* **Operator-blind не заявляется**, пока шифрование/расшифровка фактически не вынесены из
  процесса БД и пароль не перестал передаваться серверу.

## 19. Invariant checklist (v1.1)

| # | Инвариант | Статус / где обеспечено |
|---|---|---|
| 1 | No admin-decrypt API | ✅ нет такого API; `administrator_has_no_cryptographic_authority` |
| 2 | No master-key export | ✅ для subject-ключей; Master Key event plane показывается один раз при создании (существующий контракт) |
| 3 | No plaintext fallback | ✅ все пути возвращают security error |
| 4 | No key generation when expected key missing | ✅ `KeyringNotFound`, `missing_or_corrupt_key_material_fails_closed` |
| 5 | KeyManager — единственный unwrap subject-ключей в сервере | ✅ (vault `KeyTree` остаётся authority для Master-Key-домена event plane — это не ключи владельцев) |
| 6 | Production does not persist unlock material | ✅ `dmc serve` / `avrora serve` (§15 B1/B2) |
| 7 | KEK not exportable | ✅ `compile_fail` doctests |
| 8 | Auth secrets not stored plaintext | ✅ пароли/access key — Argon2id verifier; ⚠️ TOTP secret — по природе (0600) |
| 9 | Secrets not in Debug/Display/logs | ✅ для перечисленных типов (§15 P0.5) |
| 10 | Missing/corrupt keyring fails closed | ✅ |
| 11 | Ownership isolation intact | ✅ `ownership_security.rs` |
| 12 | Backup guarantees intact | ✅ `ownership_storage.rs`, `ownership_sql_storage.rs` |
| 13 | SQL migration explicit & crash-safe | ✅ §16 |
| 14 | No silent reinterpretation | ✅ явный retype + manifest + отказ для PK/индексов |
| 15 | No regression | см. итоговый прогон workspace |

## 20. Operator-Blind Client Encryption (v2)

> **Итог: `OPERATOR_BLIND_NOT_PROVEN`** для системы в целом — см. §20.12 и §21.15. Для
> эталонного пути (DMC IPC SQL + key-management API по сети, §21) свойства из §20.11
> доказаны тестами, кроме сканирования памяти серверного процесса.

Два режима **не смешиваются** ни в ключах, ни в формате, ни в claims:

| | SERVER_OWNED (§2–§19) | CLIENT_OWNED (этот раздел) |
|---|---|---|
| Кто держит KEK/DEK | процесс AvroraCore (`KeyManager`) во время сессии | только устройство клиента |
| Что видит сервер | пароль при логине, ключи и plaintext активной сессии | ciphertext, public keys, HPKE-envelopes |
| Формат записи | SealedRecord v1 (или v2, domain SERVER) | SealedRecord **v2, domain CLIENT** |
| Identity | `KeyCustody::Server`, server keyring | `KeyCustody::Client`, keyring на сервере **нет** |
| Operator-blind | нет | см. §20.11–20.12 |

### 20.1 Trust boundary

| Trusted | Untrusted |
|---|---|
| пользователь/устройство с AvroraClient (`dmc-client-crypto`) | процесс AvroraCore, DBA, host admin |
| device root secret и recovery code | backup operator, backup storage |
| | диск, WAL, snapshots, restore-каталоги |
| | транспорт (за пределами TLS/IPC) |

Модель противника — **confidentiality против злонамеренного сервера**. Целостность и
доступность сервер нарушить может (удалить, не отдать, откатить, подменить public key при
первом контакте) — это **не** защищается, кроме дешёвых клиентских проверок (§20.9).
Внешний KMS/IdP не используется.

### 20.2 Key ownership (откуда client берёт cryptographic authority)

```
device root (32 B, генерируется на устройстве, никогда не передаётся)
  └─ HKDF("avrora/client-kem/v1") → HPKE DeriveKeyPair → X25519 (sk на устройстве, pk на сервер)
        │ HPKE base mode (RFC 9180, crate `hpke` 0.12): DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/AES-256-GCM
        ▼
     DEK v1, v2, … (random) ── HPKE-envelope → хранится на сервере (OwnDataKey)
        ▼
     SealedRecord v2 (AES-256-GCM, тот же код `dmc_vault::ownership::record`)
```

* Login-пароль **только аутентифицирует** (`enroll_client_owner`): из него ничего не
  выводит клиентские ключи; ключ, который сервер вычисляет при логине, сразу зануляется
  и ничего не открывает (тест: `KeyManager.enroll/open_session` отказывают).
* Цепочка `Client → Server KeyManager → DEK → Client` **отсутствует**: на сервере нет
  ни private key, ни кода, который открывает client envelopes (`dmc-client-crypto` не
  линкуется в серверные крейты; сервер хранит `ClientPublicKey`/`ClientKeyEnvelope` из
  `dmc_vault::ownership::client` — только парсинг и проверки структуры).
* HPKE используется **только** для key encapsulation (хранение собственных DEK, async
  delegation), не для каждой записи. Аудит `rust-hpke` третьей стороной мной не подтверждён;
  крейт реализует RFC 9180 и проверяется его test vectors.

### 20.3 Client encryption API

```rust
let (id, recovery) = ClientIdentity::generate(subject, tenant);   // на устройстве
let (ring, env) = ClientKeyring::create(id, &mut state)?;         // env → сервер
let sealed = ring.seal(object_id, record_version, plaintext)?;    // → сервер
let plain  = ring.open(owner, object_id, &sealed)?;               // ← сервер
```
Для SQL: `sql_blob_literal(&sealed)` → `X'…'`, ответ — `\x…` → `parse_sql_blob_cell`;
object id `sqlc/{table}/{row_key}/{column}` связывает значение со строкой/колонкой (AAD).

### 20.4 Server storage / API

* `EncryptedStorage::put_sealed` проверяет без plaintext: формат/алгоритм/версия, owner в
  заголовке, **домен ключа = custody владельца** (CLIENT ⇒ v2/CLIENT), объект, монотонную
  record version, сессию/identity/tenant. Целостность ciphertext (AEAD) сервер проверить
  не может — нет ключа; её проверяет клиент при `open`.
* `get_sealed` отдаёт ciphertext только владельцу или grantee с живым grant.
* `ClientKeyDirectory` (`runtime/ownership/client/client-directory.json`, 0600): public keys
  (неизменяемые после регистрации), envelopes (append-only по версии), grants.
* Нет API `get_dek`/`get_kek`/`admin_get_key`; `KeyManager` отказывает client-custody.

### 20.5 SQL protected values

Сервер никогда не видит plaintext защищённой колонки: клиент запечатывает до отправки и
открывает после получения. Сервер хранит `BLOB`. Ограничения запросов прежние (§16):
**ciphertext equality ≠ plaintext equality**; range/ORDER BY/LIKE/full-text/UNIQUE по
значению не поддерживаются; searchable/deterministic encryption не изобретается. SQL-движок
не *навязывает* sealed-формат необъявленным колонкам; для колонок, объявленных через
`SealedColumnDeclare`, plaintext отклоняется (§21.5).

### 20.6 Delegation (async)

Alice берёт public key Bob у сервера, проверяет его **TOFU-пином** (или out-of-band
fingerprint `fingerprint_display`), создаёт grant и HPKE-envelopes своих DEK на ключ Bob.
Alice может уйти offline; Bob позже забирает envelopes. Private keys не покидают устройств,
сервер хранит только envelopes. Revocation: grant и envelopes удаляются на сервере, но
**ключи, уже скачанные Bob, не отзываются криптографически** — новые данные защищает только
ротация DEK у Alice (+ client-side re-encryption старых при необходимости).
Ограничение TOFU: подмена ключа сервером при *первом* контакте без сверки fingerprint не
обнаруживается.

### 20.7 Key rotation

`new_data_key` → новая версия DEK, envelope на сервер; `reencrypt` = open старым +
seal новым **на клиенте**, сервер получает только новый ciphertext. Старые версии остаются
читаемыми. Клиент хранит `highest_own_version` и отказывается загружаться, если сервер
отдаёт меньше версий (`Rollback`, fail closed).

### 20.8 Backup / restore

Directory и ciphertext входят в секцию `runtime` бэкапа и в BackupSAS-архив; restore
возвращает ciphertext; расшифровать может только клиент с device root. Тест: атакующий с
восстановленной БД + бэкапом + Master Key + `cap_root` получает только domain-CLIENT
ciphertext.

### 20.9 Recovery / потеря ключа

* Recovery code (= device root, с checksum) показывается один раз; `from_recovery`
  восстанавливает identity на новом устройстве; envelopes берутся с сервера.
* Второе устройство = импорт recovery code (отдельных device keys пока нет).
* Потеря устройства **и** recovery code ⇒ **безвозвратная потеря** CLIENT_OWNED данных.
  Серверного recovery/backdoor нет (fail closed).
* Device file `identity.json` хранит root в открытом виде с правами 0600 — защищён ровно
  настолько, насколько защищено устройство (OS keychain/TPM — следующий шаг).

### 20.10 Metadata leakage (CLIENT_OWNED)

Видно серверу: subject ids, object ids/ключи хранения, record/key versions, размеры
(+63 байта), timestamps, количество записей, граф делегирования, факт логина, SQL-текст
(кроме значений `X'…'`), паттерны доступа и трафика. Маппинг identity↔subject остаётся у
сервера (§17).

### 20.11 Acceptance criteria — доказательства

| Критерий | Статус | Тест |
|---|---|---|
| DB operator cannot decrypt | ✅ | `client_owned_storage.rs` |
| Host admin без client key cannot decrypt (данные на диске/в бэкапах) | ✅ | там же (`assert_server_blind`) |
| Backup operator cannot decrypt | ✅ | там же |
| Backup содержит только ciphertext | ✅ | там же + `client_owned_network.rs` |
| Master Key не открывает CLIENT_OWNED | ✅ | там же |
| `cap_root` не открывает CLIENT_OWNED | ✅ | там же |
| Server memory без plaintext после обработки | ⚠️ **не доказано сканированием памяти**; структурно plaintext серверу не передаётся (capture транспорта) | `client_owned_network.rs` |
| Server logs без plaintext | ✅ для SQL-пути (memory sinks) | `client_owned_network.rs` |
| Server API не раскрывает client key material | ✅ сервер его не имеет | `client_owned_storage.rs` |
| Plaintext не передаётся по сети | ✅ DMC IPC SQL (с negative control) | `client_owned_network.rs` |

### 20.12 Вывод и ограничения

**`OPERATOR_BLIND_NOT_PROVEN`** — потому что:
1. проверен один транспорт (DMC IPC SQL); control plane, HTTP, pgwire не проверены;
2. ~~API key directory только in-process~~ — закрыто в §21 (DMC IPC);
3. память серверного процесса не сканировалась;
4. TOFU не защищает от подмены ключа при первом контакте;
5. server-owned режим (§2–§19) по-прежнему не operator-blind.

Остаточные риски: компрометация клиента / дамп памяти клиента (полный доступ к его
данным); потеря ключа = потеря данных; offline guessing паролей не касается CLIENT_OWNED
ключей (они не выводятся из пароля), но login-пароль по-прежнему перебирается по verifier;
утечка метаданных и трафика (§20.10); SQL query text; ретроспективный отзыв делегирования
невозможен; миграция существующих данных в CLIENT_OWNED не автоматизирована (plaintext уже
был у сервера — нужна явная клиентская перезапись через SQL).

## 21. CLIENT_OWNED key management по сети (Stage 4, эталонный транспорт DMC IPC)

> **Итог остаётся `OPERATOR_BLIND_NOT_PROVEN`** (§21.15). Эталонный путь DMC IPC пройден
> полностью, включая key-management API; control plane / HTTP / pgwire — нет. Статус
> `REFERENCE_PATH_PROVEN` по условиям задачи присваивается только после полного DoD, поэтому
> не заявляется.

### 21.1 Протокол (DMC IPC, postcard; новые варианты добавлены в конец enum)

| Request (`ControlRequest`) | Response | Кто может | Что передаётся |
|---|---|---|---|
| `ClientKeyRegister{session_id,key}` | `ClientKeyAck{key_id,key_version}` | владелец subject, custody = Client | `ClientPublicKey` (v1) |
| `ClientKeyRotate{session_id,key}` | `ClientKeyAck` | владелец | `ClientPublicKey` (active+1) |
| `ClientKeyGet{session_id,subject}` | `ClientKeys{keys}` | любой Client-subject того же tenant | `ServerStoredPublicKey` (все версии, ACTIVE/RETIRED) |
| `KeyEnvelopePut{session_id,envelope}` | `KeyEnvelopeAck` | только owner DEK | `ClientKeyEnvelope` (HPKE) |
| `KeyEnvelopeGet{session_id}` | `KeyEnvelopes{envelopes}` | получатель (свои + делегированные при живом grant) | `ClientKeyEnvelope` |
| `GrantCreate/GrantList/GrantRevoke` | `GrantAck{changed}` / `Grants{grants}` | owner (list: owner или grantee) | subject ids, сроки |
| `SealedColumnDeclare{session_id,schema,table,column,owner_column}` | `SealedColumnAck` | SQL `CREATE` на таблицу, vault unlocked | имена |

Ни один вариант не несёт private key, root, recovery code, plaintext DEK или plaintext
значения: это проверяется исчерпывающим destructuring в
`test/tests/client_owned_type_boundary.rs` (новое поле в этих вариантах ломает компиляцию
теста). Ошибки: нет/просрочена сессия → `SessionInvalid`; чужой subject/tenant, не-Client
identity, нет grant, неверный fingerprint → `AuthorizationDenied`; конфликт версий/повтор →
`InvalidRequest`; неверная декларация колонки → `ConstraintViolation`.

### 21.2 Что сервер проверяет и чего не может проверить

Проверяет (без единого секрета): сессию, активность identity, `custody = Client`, совпадение
subject/tenant, структуру ключа/envelope (`validate`), что envelope запечатан на **ACTIVE**
зарегистрированный ключ получателя (по fingerprint), что делегированный envelope имеет
живой grant, неизменяемость/монотонность версий.
Не может проверить: что HPKE-ciphertext действительно открывается (нет private key — и не
должен), что public key «принадлежит» человеку (это задача клиента — §21.3).
Сервер **никогда** не объявляет fingerprint «доверенным»: поле `fingerprint` в
`ServerStoredPublicKey` — подсказка, клиент и CLI его пересчитывают.

### 21.3 TOFU и внешняя проверка fingerprint

* `ClientState::check_or_pin(key)`: первый контакт → `PinnedOnFirstUse`; тот же ключ →
  `Matches`; другой ключ той же или большей версии → **`KeyChanged` (отказ по умолчанию,
  авто-принятия нет)**; меньшая версия, чем закреплённая → `KeyRollback`.
* `pin_verified(key, expected_display)` — принять новый ключ только после сверки
  fingerprint, полученного вне сервера; не позволяет откатиться на старую версию.
* CLI: `avrora-key fingerprint --identity <identity.json>` (на устройстве владельца) и
  `avrora-key fingerprint --public-key <key.json>` (ключ, полученный от сервера; поле
  `fingerprint` сервера игнорируется, значение пересчитывается). Пользователи сверяют две
  строки по независимому каналу.
* **Ограничение (не скрывается):** если сервер подменил ключ при *первом* контакте и
  пользователи не сверили fingerprint, подмена не обнаруживается. TOFU даёт не больше, чем
  «тот же ключ, что в первый раз».

### 21.4 Revocation — точная семантика

`GrantRevoke` удаляет grant и все envelopes owner→grantee на сервере; после этого сервер
не отдаёт grantee ни envelopes, ни новые версии. **Revocation не уничтожает доступ
мгновенно:** DEK, которые grantee уже скачал, продолжают открывать ciphertext, который у
него уже есть или который он получит. Защита новых данных = ротация DEK у owner
(`new_data_key`) + при необходимости client-side `reencrypt`; новые версии не
делегируются отозванному. Тест `client_owned_key_api.rs` проверяет обе половины («Bob
keeps old DEK» и «new DEK version not shared»).

### 21.5 Защита от plaintext injection (sealed columns)

* `SealedColumnDeclare` регистрирует правило `{table_id, column_id, owner_column_id}` в
  `rows/sealed_columns.json` (атомарная запись). Допустимо только для `BLOB`-колонки, не
  PK и не индексированной; owner-колонка — `TEXT`.
* Каждая мутация (`INSERT`/`UPDATE`, в т.ч. в транзакции) проходит guard в
  `StateMaterializer::mutate` **до** записи: `NULL` допускается; иначе значение должно
  разбираться как SealedRecord **v2, domain CLIENT**, owner в заголовке = значение
  owner-колонки. Plaintext, v1/SERVER-domain, усечённые записи, чужой owner — отказ
  `ConstraintViolation`. Сервер **ничего не расшифровывает** (и не может).
* Миграции существующих данных автоматически не выполняются; декларация не трогает уже
  сохранённые строки.
* **Ограничение (E6 матрицы):** guard проверяет формат, домен и owner, но не AEAD (нет
  ключа) и не связывает owner-колонку с пишущей сессией. Другой пользователь с правом
  `INSERT` может записать строку, *приписанную* Alice, с корректным заголовком и мусорным
  телом. Это ничего не раскрывает; Alice обнаруживает подделку (AEAD open падает).

### 21.6 Ротация KEM-ключа по сети и rollback

`ClientKeyring::rotate_identity_key` → новый ключ версии n+1 (HKDF info
`avrora/client-kem/v1/kv{n}` из того же root) и envelopes всех своих DEK на него;
`ClientKeyRotate` делает прежний ключ `RETIRED` (хранится — старые envelopes остаются
открываемыми: `open_envelope` выбирает версию по fingerprint). Партнёры видят
`KeyChanged` до явной сверки; попытка подсунуть старый ключ после принятия нового →
`KeyRollback`. Сокрытие сервером новой версии DEK → `Rollback` (клиентский пол версий).

### 21.7 Backup / restore на новом хосте

Бэкап содержит отдельный компонент `ownership` (`BackupFileRole::Ownership`, digest в
manifest): весь каталог `ownership/` — `client/client-directory.json` (public keys,
envelopes, grants) и, если он записан, `identities.json` (hashed credentials, subject ids;
пишется `AuthService::save_identities`, SQL-сервер сам его **не** пишет — в тесте это делает
оператор при enroll). `restore` + `recover` переносят его в live-дерево. Тест: новый хост, оператор с Master Key и полными SQL-правами получает только
ciphertext; Alice на новом хосте скачивает envelopes и расшифровывает локально; правило
sealed-колонки переживает restore.
**Ограничение:** SQL-сервер пока не персистирует `AuthService`/SQL grants (было до этой
работы); на новом хосте оператор заново выдаёт SQL-grants. Identities восстанавливаются из
компонента `ownership`.

### 21.8 Разделение серверной памяти (type-level), а не сканирование памяти

Доказано тестами (`client_owned_type_boundary.rs`):
1. от `dmc-server`, `dmc-core`, `dmc-ops`, `dmc-protocol`, `dmc-security`, `dmc-vault`,
   `dmc-materialized`, `dmc-backup`, `dmc-storage`, `dmc-ipc`, `dmc-pgwire` по обычным
   (не dev) зависимостям `dmc-client-crypto` недостижим (с проверкой, что парсер видит
   реальные зависимости);
2. в `Cargo.lock` `hpke`/`x25519-dalek` используются только `dmc-client-crypto` (и тестами);
3. key-management сообщения содержат только public/wrapped типы.
Private key — newtype `ClientPrivateKey` (только в `dmc-client-crypto`, без `Serialize`,
redacted `Debug`); root — `Zeroizing<[u8;32]>`.
**Не доказано:** отсутствие секретов в памяти серверного процесса сканированием (core dump
не снимался). Аргумент структурный: серверу секреты не передаются (capture) и у него нет
кода, способного их вычислить.

### 21.9 Network capture (эталонный путь)

`test/tests/client_owned_key_api.rs`: весь трафик (регистрация/получение/ротация ключей,
envelopes, grants, revoke, SQL запись/чтение, backup) идёт через прозрачный proxy, который
пишет оба направления. Секреты вычисляются **независимо от клиентского API** (root из
recovery code → HKDF → HPKE DeriveKeyPair; DEK — `single_shot_open` каждого envelope) и
ищутся в raw/hex/HEX: roots, все версии X25519 private keys, все DEK, recovery codes,
plaintext. Скан: wire, все файлы `data_root` (включая backup), log/audit sinks, после
restore — wire нового хоста и все файлы restore. Negative control (незащищённая колонка)
обязан быть виден; login-пароль встречается на wire ровно столько раз, сколько было
`Authenticate`. Сервер, как и `dmc serve`, обслуживает одно соединение за раз — тест
открывает соединение на каждый шаг.
Ограничение метода: ищутся известные кодировки; это не доказательство против произвольного
преобразования (которое серверу без секрета недоступно — §21.8).

### 21.10 Attack matrix (`test/tests/client_owned_attack_matrix.rs`)

| # | Атака | Результат |
|---|---|---|
| A1/A2 | forged / logged-out session | `SessionInvalid` |
| A3/A4 | оператор (server custody + Master) читает envelopes / регистрирует ключ | `AuthorizationDenied` |
| A5 | отключённая identity продолжает пользоваться ранее выданной сессией (SQL и key API) | `SessionInvalid` (регрессия F7, `client-owned-authentication.md` §2.1) |
| B1/B6 | Bob регистрирует/ротирует ключ под subject Alice | `AuthorizationDenied` |
| B2 | тихая замена ключа повторной регистрацией | `InvalidRequest` |
| B3–B5 | первая регистрация v2, пропуск версии, ротация тем же ключом | `InvalidRequest` |
| B7 | cross-tenant lookup ключа | `AuthorizationDenied` |
| C1 | Bob кладёт envelope с owner = Alice | `AuthorizationDenied` |
| C2/C8 | делегированный envelope без grant / с истёкшим grant | `AuthorizationDenied` |
| C3 | envelope на ключ, не являющийся ACTIVE ключом получателя | `AuthorizationDenied` |
| C4 | повтор/перезапись версии envelope | `InvalidRequest` |
| C5 | grant себе / subject без ключа / другому tenant | `AuthorizationDenied` |
| C6/C7 | чужие envelopes; envelopes после истечения grant | не отдаются |
| C9 | оператор управляет grants | `AuthorizationDenied` |
| D1 | сервер портит envelope (ciphertext, key_version, owner) | клиент: `Hpke` / `Ownership` |
| D2 | сервер подменяет ключ после первого контакта | клиент: `KeyChanged` |
| E1/E2 | декларация на не-BLOB / PK | `ConstraintViolation` |
| E3/E4 | INSERT/UPDATE plaintext, чужой owner, v1/SERVER record, усечённая запись | `ConstraintViolation` |
| E5 | оператор меняет owner-колонку запечатанной строки | `ConstraintViolation` |
| E7 | plaintext INSERT внутри `BEGIN … COMMIT` | `ConstraintViolation` на `COMMIT`, строки нет |
| E6 | корректно оформленная подделка, приписанная Alice | **принимается** (ограничение §21.5), Alice обнаруживает |

Каждая отклонённая key-операция не меняет `client-directory.json` (проверяется байтово).

### 21.11 Формальное security property и чем оно подтверждено

**P1 (конфиденциальность CLIENT_OWNED против сервера).** Пусть клиент A честен, его
устройство не скомпрометировано, транспорт — DMC IPC, и публичные ключи партнёров A
приняты либо после сверки fingerprint, либо до любой подмены сервером. Тогда никакая
последовательность байт, доступная серверной стороне — wire в обе стороны, все файлы под
`data_root` (WAL, row store, snapshots, backups, restore), log/audit sinks, ответы любой
серверной identity, включая оператора с Master Key, `cap_root` и полными SQL-правами, —
не содержит plaintext значений A, root A, ни одной версии private key A, ни одной версии
DEK A и recovery code A (в raw/hex/HEX).
Подтверждение: `client_owned_key_api.rs` (все перечисленные артефакты, независимое
вычисление секретов, negative control), `client_owned_network.rs` (SQL путь),
`dmc-core/tests/client_owned_storage.rs` (Master/`cap_root`/backup),
`client_owned_type_boundary.rs` (у сервера нет кода для private keys).
Не покрыто: память серверного процесса, остальные транспорты, метаданные (§20.10).

**P2 (делегирование).** Grantee B получает DEK версии v владельца A, только если A сам
запечатал её на ACTIVE ключ B, проверенный TOFU/fingerprint, и grant жив. После revoke
сервер не отдаёт B envelopes A; версии DEK, созданные после revoke, B недоступны. DEK,
уже полученные B, остаются у B (явное ограничение). Подтверждение:
`client_owned_key_api.rs`, `client_owned_attack_matrix.rs` (C2–C8).

**P3 (отсутствие тихой подмены).** Клиент не использует ключ партнёра, отличный от
закреплённого, без явной сверки (`KeyChanged`), не принимает откат версии ключа
(`KeyRollback`) и не загружает keyring, если сервер скрыл известную версию DEK
(`Rollback`). Подтверждение: `client_crypto.rs`, `client_owned_key_api.rs`, D2 матрицы.

### 21.12 Транспорты

| Transport | Auth | Key-mgmt API | CLIENT_OWNED write/read | Capture + scanner | Статус |
|---|---|---|---|---|---|
| DMC IPC (Unix socket) | `AuthService` sessions | ✅ | ✅ | ✅ | **пройден** |
| Control plane (`dmc-ops` / AvroraClient) | event-plane identities, без CLIENT_OWNED subjects | ❌ | ❌ | ❌ | не начат |
| HTTP adapter (`http_server::run_with_runtime`) | отдельный event-plane `Runtime` | ❌ | ❌ | ❌ | не начат |
| pgwire (`dmc-pgwire`) | **нет**: `AuthenticationOk` отправляется безусловно, startup params игнорируются (`crates/dmc-pgwire/src/server.rs`) | ❌ | ❌ | ❌ | **заблокирован** — сначала нужна аутентификация |

Транспорты не подключались одновременно: по правилу задачи следующий начинается только
после полного прохождения предыдущего.

### 21.13 Исправленная по пути ошибка (вне ownership, но влияла на безопасность отказа)

`dmc_sql_exec::execute_plan` перемещал весь `ExecutionContext` в `Rc` и при любой ошибке
исполнителя (`?`) не возвращал его: после первой неудачной команды (дубликат PK, отказ
guard) сервер терял journal и catalog до перезапуска. Теперь контекст возвращается на всех
путях; регрессионный тест `phase6_atomicity.rs::failed_statement_keeps_session_journal_and_catalog`
падает без исправления.

### 21.14 Остаточные риски

Компрометация клиентского устройства; TOFU первого контакта без сверки fingerprint;
метаданные и граф делегирования; уже скачанные grantee DEK; подделки, приписанные чужому
owner (обнаруживаются клиентом, не сервером); память серверного процесса не сканировалась;
SQL grants и identities не персистируются SQL-сервером автоматически; pgwire без аутентификации; `identity.json`
хранит root с правами 0600, без OS keychain/TPM; аудит `rust-hpke` третьей стороной не
подтверждён.

### 21.15 Статус

**`OPERATOR_BLIND_NOT_PROVEN`.** Причины: control plane, HTTP и pgwire не пройдены (pgwire
не аутентифицирует вовсе); память серверного процесса не сканировалась; первый контакт
TOFU не защищён без внешней сверки. `REFERENCE_PATH_PROVEN` не заявляется, т.к. по условию
требует полного DoD.

## 14. Test map

| Требование | Тест |
|---|---|
| valid / invalid / revoked / disabled | `dmc-security/tests/ownership_security.rs::auth_valid_invalid_disabled_revoked` |
| authentication ≠ key access | `authentication_alone_does_not_unlock_keys` |
| Alice↔Bob isolation, raw ciphertext swap | `owner_isolation_matrix` |
| tenant isolation | `tenant_isolation` |
| delegated read / revoke | `delegated_read_and_revocation` |
| tamper / wrong key / wrong context | `ciphertext_tamper_wrong_key_wrong_context`, `dmc-vault ownership::record::tests` |
| administrator isolation | `administrator_has_no_cryptographic_authority` |
| rotation + restart | `rotation_old_readable_new_version_and_survives_restart` |
| destroy only unreferenced | `retired_key_destroyed_only_when_unreferenced` |
| crash during rotation | `crash_between_rotation_steps_is_recovered` |
| password change, crash windows | `password_change_rewraps_without_reencryption_and_crash_windows` |
| fail closed | `missing_or_corrupt_key_material_fails_closed`, `dmc-core …::backup_without_keyrings_restores_ciphertext_and_fails_closed` |
| WAL / segments / compaction / snapshots / backup / archive / restore raw bytes | `dmc-core/tests/ownership_storage.rs::owned_data_stays_ciphertext_through_wal_snapshot_backup_restore` |
| SQL row store raw bytes (+ negative control) | `dmc-materialized/tests/ownership_sql_rowstore.rs` |
| envelope / keyring MAC / rollback / Debug redaction | `dmc-vault` `ownership::*::tests` |
| dev auto-unlock gate | `dmc-core control::dev::tests::dev_mode_requires_explicit_opt_in` |
| KEK non-export | `dmc-vault` doctests (`compile_fail`), `ownership::store::tests::subject_kek_not_reachable_from_vault_or_backup_bytes` |
| production unlock material | `dmc-cli serve::tests::*` |
| UI access key Argon2id + migration + 0600 | `dmc-security authentication::tests::*` |
| owner-only secret files | `dmc-vault secure_fs::tests::*` |
| SQL migration + backup/archive/restore raw bytes | `dmc-backup/tests/ownership_sql_storage.rs` |
| ciphertext-only write path | `ownership_security.rs::externally_sealed_records_are_stored_without_server_keys` |
| record format v2 / key domain | `dmc-vault ownership::record::tests::v2_client_domain_roundtrip_and_domain_separation` |
| client crypto (tamper, recovery, restart, rotation, rollback, TOFU, delegation) | `dmc-client-crypto/tests/client_crypto.rs` |
| CLIENT_OWNED vs Master Key + backup + cap_root, host compromise, async delegation/revoke | `dmc-core/tests/client_owned_storage.rs` |
| network reference path (capture proxy, logs, backup/restore) | `test/tests/client_owned_network.rs` |
| SQL `X'..'` literal | `dmc-sql-front lexer::blob_literal_tests` |
| key-management API по DMC IPC, TOFU, revoke, KEM rotation, injection, backup → новый хост, capture + scan | `test/tests/client_owned_key_api.rs` |
| attack matrix (sessions, registry, envelopes, grants, malicious server, sealed columns) | `test/tests/client_owned_attack_matrix.rs` |
| server crates не линкуют private-key код; wire без private material | `test/tests/client_owned_type_boundary.rs` |
| fingerprint CLI (сервер не может подсунуть fingerprint) | `dmc-client-crypto/tests/avrora_key_cli.rs` |
| `key_version` по умолчанию 1, 0 недопустим | `dmc-vault ownership::client::tests::key_version_defaults_to_one_and_zero_is_invalid` |
| failed SQL statement не ломает сессию | `dmc-sql-exec/tests/phase6_atomicity.rs::failed_statement_keeps_session_journal_and_catalog` |
