# Avrora Benchmark V1

> Baseline-измерения производительности, нагрузки и корректности AvroraCore **до каких-либо оптимизаций**.
> Production-код не изменялся. Все числа взяты из сырых записей
> `bench-results/v1/run-20261003/results.jsonl` (основной прогон) и
> `bench-results/v1/run-20261003-supp/results.jsonl` (дополнительные прогоны, см. §Methodology).
> Таблицы ниже сгенерированы/сверены скриптом `crates/dmc-bench/summarize_v1.py`.
> Обозначения: **NOT VERIFIED** — не удалось измерить/проверить; **NOT DIRECTLY COMPARABLE** — нет эквивалента в PostgreSQL.

## TL;DR

| Что | Результат (1 KiB записи, если не указано иное) |
|---|---|
| Avrora read (in-process KV) | **601 350 ops/s**, p99 2.5 µs — чтение из RAM, без расшифровки |
| Avrora write (durable, F_FULLFSYNC) | **42 ops/s**, p50 24 ms, p99 29 ms при 10 000 ключей; **деградирует с числом ключей** (96 → 27 ops/s на 0 → 18 000 ключей) |
| PostgreSQL write (сопоставимая durability, `fsync_writethrough`) | **259 ops/s** (×6.2 Avrora), 16 клиентов — **2 224 ops/s** (×65 Avrora) |
| PostgreSQL write (default macOS, без F_FULLFSYNC) | 31 547 ops/s — **иная, более слабая гарантия durability** |
| Каналы 1P→1C (closed loop) | produce 38.5 msg/s, deliver+ACK **25.9 msg/s**; потерь 0, дублей 0 |
| MAX_STABLE_MESSAGES_PER_SEC (1P→1C, 1 KiB) | **20 msg/s** (0.02 MB/s); 1P→10C — **< 5 msg/s** (не найдено устойчивой точки) |
| MAX_STABLE_CONNECTIONS (control plane, TLS 1.3 + mTLS) | **≥ 15 000** (ограничение генератора нагрузки, не сервера); пропускная способность при этом **~88–99 k req/s и не растёт** |
| Корректность | 5/5 сценариев PASS, включая **5 циклов реального SIGKILL**: 610 подтверждённых записей, **0 потерь, 0 дублей ACK** |
| Главный bottleneck | путь записи: ≥2 F_FULLFSYNC на запись + O(N) экспорт всего key tree на каждую запись + глобальный mutex runtime; у потребителя — 1 in-flight и O(backlog) скан журнала на каждый `consume` |

---

## Environment

| Параметр | Значение (из `env.json`) |
|---|---|
| Git commit | `0ec23fb0bcd8f86a3784dc2de22496057a4f0ee9` (working tree dirty: добавлены только benchmark-файлы и REPORT_V1.md) |
| OS | macOS 26.2 (25C56), Darwin 25.2.0 arm64 |
| CPU | Apple M4, 10 ядер (4 performance + 6 efficiency) |
| RAM | 16 GiB |
| Disk | встроенный SSD, APFS; свободно ~47.7 GB на момент запуска |
| Rust | rustc 1.98.0, cargo 1.98.0, **release** profile |
| PostgreSQL | 14.17 (Homebrew), отдельный кластер `initdb` во временном каталоге, порт 55432 |
| PG настройки | `shared_buffers=128MB, fsync=on, synchronous_commit=on, full_page_writes=on, wal_level=replica`; `wal_sync_method`: **`open_datasync`** (default) и **`fsync_writethrough`** |
| OS-лимиты | `kern.maxfilesperproc=61440` (RLIMIT_NOFILE поднят до 61440), `somaxconn=128`, эфемерные порты 49152–65535 (16 384), `maxprocperuid=2666`, TCP MSL 15 s |
| Avrora конфигурация | `Runtime` с vault, созданным `create_dev(false)` (единственный путь получения root-identity, см. Limitations); journal `FsyncPolicy::Always`, 1 партиция; control plane — отдельный процесс, TLS 1.3, mTLS после bootstrap устройства, вход access-key + TOTP |
| Нагрузка/время | warmup **5 s**, measurement **30 s** (соединения и security — 15 s); closed loop; см. Methodology |

---

## Methodology

**Инфраструктура (новая, только для бенчмарка):**
* `crates/dmc-bench/src/bin/bench_v1/` — бинарь `avrora-bench-v1` (подкоманды `env, storage, sql, pg, channel, trigger, connections, security, correctness, csv`);
* `crates/dmc-bench/run_v1.sh` — полный последовательный прогон (наборы не пересекаются по времени, чтобы не конкурировать за CPU/диск);
* `crates/dmc-bench/summarize_v1.py` — генерация таблиц;
* в `crates/dmc-bench/Cargo.toml` добавлены только зависимости бенчмарка (`tokio-postgres`, `libc`, клиентские крейты Avrora). Production-код **не менялся**.

**Измерение:**
* **Closed loop:** N воркеров, каждый выдаёт следующую операцию сразу после завершения предыдущей; латентность записывается только в окне измерения после warmup. Перцентили — точные по всем образцам.
* **Ресурсы:** macOS `proc_pid_rusage` каждые 200 мс: CPU (user+sys), RSS/phys_footprint, байты дисковых записей/чтений **процесса**. Для Avrora in-process — процесс бенчмарка (включает генератор нагрузки); для SQL Core и control plane — отдельный серверный процесс; для PostgreSQL — всё дерево процессов postmaster. RSS дерева PG суммируется по процессам и **завышен** (shared buffers учитываются в каждом backend).
* **Размеры записей:** 100 B, 1 KiB, 10 KiB, 100 KiB, 1 MiB. Датасет для чтения: `min(10 000, 256 MiB / size)` строк. Бюджет записи на сценарий 512 MiB (сценарий останавливается раньше, если бюджет исчерпан).
* **Одинаковые сценарии для Avrora и PG:** write (новые ключи), read (последовательно), random_read, random_rw (50/50 upsert/read), batch_write (100 записей), batch_read (100), concurrent_read/write (16 воркеров), mixed 80/20 (16).
  * **Семантическое различие batch:** у Avrora нет batch-API — «batch» = 100 последовательных `put_data` (100 коммитов). У PG — один multi-row `INSERT` (1 коммит). Это **разные гарантии**, сравнение показывает цену отсутствия batch-API.
  * **Семантическое различие транспорта:** Avrora KV измеряется **in-process** (embedded API, без сети); PostgreSQL — через unix socket (tokio-postgres, prepared statements). Отдельно измерены Avrora remote (TLS+mTLS) и SQL Core (IPC).
  * **Семантическое различие durability:** `std::fs::File::sync_all` на macOS = `F_FULLFSYNC` (сброс кэша накопителя). PostgreSQL по умолчанию на macOS (`open_datasync`) **не** выполняет F_FULLFSYNC. Поэтому PG прогнан дважды; честное сравнение durable-записей — с **`fsync_writethrough`**.
* **Каналы:** каждое сообщение содержит `(producer, seq)` → уникальный id и метку времени; потребитель проверяет уникальность, порядок по `sequence` и по `seq` производителя, считает retry/DLQ. Каждый потребитель — **отдельная подписка (fan-out)**. Undelivered = не получено за `drain_timeout` после остановки производителей.
* **MAX_STABLE (каналы):** open-loop производитель с целевой частотой R (5, 10, 20, 30, 40, … msg/s). Устойчиво, если: достигнуто ≥ 95 % R **и** backlog при остановке ≤ 1 s трафика **и** e2e p99 < 1 s **и** 0 undelivered после drain. Останов после двух подряд неустойчивых точек.
* **MAX_STABLE_CONNECTIONS:** ступени 10…15 000 постоянных соединений; на каждой — closed-loop запросы `GetPath` (Avrora) / `SELECT` по PK (PG) 15 s. Устойчиво, если: все соединения установлены, error rate < 0.1 %, p99 < 1 s. Между крупными ступенями пауза 32 s (истечение TIME_WAIT).
* **Crash/recovery:** отдельный дочерний процесс пишет и подтверждает (stdout `W id` после возврата `put_data`, `A id` после возврата `ack`); родитель шлёт **SIGKILL** через случайные 1.5–4 s; 5 циклов; затем проверка каждого подтверждённого id.

**Отклонения от запрошенной методики (явно):**
* warmup 5 s / measurement 30 s вместо 10–30 s / 60 s: полный прогон занял ≈ 2 ч 20 мин; с 60 s он превысил бы 5 ч. Для write-сценариев Avrora (≤ 100 ops/s) 30 s дают ≥ 800 образцов.
* SQL Core: датасет ограничен 16 MiB данных (`clamp(16 MiB/size, 50, 2000)` строк), т.к. `state_events.json` переписывается целиком при каждом коммите (O(n²) байт записи — десятки ГБ на 100 KiB строках).
* SQL Core клиент переподключается каждые 5 000 запросов: при достижении `max_requests_per_connection = 10 000` IPC-listener сервера **останавливается** (подтверждено, см. Bottlenecks). Обход задокументирован, а не скрыт.
* Дополнительный прогон (`run-20261003-supp`) после основного: (1) исправлен учёт CPU для PostgreSQL backend-процессов, созданных после старта монитора (в основном прогоне CPU PG в ramp соединений = 0 — **ошибка инструмента**, не PG); (2) повтор trigger-набора для проверки воспроизводимости; (3) 10P→1C с `drain_timeout = 1800 s`, чтобы отличить «не доставлено вовремя» от «потеряно».

**Воспроизведение:**
```bash
crates/dmc-bench/run_v1.sh bench-results/v1/<run>
python3 crates/dmc-bench/summarize_v1.py bench-results/v1/<run>/results.jsonl
```

---

## Storage Performance

### Avrora KV (in-process production API: AuthZ + AES-256-GCM + journal + F_FULLFSYNC)

| size | scenario | workers | records/s | MB/s | p50 | p95 | p99 | CPU % | peak RSS MB | disk write MB/s |
|---|---|---|---|---|---|---|---|---|---|---|
| 100B | write | 1 | 41.1 | 0.00 | 24.00 ms | 27.04 ms | 32.97 ms | 67.6 | 22 | 0.9 |
| 100B | read | 1 | 584 370 | 55.7 | 1.5 µs | 2.0 µs | 3.1 µs | 99.3 | 53 | 0 |
| 100B | random_read | 1 | 544 077 | 51.9 | 1.7 µs | 2.2 µs | 3.0 µs | 100.2 | 102 | 0 |
| 100B | random_rw | 1 | 79.0 | 0.01 | 32.5 µs | 27.96 ms | 40.39 ms | 67.8 | 106 | 0.8 |
| 100B | batch_write (100 puts) | 1 | 40.0 | 0.00 | 2 573 ms | 2 620 ms | 2 628 ms | 69.4 | 26 | 0.8 |
| 100B | batch_read (100 gets) | 1 | 655 368 | 62.5 | 150 µs | 171 µs | 196 µs | 100.8 | 28 | 0 |
| 100B | concurrent_read | 16 | 439 147 | 41.9 | 35.6 µs | 41.8 µs | 51.7 µs | 121.3 | 103 | 0 |
| 100B | concurrent_write | 16 | 36.4 | 0.00 | 443 ms | 461 ms | 466 ms | 72.0 | 184 | 0.8 |
| 100B | mixed 80/20 | 16 | 174.9 | 0.02 | 86.8 ms | 173 ms | 205 ms | 72.7 | 48 | 0.7 |
| 1KB | write | 1 | 42.0 | 0.04 | 23.96 ms | 25.93 ms | 29.11 ms | 66.5 | 35 | 1.0 |
| 1KB | read | 1 | 601 350 | 587.3 | 1.5 µs | 2.0 µs | 2.5 µs | 99.6 | 40 | 0 |
| 1KB | random_read | 1 | 550 358 | 537.5 | 1.7 µs | 2.2 µs | 2.8 µs | 100.6 | 45 | 0 |
| 1KB | random_rw | 1 | 80.0 | 0.08 | 21.94 ms | 26.00 ms | 26.64 ms | 68.3 | 45 | 0.9 |
| 1KB | batch_write (100 puts) | 1 | 36.7 | 0.04 | 2 568 ms | 2 705 ms | 2 705 ms | 69.4 | 46 | 0.9 |
| 1KB | batch_read (100 gets) | 1 | 621 181 | 606.6 | 159 µs | 180 µs | 204 µs | 100.9 | 46 | 0 |
| 1KB | concurrent_read | 16 | 422 694 | 412.8 | 36.9 µs | 44.0 µs | 58.8 µs | 120.6 | 47 | 0 |
| 1KB | concurrent_write | 16 | 34.2 | 0.03 | 454 ms | 565 ms | 700 ms | 71.2 | 60 | 0.8 |
| 1KB | mixed 80/20 | 16 | 162.6 | 0.16 | 89.0 ms | 194 ms | 268 ms | 71.3 | 42 | 0.8 |
| 10KB | write | 1 | 42.1 | 0.41 | 23.92 ms | 25.88 ms | 27.47 ms | 67.7 | 74 | 1.7 |
| 10KB | read | 1 | 479 093 | 4 679 | 2.0 µs | 2.5 µs | 3.2 µs | 98.9 | 150 | 0 |
| 10KB | random_rw | 1 | 80.4 | 0.79 | 31.7 µs | 26.93 ms | 29.06 ms | 69.2 | 142 | 1.6 |
| 10KB | batch_write | 1 | 36.7 | 0.36 | 2 560 ms | 2 713 ms | 2 713 ms | 69.7 | 83 | 1.5 |
| 10KB | concurrent_read | 16 | 382 161 | 3 732 | 41.6 µs | 44.6 µs | 46.5 µs | 118.0 | 154 | 0 |
| 10KB | concurrent_write | 16 | 36.0 | 0.35 | 446 ms | 465 ms | 505 ms | 72.0 | 160 | 1.4 |
| 10KB | mixed 80/20 | 16 | 179.0 | 1.75 | 85.1 ms | 173 ms | 225 ms | 73.4 | 159 | 1.4 |
| 100KB | write | 1 | 63.4 | 6.19 | 15.84 ms | 18.03 ms | 21.53 ms | 51.4 | 348 | 13.2 |
| 100KB | read | 1 | 229 867 | 22 448 | 4.1 µs | 5.4 µs | 6.9 µs | 100.0 | 380 | 0 |
| 100KB | random_rw | 1 | 116.7 | 11.4 | 18.5 µs | 18.13 ms | 19.72 ms | 54.6 | 380 | 12.0 |
| 100KB | batch_write | 1 | 56.7 | 5.53 | 1 862 ms | 2 001 ms | 2 094 ms | 58.7 | 395 | 11.2 |
| 100KB | concurrent_read | 16 | 191 105 | 18 663 | 81.0 µs | 101 µs | 119 µs | 110.3 | 361 | 0 |
| 100KB | concurrent_write | 16 | 45.9 | 4.49 | 346 ms | 367 ms | 568 ms | 63.7 | 426 | 9.6 |
| 100KB | mixed 80/20 | 16 | 228.1 | 22.3 | 67.2 ms | 136 ms | 163 ms | 66.2 | 353 | 9.2 |
| 1MB | write | 1 | 27.9 | **27.9** | 35.04 ms | 40.51 ms | 51.03 ms | 74.6 | 1 088 | 54.0 |
| 1MB | read | 1 | 47 006 | 47 006 | 19.8 µs | 28.8 µs | 41.5 µs | 99.6 | 909 | 0 |
| 1MB | random_rw | 1 | 55.2 | 55.2 | 32.85 ms | 36.78 ms | 45.86 ms | 75.3 | 762 | 53.7 |
| 1MB | batch_write | 1 | 24.6 | 24.6 | 3 735 ms | 3 806 ms | 3 806 ms | 74.9 | 979 | 52.3 |
| 1MB | concurrent_read | 16 | 47 339 | 47 339 | 320 µs | 421 µs | 593 µs | 101.7 | 619 | 0 |
| 1MB | concurrent_write | 16 | 26.4 | 26.4 | 604 ms | 642 ms | 677 ms | 76.0 | 894 | 51.1 |
| 1MB | mixed 80/20 | 16 | 132.5 | 132.5 | 113 ms | 252 ms | 298 ms | 76.6 | 882 | 50.3 |

Ошибок: 0 во всех сценариях. Полная таблица (включая random_read/batch_read для всех размеров) — `bench-results/v1/run-20261003/summary.md`.

Наблюдения:
* **Чтение не расшифровывает данные:** `get_data` стоит ~1.4–2 µs независимо от того, что значение хранится зашифрованным на диске — значения держатся в RAM (overlay) в открытом виде. MB/s чтения 1 MiB (47 GB/s) — это копирование памяти, а не I/O.
* **Вся база в RAM:** RSS растёт с объёмом данных (1 MiB × 256 строк + записанное → ~1.1 GB RSS).
* **Write amplification (устройство):** 1 KiB put → ~27.9 KB записей на диск (34.3 MB / 1 260 операций), рост журнала ~4.4 KB/запись. PostgreSQL (writethrough) — ~17.7 KB на 1 KiB INSERT. Порядок величины сопоставим.

### Write throughput vs количество ключей (1 KiB)

| ключей до окна | writes/s | avg latency | CPU % |
|---|---|---|---|
| 0 | 96.5 | 10.4 ms | 22.3 |
| 2 000 | 79.0 | 12.7 ms | 37.4 |
| 5 000 | 63.0 | 15.9 ms | 50.3 |
| 10 000 | 43.1 | 23.2 ms | 64.8 |
| 15 000 | 31.7 | 31.5 ms | 73.1 |
| 18 000 | 27.0 | 37.1 ms | 75.5 |

Линейная деградация + рост CPU. Причина установлена профилированием (macOS `sample`): на **каждую** запись `node_bundle()` (`crates/dmc-core/src/materializer.rs:104`) вызывает `KeyTree::list_nodes()` → `export_meta()`, который сортирует и hex-форматирует **все** узлы дерева ключей (узел на каждый уникальный путь), чтобы затем отфильтровать предков. Это O(N log N) CPU на запись под глобальным mutex.

### PostgreSQL 14 (unix socket, prepared statements)

`fsync_writethrough` (durability, сопоставимая с F_FULLFSYNC Avrora):

| size | scenario | workers | records/s | MB/s | p50 | p95 | p99 | CPU % | disk write MB/s |
|---|---|---|---|---|---|---|---|---|---|
| 1KB | write | 1 | 258.8 | 0.25 | 3.98 ms | 4.08 ms | 4.33 ms | 5.4 | 4.6 |
| 1KB | read | 1 | 79 939 | 78.1 | 12.1 µs | 14.6 µs | 25.0 µs | 63.6 | 0 |
| 1KB | random_rw | 1 | 497.9 | 0.49 | 500 µs | 4.05 ms | 4.68 ms | 6.4 | 4.5 |
| 1KB | batch_write (1 INSERT × 100 rows) | 1 | 17 871 | 17.5 | 5.04 ms | 6.85 ms | 12.62 ms | 19.2 | 45.8 |
| 1KB | batch_read (ANY(100)) | 1 | 933 643 | 911.8 | 108 µs | 121 µs | 132 µs | 84.0 | 0.9 |
| 1KB | concurrent_read | 16 | 316 234 | 308.8 | 45.3 µs | 99.6 µs | 140.5 µs | 429.1 | 0 |
| 1KB | concurrent_write | 16 | 2 224 | 2.17 | 6.95 ms | 8.13 ms | 14.11 ms | 31.8 | 9.8 |
| 1KB | mixed 80/20 | 16 | 11 985 | 11.7 | 83.8 µs | 6.77 ms | 7.70 ms | 61.0 | 6.0 |
| 1MB | write | 1 | 59.1 | 59.1 | 13.98 ms | 37.97 ms | 46.02 ms | 50.3 | 148.5 |
| 1MB | concurrent_write | 16 | 105.4 | 105.4 | 126 ms | 356 ms | 1 004 ms | 172.0 | 320.5 |

`open_datasync` (default macOS — **без** сброса кэша накопителя): 1 KiB write **31 547 ops/s** (p50 29.5 µs), concurrent_write 56 789, batch_write 144 777 records/s; 1 MiB write 92 ops/s. Полные таблицы обоих режимов для всех размеров — `summary.md`.

---

## SQL Performance

SQL Core (Avrora) — отдельный процесс `dmc serve --dev`, клиент `dmc-client` по unix socket (IPC), SQL-текст; пользователь `analyst` (единственная доступная identity). PostgreSQL — simple query protocol с литералами (та же форма SQL). Таблица `items(id BIGINT PK, name TEXT, score BIGINT)`.

| size | scenario | Avrora SQL Core rows/s | p50 / p99 | PG writethrough rows/s | p50 / p99 | PG default rows/s |
|---|---|---|---|---|---|---|
| 100B | INSERT (autocommit) | 13.3 | 75.0 / 85.9 ms | 302.4 | 3.05 / 4.19 ms | 22 657 |
| 100B | SELECT by PK | 46.7 | 21.3 / 25.7 ms | 58 993 | 16.2 / 29.9 µs | 57 228 |
| 100B | multi-row INSERT (100) | 13.3 | 8 790 / 8 829 ms | 22 383 | 4.11 / 6.05 ms | 307 910 |
| 100B | SELECT … LIMIT 100 (rows/s) | 10 867 | 9.0 / 11.4 ms | 2 774 157 | 35.7 / 50.5 µs | 2 766 427 |
| 1KB | INSERT | 12.5 | 78.1 / 123.0 ms | 282.8 | 3.61 / 4.95 ms | 20 019 |
| 1KB | SELECT by PK | 41.8 | 22.5 / 50.7 ms | 56 867 | 16.7 / 30.9 µs | 58 186 |
| 1KB | multi-row INSERT (100) | 10.0 | 8 935 / 9 487 ms | 17 030 | 5.92 / 11.97 ms | 103 333 |
| 10KB | INSERT | 8.3 | 114 / 196 ms | 219.5 | 4.42 / 8.00 ms | 3 503 |
| 10KB | SELECT by PK | 40.7 | 24.2 / 32.2 ms | 33 548 | 29.5 / 43.2 µs | 42 632 |
| 100KB | INSERT | 8.6 | 111 / 290 ms | 159.9 | 6.03 / 12.01 ms | 498 |
| 100KB | SELECT by PK | 44.2 | 20.7 / 58.9 ms | 9 879 | 91.8 / 144.5 µs | 11 561 |
| 1MB | любой | **не поддерживается**: SQL ≤ 1 MiB frame | — | (не тестировалось) | — | — |

Конкурентность SQL Core (4 клиента, соединение на операцию): INSERT 10.6 rows/s (p50 379 ms), SELECT 34.3 rows/s (p50 115 ms) — то есть **не выше одного клиента**: сервер обслуживает одно соединение за раз (`persistent_concurrency_probe`: из 4 клиентов с постоянными соединениями прогресс у **1**, у остальных 0 запросов за 15 s).

INSERT vs размер таблицы (1 KiB): 22.5 → 19.1 → 16.6 → 14.3 → 12.2 → 10.7 → 9.5 inserts/s на 0 / 500 / … / 3 000 строк; `state_events.json` 0.78 → 5.46 MB, запись на диск растёт до 53 MB/s при 9.5 inserts/s — весь лог переписывается на каждый коммит.

Наблюдения (без верификации причины): SELECT по PK стоит ~21–24 ms независимо от размера строки и таблицы (≈ 45 запросов/s при CPU сервера ~99 %) — порядок совпадает с ценой полного прохода; использование PK-индекса в этом пути **NOT VERIFIED**.

100 KiB: `SELECT … LIMIT 100` и последующие сценарии дали 0 операций — к их началу IPC-listener уже не принимал соединения (клиенты получили `Connection refused`, см. Bottlenecks). Отдельно воспроизведено: **один SELECT, ответ которого > 1 MiB, останавливает listener** (процесс жив, все новые клиенты — `Connection refused`).

---

## Channel Performance

Путь: `put_data` (producer, admin session) → журнал → подписка (user `consumer`, роль Read на `chan/*`) → `consume` → `ack`. Fan-out: каждый потребитель — отдельная подписка, получает **все** сообщения.

### Основная таблица (1 KiB, closed loop, 30 s производства + drain ≤ 120 s)

| Channel scenario | msg/sec (produce) | msg/sec (deliver+ACK, все C) | MB/sec (produce) | p95 e2e | p99 e2e | Lost | Duplicate |
|---|---|---|---|---|---|---|---|
| 1P / 1C | 38.5 | 25.9 | 0.040 | 23.4 s | 23.5 s | **0** | **0** |
| 10P / 1C | 72.2 | 14.1 | 0.070 | 124.4 s | 126.8 s | **0** *(477 не доставлено за 120 s drain; повтор с drain 1800 s: 2 558/2 558 доставлено)* | **0** |
| 1P / 10C | 8.1 | 45.8 | 0.010 | 31.9 s | 32.9 s | **0** | **0** |
| 10P / 10C | 36.6 | 22.9 | 0.040 | 146.6 s | 148.1 s | 0 доказанных *(10 010 из 13 470 доставок не выполнено за 120 s drain; полный drain не проверялся — NOT VERIFIED)* | **0** |

p95/p99 — это латентность от `put_data` до получения потребителем; в closed loop производитель быстрее потребителя, backlog растёт линейно, поэтому e2e ≈ «время в очереди». Латентность одиночного сообщения без backlog — см. ramp (20 msg/s: e2e p50 22.3 ms, p99 30.2 ms).

Остальные метрики 1P/1C: producer p99 42.1 ms; ACK 25.9/s; backlog при остановке производителя 696; порядок по sequence и по производителю — 0 нарушений; CPU 44.5 %.

**Undelivered ≠ lost.** Для 10P/1C прогон с `drain_timeout = 1800 s` (supp) доставил 2 558 из 2 558 (см. «Correctness Results»). Для 10P/10C полный drain не выполнялся. В основном прогоне ни одно полученное сообщение не было дублем, порядок не нарушался.

### Варианты (1 KiB)

| scenario | produce msg/s | deliver msg/s | ack/s | retried | DLQ | lost | dup |
|---|---|---|---|---|---|---|---|
| 1P/1C same path (без роста key tree) | 42.8 | 28.2 | 28.2 | 0 | 0 | 0 | 0 |
| 1P/1C `ack_batch` | 38.9 | 26.2 | 26.2 | 0 | 0 | 0 | 0 |
| 1P/1C retry (ACK на 2-й попытке) | 36.1 | 32.2 | 16.1 | 1 311 (=produced) | 0 | 0 | 0 |
| 1P/1C DLQ (max_attempts=3, без ACK) | 21.6 | 17.2 | 0 | 1 630 (=2×) | 815 (=produced) | 0 | 0 |

* **Batch ACK не даёт выигрыша:** `consume`/`consume_batch` всегда возвращают ≤ 1 событие (`consume_batch(max_events=10)` → 1), а повторный `consume` до ACK переотдаёт то же событие как retry (`attempt=2`). In-flight на подписку = 1, поэтому `ack_batch` фактически подтверждает 1 доставку.
* **Backpressure:** при `max_in_flight=1` второй `consume_batch` возвращает `Err(Backpressure in_flight=1 max=1)` — потребительский backpressure работает. **Producer-side backpressure отсутствует:** `put_data` никогда не отклоняется из-за lag (backlog в timeline растёт линейно: +~23 msg/s в 1P/1C).
* **Consumer lag метрика:** после полного DLQ-прогона `consumer_lag.lag_events = 204` при пустом backlog — метрика считает все записи журнала (включая DLQ/config), а не доставляемые события.

### 100 KiB

| scenario | produce msg/s | produce MB/s | deliver msg/s | p99 e2e | lost (за 120 s) | dup |
|---|---|---|---|---|---|---|
| 1P/1C | 10.1 | 0.99 | 6.8 | 36.2 s | 0 | 0 |
| 10P/1C | 23.2 | 2.26 | 1.2 | — | 779 не доставлено | 0 |
| 1P/10C | 3.1 | 0.31 | 19.1 | 38.4 s | 0 | 0 |
| 10P/10C | 8.0 | 0.78 | 3.5 | — | 2 990 не доставлено | 0 |
| DLQ max3 | 3.3 | 0.32 | 2.5 | 130 s | 25 не доставлено | 0 |

RSS процесса до 2.9 GB в 100 KiB сценариях (данные + backlog в RAM).

### MAX_STABLE (open-loop ramp, 1 KiB)

| target msg/s | 1P/1C achieved | backlog@stop | e2e p99 | stable |
|---|---|---|---|---|
| 5 | 5.03 | 1 | 24.9 ms | ✅ |
| 10 | 10.03 | 1 | 26.5 ms | ✅ |
| **20** | **20.03** | 1 | 30.2 ms | ✅ |
| 30 | 30.03 | 78 | 2.58 s | ❌ |
| 40 | 38.4 | 591 | 19.2 s | ❌ |

| target msg/s | 1P/10C achieved | backlog@stop | e2e p99 | stable |
|---|---|---|---|---|
| 5 | 5.03 | 180 | 3.89 s | ❌ |
| 10 | 8.07 | 1 440 | 31.5 s | ❌ (109 не доставлено за 30 s) |

* **MAX_STABLE_MESSAGES_PER_SEC (1P/1C, 1 KiB) = 20 msg/s**; **MAX_STABLE_MB_PER_SEC = 0.02 MB/s**.
* **1P/10C: устойчивой точки ≥ 5 msg/s нет** (10 подписок × 5 msg/s = 50 доставок/s превышают ёмкость потребителей ~46 доставок/s).
* 100 KiB: ramp не выполнялся; верхняя граница по closed loop — потребитель 6.8 msg/s (0.68 MB/s), при этом backlog растёт → **MAX_STABLE для 100 KiB NOT DETERMINED** (< 6.8 msg/s).

---

## Trigger Performance

Путь: `put_data` → событие `OverlayApply` → `TriggerAction::ForwardToStream` → in-memory stream (`tokio::broadcast(256)`) → receiver. Триггеры выполняются **синхронно внутри записи** под mutex runtime.

| scenario | writes/s | write p50 | write p99 | trigger deliveries/s | trigger latency p50 | p99 | expected | received | lagged/lost | CPU % |
|---|---|---|---|---|---|---|---|---|---|---|
| 0 триггеров, 1 writer | 79.6 | 12.93 ms | 14.12 ms | — | — | — | 0 | 0 | 0 | 36.0 |
| 1 триггер, 1 writer | 81.6 | 12.05 ms | 14.08 ms | 83.6 | **766 ms** | 1.57 s | 2 925 | 2 925 | 0 | 35.8 |
| 5 триггеров, 1 writer | 79.9 | 12.84 ms | 15.15 ms | 408.0 | 12.9 ms | 27.9 ms | 14 280 | 14 280 | 0 | 35.6 |
| 0 триггеров, 8 writers | 81.2 | 99.91 ms | 113.03 ms | — | — | — | 0 | 0 | 0 | 35.9 |
| 1 триггер, 8 writers | 79.7 | 100.98 ms | 110.00 ms | 82.0 | 99.9 ms | 110.0 ms | 2 871 | 2 871 | 0 | 36.3 |
| 5 триггеров, 8 writers | 80.6 | 99.86 ms | 109.00 ms | 413.7 | 98.2 ms | 109.2 ms | 14 480 | 14 480 | 0 | 36.0 |

Повтор (supp-прогон) воспроизводит те же значения: writes/s 80.4–82.3; trigger latency 763 ms (1 триггер/1 writer), 12.1 ms (5/1), ~99 ms (8 writers); 0 потерь.

* **Дополнительная латентность записи от триггеров: ≈ 0** (79.6 → 81.6 → 79.9 writes/s; p50 12.9 → 12.1 → 12.8 ms) — `ForwardToStream` в памяти пренебрежимо дёшев на фоне fsync.
* **Конкурентные триггеры (8 writers)** не увеличивают пропускную способность (≈ 80 writes/s) — триггеры наследуют сериализацию пути записи; latency доставки ≈ latency записи (~100 ms).
* **Аномалия (воспроизводимая, причина NOT VERIFIED):** при одном триггере и одном писателе медиана доставки получателю — 763–766 ms, тогда как при 5 триггерах — 12 ms. Вероятная гипотеза — планирование tokio-задачи получателя при блокирующем fsync в async-контексте runtime; не проверялась.
* **Семантика:** доставка через `broadcast(256)` — in-memory, без durability и ACK; медленный получатель теряет сообщения (`Lagged`); в тестах lagged = 0.

---

## Connection Scalability

| system | conns | connected | failed | setup p50 | setup p99 | req/s | errors/s | p50 | p95 | p99 | server CPU % | server RSS MB | stable |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Avrora control (TLS1.3+mTLS) | 10 | 10 | 0 | 1.33 ms | 1.39 ms | 95 217 | 0 | 103 µs | 152 µs | 179 µs | 198 | 17 | ✅ |
| | 100 | 100 | 0 | 11.5 ms | 14.5 ms | 99 279 | 0 | 1.00 ms | 1.11 ms | 1.17 ms | 208 | 19 | ✅ |
| | 1 000 | 1 000 | 0 | 11.7 ms | 53.1 ms | 94 262 | 0 | 10.6 ms | 11.1 ms | 11.5 ms | 204 | 30 | ✅ |
| | 2 500 | 2 500 | 0 | 11.1 ms | 52.7 ms | 91 981 | 0 | 27.0 ms | 28.5 ms | 31.1 ms | 201 | 49 | ✅ |
| | 5 000 | 5 000 | 0 | 11.5 ms | 85.5 ms | 91 500 | 0 | 54.4 ms | 57.4 ms | 61.8 ms | 202 | 80 | ✅ |
| | 10 000 | 10 000 | 0 | 12.3 ms | 51.0 ms | 88 712 | 0 | 111 ms | 122 ms | 130 ms | 200 | 142 | ✅ |
| | 15 000 | 15 000 | 0 | 12.9 ms | 43.3 ms | 88 275 | 0 | 168 ms | 188 ms | 208 ms | 199 | 205 | ✅ |

| PostgreSQL 14 (TCP, default) | 10 | 10 | 0 | 8.48 ms | 14.8 ms | 163 783 | 0 | 58.9 µs | 99.3 µs | 127 µs | 335 | 178* | ✅ |
| | 100 | 100 | 0 | 24.7 ms | 66.2 ms | 202 428 | 0 | 464 µs | 903 µs | 1.40 ms | 439 | 1 096* | ✅ |
| | 250 | 250 | 0 | 122 ms | 213 ms | 190 223 | 0 | 1.14 ms | 2.76 ms | 4.38 ms | 494 | 2 628* | ✅ |
| | 500 | 500 | 0 | 78.4 ms | 280 ms | 171 614 | 0 | 2.25 ms | 7.24 ms | 13.3 ms | 530 | 5 202* | ✅ |
| | 1 000 | 1 000 | 0 | 85.4 ms | 626 ms | 160 225 | 0 | 4.46 ms | 18.2 ms | 34.2 ms | 529 | 10 076* | ✅ |

\* сумма RSS дерева процессов PG, завышена (shared memory считается в каждом backend). Данные PG — из supp-прогона (исправлен учёт CPU backend-процессов); req/s и латентности совпадают с основным прогоном (155–205 k req/s).

* **Avrora MAX_STABLE_CONNECTIONS ≥ 15 000.** 15 000 — предел генератора (один клиентский IP, 16 384 эфемерных порта, TIME_WAIT), а **не** сервера: ошибок нет, RSS сервера ~14 KB/соединение.
* **Но это не производительность:** request rate не растёт с числом соединений (95–99 k req/s при 10–500, 88 k при 15 000), сервер стабильно занимает ~2 ядра (200 % CPU), латентность растёт линейно с числом соединений (p99 ≈ 14 µs × N). Все запросы сериализуются глобальным mutex runtime.
* **SQL Core IPC: MAX_STABLE_CONNECTIONS = 1** активное соединение (остальные ждут без таймаута; `persistent_concurrency_probe`).
* Avrora стабильна дальше, чем PostgreSQL в абсолютном числе соединений, но PostgreSQL при 1 000 соединений даёт больше запросов/s; PG-рампа ограничена 1 000 соединений сознательно (process-per-connection, `maxprocperuid = 2666`, RSS).

---

## Security Overhead

Отключаемого security-режима в Avrora нет; контрольные baseline построены из тех же примитивов без security-слоя.

| Сравнение (1 KiB, 1 клиент) | latency p50 | throughput | overhead latency | overhead throughput | CPU на операцию |
|---|---|---|---|---|---|
| Avrora put **in-process** (AuthZ + AES-GCM + journal + fsync) | 10.13 ms | 94.9/s | baseline | baseline | 2.47 ms |
| Avrora put **remote** (TLS 1.3 + mTLS + control session + JSON) | 12.00 ms | 82.6/s | **+18.5 %** | **−13.0 %** | 3.87 ms сервер (+57 %) |
| Avrora get in-process | 1.4 µs | 665 215/s | baseline | baseline | 1.5 µs |
| Avrora get remote | 36.7 µs | 25 108/s | **+2 521 % (×26)** | **−96.2 %** | 16.9 µs сервер + 22 µs клиент |
| echo plain TCP (контроль транспорта) | 18.5 µs | 53 215/s | baseline | baseline | — |
| echo **TLS 1.3** | 21.0 µs | 47 609/s | **+13.5 %** | **−10.5 %** | CPU +14 % (97.5 vs 85.3 %) |
| raw append + F_FULLFSYNC (без шифрования) | 3.97 ms | 250/s | baseline | baseline | — |
| raw append + **AES-256-GCM** + F_FULLFSYNC | 3.98 ms | 257/s | **≈ 0 %** | ≈ 0 % | AES 5.6 µs/KiB |

По размерам:

| size | AES-256-GCM encrypt | TLS echo vs TCP (latency) | remote get vs in-proc | append+AES+fsync vs append+fsync |
|---|---|---|---|---|
| 100 B | 2.0 µs | +4 % | 22.5 µs vs 1.4 µs | ≈ 0 % |
| 10 KiB | 47.6 µs (97.7 MB/s) | +65 % | 178 µs vs 1.8 µs | −4 % throughput |
| 100 KiB | 470 µs (104 MB/s) | +263 % | 1.60 ms vs 5.6 µs | −26 % throughput |
| 1 MiB | 4.81 ms (104 MB/s) | — | **не поддерживается** (> 300 KiB: `frame too large (1097141 bytes)`) | −47 % throughput |

Выводы:
* **Шифрование хранения почти бесплатно для малых записей** (5.6 µs на 4–10 ms записи) и заметно для больших: AES-GCM работает в **программной** реализации (`aes::soft::fixslice` в профиле) с потолком ~100 MB/s; ARMv8 AES-инструкции не задействованы.
* **TLS 1.3 сам по себе дёшев** (+13.5 % latency на 1 KiB; handshake 183 µs поверх TCP 34 µs). Основная цена remote-пути — **формат протокола**: `Vec<u8>` сериализуется в JSON как массив чисел (×3–4 к размеру), отсюда 1.6 ms на 100 KiB get против 0.12 ms TLS echo того же размера и лимит полезной нагрузки ~300 KiB при `MAX_FRAME = 1 MiB`.
* **Цена durability, а не security, доминирует в записи:** F_FULLFSYNC = 3.98 ms против 17–29 µs у обычного `fsync` (который на macOS не сбрасывает кэш накопителя). Запись Avrora (10 ms) ≈ 2.5 × F_FULLFSYNC.
* AuthZ отдельно не измерялся (нет отключаемого режима); верхняя граница — полный in-process `get_data` = 1.4 µs.

---

## Stress Test

| нагрузка | наблюдаемое поведение | тип bottleneck |
|---|---|---|
| Writers 1 → 64 (1 KiB) | 75.7 → 69.9 → 66.1 → 64.1 → 58.1 → 57.3 → 53.3 writes/s; p50 13 ms → 1.19 s; CPU 40–55 % | **lock contention** (глобальный mutex) + **disk sync latency** (F_FULLFSYNC); пропускная способность не растёт, падает |
| Readers 1 → 64 (1 KiB) | 528 k → 476 k → 453 k → 478 k → 471 k → 448 k → 439 k reads/s; CPU ~120 % из 1000 % | **lock contention**: чтения сериализованы, используется ~1.2 ядра |
| Рост числа ключей 0 → 18 000 | 96 → 27 writes/s, CPU 22 → 75 % | **CPU** (O(N) `node_bundle` на запись) |
| SQL Core: рост таблицы 0 → 3 000 строк | 22.5 → 9.5 inserts/s, диск до 53 MB/s | **disk/CPU** (полная перезапись JSON-лога) |
| Каналы: rate 20 → 30 msg/s | e2e p99 30 ms → 2.6 s; backlog растёт | **consumer**: 2 durable записи consumer-meta на сообщение, 1 in-flight, O(backlog) scan |
| Каналы: 1 → 10 потребителей | доставка на потребителя падает до ~4.6/s | тот же consumer-путь × fan-out под одним mutex |
| Соединения 10 → 15 000 | req/s 95 k → 88 k, p99 0.18 → 208 ms, 0 ошибок, сервер 200 % CPU | **lock contention / CPU** (2 ядра), не память и не сеть |
| RAM | Avrora KV держит все данные в RAM (1 MiB-сценарии: RSS ~1.1 GB; 100 KiB каналы: 2.9 GB) | память — ограничение объёма, не скорости |
| Network | localhost; TLS echo 100 KiB 1.6 GB/s — не насыщался | не bottleneck |

* **MAX_STABLE_LOAD** (комбинированно, 1 KiB): ≈ **20 durable msg/s через канал с одним потребителем** или ≈ **40–96 durable writes/s** (в зависимости от числа ключей) плюс до ~430–600 k reads/s из RAM.
* **MAX_STABLE_STORAGE_THROUGHPUT:** запись — **27.9 MB/s** (1 MiB записи, 28 ops/s), для 1 KiB — 42 ops/s (0.04 MB/s) при 10 000 ключей; чтение — ограничено памятью/CPU (≥ 400 k ops/s до 10 KiB).
* **MAX_STABLE_CHANNEL_THROUGHPUT:** **20 msg/s, 0.02 MB/s** (1P/1C, 1 KiB); 1P/10C — < 5 msg/s.
* **MAX_STABLE_CONNECTIONS:** **≥ 15 000** (control plane, предел генератора); SQL Core IPC — **1**.

---

## Correctness Results

| check | produced | received | acked | retried | dlq | lost | duplicated | result |
|---|---|---|---|---|---|---|---|---|
| Idempotent producer (2 конкурентных производителя × 500 одинаковых ключей + 100 повторов после restart) | 1 000 попыток / 500 уникальных | 500 | 500 | 0 | 0 | **0** | **0** | ✅ PASS (500 replay-флагов, 0 расхождений sequence, после restart 100/100 replay) |
| Retry: ACK только на 3-й попытке | 200 | 200 (600 доставок) | 200 | 400 | 0 | **0** | **0** | ✅ PASS (у всех 200 попытки ровно 1,2,3) |
| DLQ: max_attempts=3, без ACK | 100 | 100 (300 доставок) | 0 | 200 | **100** | **0** | **0** | ✅ PASS (attempts=3 у всех, sequence совпадают) |
| Graceful restart (lock → reopen) | 1 000 | 1 000 | 1 000 | 1 (pending) | 0 | **0** | **0** | ✅ PASS (0 повторов подтверждённых, pending переотдан) |
| **SIGKILL × 5 циклов** (реальный процесс) | 610 подтверждённых записей | 612 уникальных | 361 до крэшей + 251 после | — | 0 | **0** | **0** ACK-дублей | ✅ PASS (0 потерь подтверждённых, 0 повреждённых payload, 0 переотдач подтверждённых) |
| Каналы под нагрузкой (24 прогона: матрица 1 KiB/100 KiB, ramp, supp) | 20 602 | см. таблицы | | | | 0 доказанных потерь | **0** | ✅ по дублям и порядку; доставка в срок — ❌ (backlog) |
| Каналы: 0 нарушений порядка (sequence и per-producer) | | | | | | | | ✅ |
| Триггеры: доставлено = writes × triggers, lagged 0 | | | | | | 0 | | ✅ |

**Undelivered vs lost (10P/1C, supp, `drain_timeout = 1800 s`):** produced 2 558 → received unique **2 558**, acked 2 558, lost **0**, duplicated **0**, нарушений порядка 0; полная доставка заняла 138 s после остановки производителей (backlog 2 430). Т.е. «undelivered» основного прогона — следствие 120-секундного таймаута drain при скорости потребителя ~15 msg/s, а не потеря данных.

Примечания:
* 612 > 610 в SIGKILL-тесте: 2 записи стали durable, но процесс был убит до печати подтверждения клиенту — ожидаемо для at-least-once (не дубликат и не потеря).
* **Ограничение AuthZ:** потребитель **не может прочитать собственный DLQ** (`access denied: missing READ on '/_system/dlq/<sub>'`); проверка DLQ выполнена admin-сессией.
* Семантика доставки: at-least-once, порядок в пределах подписки по глобальному `sequence`, один in-flight. Exactly-once не заявлен и не тестировался.

---

## PostgreSQL Comparison

Avrora — in-process embedded KV (без сети, без SQL); PostgreSQL — сервер, unix socket, prepared statements. **Это разные архитектуры**: чтения Avrora не проходят ни IPC, ни парсер, ни расшифровку. Durability сравнивается с PG `fsync_writethrough` (F_FULLFSYNC, как `sync_all` в Avrora); PG default приведён справочно.

| Metric (1 KiB) | Avrora | PostgreSQL (`fsync_writethrough`) | PostgreSQL (default, без F_FULLFSYNC) |
|---|---|---|---|
| Read ops/sec | **601 350** (in-process) / 25 108 (remote TLS) | 79 939 | 80 411 |
| Write ops/sec | **42.0** | **258.8** | 31 547 |
| Batch write ops/sec (records) | 36.7 (100 отдельных put) | 17 871 (1 INSERT × 100) | 144 777 |
| Concurrent read (16) | 422 694 | 316 234 | 318 227 |
| Concurrent write (16) | 34.2 | 2 224 | 56 789 |
| Throughput MB/sec — read | 587 | 78 | 79 |
| Throughput MB/sec — write | 0.04 (1 KiB) / 27.9 (1 MiB) | 0.25 (1 KiB) / 59.1 (1 MiB) | 30.8 / 92.1 |
| p50 (write / read) | 23.96 ms / 1.5 µs | 3.98 ms / 12.1 µs | 29.5 µs / 12.0 µs |
| p95 (write / read) | 25.93 ms / 2.0 µs | 4.08 ms / 14.6 µs | 37.2 µs / 14.5 µs |
| p99 (write / read) | 29.11 ms / 2.5 µs | 4.33 ms / 25.0 µs | 48.1 µs / 24.9 µs |
| Max stable connections | **≥ 15 000** control plane (88 k req/s); SQL Core IPC: **1** | **≥ 1 000** (протестировано до 1 000; 160 k req/s, p99 34 ms; потолок задан `maxprocperuid=2666` и RAM) | — |
| CPU (write, 1 клиент) | 66.5 % (≈ 16 ms CPU / запись) | 5.4 % | 45.6 % |
| CPU (read, 1 клиент) | 99.6 % (процесс бенчмарка = клиент+движок) | 63.6 % (сервер) | 64.6 % |
| RAM (peak) | 35 MB (1 KiB, 10 k строк); ~1.1 GB (1 MiB × 256) — **все данные в RAM** | 222 MB (сумма RSS дерева, завышена shared buffers) | 389 MB |
| Disk I/O (write) | ~1.0 MB/s при 42 ops/s (~28 KB на 1 KiB запись) | 4.6 MB/s при 259 ops/s (~18 KB) | 574 MB/s |

SQL (одинаковый SQL-текст): Avrora SQL Core INSERT **12.5/s** vs PG 282.8/s (writethrough), SELECT by PK **41.8/s** vs **56 867/s** (×1 360), multi-row INSERT 10 rows/s vs 17 030 rows/s.

* Avrora **быстрее** PostgreSQL только в чтении через embedded in-process API (×7.5 по 1 клиенту, ×1.3 по 16) — за счёт того, что всё лежит в RAM без сетевого и SQL-слоя. Через свой сетевой интерфейс (TLS) Avrora читает в **3.2×** медленнее PG по сокету.
* В durable-записи PostgreSQL быстрее в **6.2×** (1 клиент) и в **65×** (16 клиентов — group commit), в batch — в **487×**.
* SQL Core медленнее PostgreSQL на 2–4 порядка во всех SQL-сценариях.
* **Channels / streams / triggers / ACK / retry / DLQ: NOT DIRECTLY COMPARABLE** — в PostgreSQL нет эквивалента (LISTEN/NOTIFY не durable и без ACK/retry/DLQ; очереди на таблицах — это другой продукт). Сравнение не проводилось.

---

## Bottlenecks

Подтверждено измерениями/профилем/кодом; ранжировано по влиянию на цели проекта.

1. **Путь записи Avrora (все записи, каналы, триггеры):**
   * **≥ 2 F_FULLFSYNC на запись** (journal `sync_all` + метаданные/каталог): запись при 0 ключей ≈ 10 ms ≈ 2.5 × 3.98 ms F_FULLFSYNC; `fcntl` — главный пункт ожидания в профиле.
   * **O(N) CPU на запись**: `node_bundle()` → `KeyTree::export_meta()` сортирует и форматирует весь key tree (`materializer.rs:104`) — деградация 96 → 27 writes/s при 0 → 18 000 ключей.
   * **Нет group commit/batch API**: 16 писателей дают 34 writes/s против 2 224 у PG.
2. **Глобальный `tokio::Mutex<RuntimeInner>`** сериализует все операции: чтения не масштабируются (≈ 1.2 ядра из 10), запись не масштабируется, connection-нагрузка упирается в ~2 ядра; блокирующий fsync выполняется внутри async-контекста.
3. **Потребительский путь каналов:** 1 in-flight на подписку; каждый `consume` заново читает и расшифровывает журнал от offset до конца (`matching_entries` без лимита в `consume_next`) — O(backlog); 2 durable (fsync) перезаписи всего consumer-meta на сообщение (begin_delivery + ack). Итог — ~26 доставок/s и MAX_STABLE 20 msg/s; fan-out на 10 подписок умножает стоимость.
4. **Нет producer-side backpressure** — backlog растёт неограниченно, e2e-латентность растёт до минут.
5. **SQL Core:** полная перезапись `state_events.json` на каждый коммит (O(n²) записи), одно соединение за раз, SELECT по PK ~22 ms; **fail-stop listener** при: (а) 10 000 запросов в одном соединении, (б) ответе > 1 MiB — оба воспроизведены, сервер продолжает работать без приёма соединений.
6. **Remote-протокол:** JSON-массив чисел для `Vec<u8>` (×26 к latency чтения vs in-process, 1.6 ms на 100 KiB) и потолок полезной нагрузки ~300 KiB.
7. **Программный AES-GCM** (~100 MB/s): −47 % пропускной способности для 1 MiB записей.
8. **Всё в RAM:** KV/overlay целиком в памяти, RSS растёт с данными (до 2.9 GB в 100 KiB канальных сценариях).

---

## Maximum Stable Load

| Метрика | Значение | Условия |
|---|---|---|
| **MAX_STABLE_STORAGE_THROUGHPUT** (write) | **42 ops/s** (1 KiB, 10 k ключей); **96 ops/s** (пустая база); **27.9 MB/s** (1 MiB) | 1 писатель, F_FULLFSYNC; больше писателей не помогает |
| MAX_STABLE_STORAGE_THROUGHPUT (read) | **~600 k ops/s** (1 клиент), **~420 k** (16) — 1 KiB, in-process | все данные в RAM |
| **MAX_STABLE_MESSAGES_PER_SEC** | **20 msg/s** (1P/1C, 1 KiB); **< 5 msg/s** (1P/10C) | e2e p99 < 1 s, backlog ≤ 1 s |
| **MAX_STABLE_MB_PER_SEC** (channels) | **0.02 MB/s** (1 KiB); 100 KiB — NOT DETERMINED (< 0.68 MB/s) | |
| **MAX_STABLE_CHANNEL_THROUGHPUT** | 20 msg/s / 0.02 MB/s | |
| **MAX_STABLE_CONNECTIONS** | **≥ 15 000** (control plane, предел генератора); **1** (SQL Core IPC) | 0 ошибок, p99 208 ms при 15 000 |
| **MAX_STABLE_LOAD** | ≈ 20 durable msg/s по каналу **или** ≈ 40–90 durable writes/s + сотни тысяч reads/s из RAM | ресурс насыщения: mutex + F_FULLFSYNC, не CPU-ядра и не диск |

---

## Limitations

* **Одна машина, localhost:** генератор нагрузки и сервер делят 10 ядер; сетевые эффекты (RTT, пропускная способность) не измерялись. Avrora KV/каналы/триггеры измерены **in-process** (embedded API); CPU in-process сценариев включает генератор.
* **Avrora root-identity** получена через `create_dev(false)` → `devo_init`: это единственный путь её создания; vault, созданный через control-plane `DbCreate` (`Runtime::create`), не имеет admin-сессии (`OpenAdminSession` → `Locked`). Шифрование/журнал/AuthZ при этом идентичны.
* **PostgreSQL RSS** суммируется по процессам и завышен (shared buffers); CPU PG в ramp соединений основного прогона = 0 из-за ошибки инструмента — использованы данные supp-прогона.
* **Консьюмер-сценарии** используют polling (`consume` + sleep 200 µs при пустом ответе) — push-API нет.
* **PostgreSQL TLS** не измерялся (NOT VERIFIED); Avrora remote измерен только через control plane (TLS+mTLS); `dmc-remote` (TLS для SQL Core) не поднимается ни одним бинарём — NOT VERIFIED.
* **SQL Core 1 MiB**: не поддерживается (лимит 1 MiB на SQL/frame); 100 KiB SELECT LIMIT 100 и конкурентные 100 KiB сценарии — 0 результатов из-за остановки listener.
* **Consumer groups** (group_consume/group_ack) в нагрузочных тестах не измерялись — NOT VERIFIED; использовались независимые подписки.
* **Крэш-тесты** — SIGKILL процесса; отключение питания/потеря кэша накопителя не моделировались (NOT VERIFIED), хотя использование F_FULLFSYNC делает это допущение обоснованным.
* **Длительность:** 30 s измерения; долговременные эффекты (часы, рост журнала до ГБ, компакция) — NOT VERIFIED.
* **Мобильность результатов:** абсолютные числа fsync специфичны для Apple SSD + F_FULLFSYNC; на Linux с `fdatasync` записи Avrora были бы быстрее, но относительные bottleneck'и (O(N) key tree, mutex, consumer-путь) от ОС не зависят.

---

## Conclusions

1. **Безопасность (цель 1):** шифрование хранения и TLS 1.3 сами по себе дёшевы (≈ 0 % на 1 KiB записи, +13.5 % latency транспорта). Дорогими являются протокол (JSON-байты, ×26 на чтении) и durability (F_FULLFSYNC). Корректность под SIGKILL подтверждена: 0 потерь подтверждённых записей и ACK.
2. **Скорость (цель 2):** чтение из RAM быстрое (≈ 600 k ops/s, быстрее PG через embedded API), но durable-запись — **42 ops/s** (в 6–65 раз медленнее PostgreSQL при сопоставимой durability) и **деградирует с ростом числа ключей**. SQL Core на 2–4 порядка медленнее PostgreSQL. Avrora **не быстрее** PostgreSQL ни в одной операции записи и ни в одном SQL-сценарии.
3. **Kafka-like каналы (цель 3):** семантика корректна (at-least-once, порядок, retry, DLQ, idempotent producer, 0 дублей, 0 нарушений порядка), но пропускная способность — **20 msg/s устойчиво** на одного потребителя и < 5 msg/s при fan-out на 10; batch ACK не работает (in-flight = 1), producer backpressure отсутствует.
4. **Масштабируемость соединений** высокая (≥ 15 000 TLS-соединений без ошибок), но **пропускная способность фиксирована** (~90 k req/s, 2 ядра) из-за глобального mutex.
5. Перед оптимизацией приоритетны (в порядке ожидаемого эффекта): убрать O(N) `node_bundle`, ввести group commit / batch-API и сократить число F_FULLFSYNC на запись; снять глобальный mutex для чтений; переписать consumer-путь (индекс по offset вместо полного скана, batch-доставка, несколько in-flight, накопительная запись consumer-meta); бинарная сериализация байтов в протоколе; аппаратный AES; устранить fail-stop SQL Core listener.

---

Benchmark date: 2026-10-03
Commit: 0ec23fb0bcd8f86a3784dc2de22496057a4f0ee9 (+ uncommitted benchmark infrastructure)
Results: `bench-results/v1/run-20261003/` (+ `run-20261003-supp/`)
Benchmark source: `crates/dmc-bench/src/bin/bench_v1/`, `crates/dmc-bench/run_v1.sh`, `crates/dmc-bench/summarize_v1.py`
