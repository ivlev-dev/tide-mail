# Аудит производительности

## Методика

`crates/tide-store/examples/bench.rs`:

- 5 000 писем, тело ~1 КиБ, 8 data-lane по 64 МиБ;
- release build;
- append через `Db::append_message_blocking` (durable `RWF_DSYNC`);
- 100 поисков по `invoice` с лимитом 50;
- snapshot (`flush`) и повторное открытие.

Запуск:

```bash
cargo run --release -p tide-store --example bench
```

## Результат на тестовой машине

```text
messages=5000 append=269ms (18603/s) snapshot=25ms search100=84ms hits=5000 reopen=19.9ms
same-account concurrent messages=16000 append=488ms (32811/s) apply_pending=16000
```

| Метрика | Значение |
|---|---|
| durable append, один поток | ~18 600 msg/s |
| group commit, 16 потоков | ~32 800 msg/s |
| snapshot 5k | ~25 мс |
| поиск | ~0.84 мс/запрос |
| reopen со снапшотом | ~19.9 мс |

Цифры зависят от диска: `RWF_DSYNC` упирается в fsync/кэш накопителя. На NVMe результаты выше, на HDD — ниже.

## Найденные и исправленные проблемы

1. **O(N²) поиск.** IDF для каждого термина пересчитывался для каждого кандидата; `tf()` линейно сканировал posting list. IDF считается один раз, `tf()` использует binary search. 100 запросов: ~98.6 с → ~1.3 с.
2. **Лишние аллокации поиска.** Раньше для всех кандидатов клонировались строки и строились `SearchHit`; теперь скоринг хранит только `(doc_id, score, date)`, top-k выбирается `select_nth_unstable_by`, объекты и сниппеты строятся только для страницы. 100 запросов: ~1.3 с → ~0.13 с (~8x).
3. **Двойной decode при записи.** `append_message` больше не декодирует только что закодированное сообщение повторно.
4. **HTTP keep-alive.** Соединение переиспользуется для нескольких запросов вместо одного; для API это даёт кратный рост при последовательных запросах.
5. **Snapshot без checkpoint.** Индекс пересобирался с нуля; теперь manifest + replay хвоста, reopen 18 мс.
6. **Lane-sharded append.** Нет глобального WAL/fsync; разные аккаунты пишутся параллельно.
7. **Group commit внутри lane.** Один `RWF_DSYNC` на пачку до 64 батчей/8 МиБ; разные lane коммитят независимо.
8. **Отдельный apply-поток.** Индекс/каталог/change log обновляются вне I/O-потока, с переупорядочиванием по `seq`.
9. **Bulk append.** `append_messages` группирует письма в батчи до 1000 записей — для импорта.
10. **Postings sharding.** 16 шардов по хешу терма; поиск по кандидатам >=4096 выполняется через rayon параллельно.

## Узкие места

- `RWF_DSYNC` на каждый батч: максимизирует durability, но ограничивает throughput диском. Опция `Durability::None` есть для benchmark, но не для production.
- `snapshot`/`compact` берут write-barrier: запись ждёт, чтение продолжается.
- HTTP реализован без keep-alive: один запрос на соединение.
- SMTP/HTTP не имеют rate limit; при атаке возможен resource exhaustion.
- Индекс полностью в RAM; 100k писем с большими телами требуют планирования памяти.

## Рекомендации

1. Для высоких нагрузок: NVMe, отдельный диск под `mail.tide`, `data_lanes >= workers`.
2. Включить `snapshot_interval_secs` (300–900) и периодическую компакцию в maintenance window.
3. Для >100k писем — шардировать индекс по account/term.
4. Добавить keep-alive и rate limit на HTTP/SMTP.
5. Мерить `iostat`/`fio` на целевом диске; `RWF_DSYNC` чувствителен к latency.
