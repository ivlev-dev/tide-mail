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
messages=5000 append=357.8ms (13974/s) snapshot=24.0ms search100=1.074s hits=5000 reopen=18.5ms
```

| Метрика | Значение |
|---|---|
| durable append | ~14 000 msg/s |
| snapshot 5k | 24 мс |
| поиск | ~10.7 мс/запрос |
| reopen со снапшотом | 18.5 мс |

Цифры зависят от диска: `RWF_DSYNC` упирается в fsync/кэш накопителя. На NVMe результаты выше, на HDD — ниже.

## Найденные и исправленные проблемы

1. **O(N²) поиск.** IDF для каждого термина пересчитывался для каждого кандидата. IDF теперь считается один раз до скоринга. На 5k писем 100 запросов ускорились с ~98.6 с до ~1.07 с.
2. **Snippet для всех кандидатов.** Сниппеты строились до `limit`; теперь только для финальной страницы.
3. **Snapshot без checkpoint.** Индекс пересобирался с нуля; теперь manifest + replay хвоста, reopen 18 мс.
4. **Group commit и один WAL.** Заменены на lane-sharded append с независимыми `RWF_DSYNC`, это убрало глобальную сериализацию.
5. **Единый `RwLock` индекса.** Поиск и запись конкурируют; для больших аккаунтов рекомендуется шардирование postings (roadmap).

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
