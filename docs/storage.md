# Хранилище TDB1

`tide-store` хранит почту в одном файле `mail.tide`. Чтение идёт через mmap без копирования, запись — через `pwrite` с `RWF_DSYNC`; изменения сразу видны в mapping. Файл разбит на lane — независимые append-only журналы. Аккаунт хешируется в lane, поэтому все изменения одного аккаунта упорядочены, а разные аккаунты пишутся параллельно.

## Раскладка файла

```
+----------------------+ 0
| Superblock A (4 KiB) |
+----------------------+ 4 KiB
| Superblock B (4 KiB) |
+----------------------+ 64 KiB
| Lane 0 (meta)        |
| Lane 1 (index)       |
| Lane 2 ... N+1       |
+----------------------+
```

- Superblock A и B — две копии с generation и CRC32C. При открытии выбирается валидная копия с большей generation.
- Lane 0 зарезервирован под метаданные, lane 1 — под снапшоты индекса, lane 2..N+1 — данные аккаунтов.
- Размер lane задаётся при создании (`lane_capacity_mb`), файл разреженный. По умолчанию 16 data-lane по 512 МиБ.
- Один процесс на файл: `flock(LOCK_EX | LOCK_NB)`.

Lane header (4 KiB) содержит `lane_id`, `capacity`, `head`, `seq`, `checkpoint_seq`, `checkpoint_head` и CRC.

## Батч

Запись всегда идёт целым батчем. Батч самодостаточен: в нём есть заголовок, записи и footer с CRC.

```
BatchHeader (64 B)
  magic "TDBB" | version | lane_id | flags
  total_len | txn_id | seq | created_at
  record_count | header_crc32c | reserved

Record 0..N
  magic "TDBR" | version | kind | flags
  key_len | payload_len | record_len
  key_crc32c | payload_crc32c | header_crc32c
  key | payload

BatchFooter (64 B)
  magic "TDBE" | version | flags
  total_len | record_count
  batch_crc32c | footer_crc32c | reserved
```

- `total_len` выровнен на 64 байта, footer всегда последние 64 байта.
- `batch_crc32c` покрывает header, записи и padding.
- Payload больше 1 КиБ сжимается zstd, флаг `RECORD_FLAG_ZSTD`.
- Типы записей: `MESSAGE`, `DELETE`, `FLAGS`, `MOVE`, `META`, `NOTE`.

## Запись и durability

1. Поток-писатель получает lane-мьютекс (внутри процесса), чтобы сохранить порядок операций аккаунта.
2. Батч кодируется в buffer.
3. Один `IORING_OP_WRITE` с `RWF_DSYNC` пишет батч по offset `head`.
4. После завершения io_uring-операции `head` и `seq` сдвигаются, батч применяется к индексу и каталогу.
5. Только после этого вызывающему возвращается `Receipt { durable: true }`.

`RWF_DSYNC` означает, что подтверждённая запись переживает `kill -9` и потерю питания в пределах возможностей диска. Отдельного WAL нет: footer батча и есть commit-запись.

### Параллелизм

- Разные lane используют разные writer-потоки и разные io_uring rings.
- Внутри lane writer собирает group commit: до 64 батчей / 8 МиБ в одном `RWF_DSYNC`.
- Индекс обновляет отдельный apply-поток, переупорядочивая батчи по `seq`.
- `append_messages` группирует импорт в батчи до 1000 записей.
- Postings разбиты на 16 шардов; поиск по большим выдачам распараллелен через rayon.
- Индекс обновляется после durable-коммита; при падении между коммитом и обновлением индекса состояние восстанавливается replay'ем.

## Снапшоты индекса

`Db::snapshot()` (и `flush()`) сериализует `SearchIndex`, каталог сообщений, change log и позиции lane в bincode + zstd. Снапшот режется на чанки по 8 МиБ и пишется в index lane (lane 1) как `META`-записи `snap:<id>:<chunk>`, затем манифест `snap:<id>`.

При старте:

1. Сканируется index lane и выбирается манифест с максимальным `id`, у которого есть все чанки.
2. Индекс, каталог и change log восстанавливаются из снапшота.
3. Data lane сканируются от `min(header.checkpoint_head, snapshot.head)`, батчи с `seq <= snapshot.seq` пропускаются.
4. Всё, что после снапшота, применяется заново.

Снапшот — оптимизация старта, а не источник истины. При повреждении снапшота выполняется полный replay.

## Online-компакция

`Db::compact()`:

1. Берёт эксклюзивный write-barrier (новые записи ждут, читатели работают).
2. Создаёт новый файл `<name>.compact` с теми же параметрами lane.
3. Переносит все активные сообщения (с учётом флагов/папок) в новый файл.
4. Делает снапшот и закрывает новый файл.
5. Атомарно заменяет старый файл новым через `rename`.
6. Переоткрывает БД и подменяет `DbInner` через `ArcSwap`.

Старые читатели доигрывают на старом mmap, новые видят новый файл. История sync сбрасывается: клиенты должны начать с `seq = 0`.

## Восстановление

1. Читаются superblock A/B, выбирается валидный с максимальной generation.
2. Загружается последний валидный снапшот из index lane.
3. Для каждого data lane проверяются magic, длины, header/footer CRC и batch CRC от checkpoint.
4. Первый невалидный батч считается оборванным хвостом; сканирование lane останавливается.
5. Индекс, каталог сообщений и change log дополняются батчами после снапшота.
6. Lane header перезаписывается актуальными `head`/`seq`, checkpoint сохраняется.

Битый хвост не приводит к потере предыдущих подтверждённых батчей.

## Папки

Папки account-scoped хранятся в data lane аккаунта как `META`-записи `folder:<name>`:

```text
FolderRecord { account_id, name, role, deleted, created_at, updated_at }
```

Они входят в снапшот и восстанавливаются вместе с индексом. `rename`/`delete` двигают письма батчами `MOVE` по 500 записей.

## Поиск

- Документный индекс в памяти: аккаунт, папка, тема, отправитель, получатели, дата, флаги, текст.
- Инвертированный индекс по полям `subject`, `body`, `from`, `to`.
- Токенизация Unicode, lowercase, Snowball (ru/en), стоп-слова.
- BM25, фильтры по аккаунту, папке, флагам, диапазону дат.
- Поиск выполняется по RAM, без чтения диска.
- Индекс account-sharded: 16 шардов; внутри postings ещё 16 шардов по терму.
- Вложения с `data=[]` ссылаются на content-addressed blob-store через `blobref:`-записи.
- GC blob: `POST /v1/admin/gc-blobs` с grace-периодом.

Векторная секция зарезервирована, эмбеддинги в текущей итерации не подключены.

## API

```rust
let db = Db::open("mail.tide", StoreOptions::default())?;
let receipt = db.append_message(message).await?;
let hits = db.search(&SearchQuery::new().account("alice@example.com").text("invoice"));
let cursor = db.sync_cursor("alice@example.com");
let changes = db.sync_changes("alice@example.com", 0, 100);
db.flush().await?;
```

## Ограничения текущей версии

- Fixed-capacity lane: увеличение ёмкости требует нового файла/компакции.
- `move` между аккаунтами не переносит физическую запись в другой lane; move используется для смены папки.
- Снапшоты и старые чанки не удаляются до компакции.
