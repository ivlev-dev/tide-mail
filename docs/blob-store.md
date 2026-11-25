# Blob-store вложений

Крупные вложения выносятся из `Message.payload` в content-addressed blob-store на диске.

## Структура

```
data/blobs/
  ab/
    cd/
      abcdef...64hex
  tmp/
```

- Имя файла — SHA-256 содержимого.
- Дедупликация: одинаковые вложения хранятся один раз.
- Запись: temp-файл → `fsync` → atomic `rename`.
- ID проверяется как ровно 64 hex-символа; path traversal невозможен.

## Связь с письмом

В stores остаётся `Attachment` с `data = []`, а ссылка хранится отдельной `META`-записью:

```text
BlobRefRecord { message_id, attachment_id, blob_id }
key = blobref:<message_id>:<attachment_id>
```

`Db::append_message_with_blobs`:

1. кладёт каждый непустой `Attachment.data` в blob-store;
2. очищает `data`;
3. пишет письмо и `blobref`-записи в одном батче;
4. apply-поток обновляет карту ссылок.

`Db::get_attachment` сначала смотрит inline `data`, затем `blobref` + blob-store. API download и sync `BLOB_REQUEST` используют этот метод.

## S3 backend

```toml
[blob]
backend = "s3"
bucket = "tide-mail"
region = "us-east-1"
endpoint = "https://s3.example.com"
access_key_id = "..."
secret_access_key = "..."
prefix = "blobs"
allow_http = false
```

Поддерживается любой S3-совместимый сервис (MinIO, R2, Wasabi). Ключ объекта — `<prefix>/<sha256>`. S3-режим использует `object_store`; локальный кеш не ведётся.

## Обслуживание

- `compact` перечитывает blob из старого store и заново раскладывает в новый.
- `backup_to` копирует `mail.tide` и каталог `blobs`.
- GC: `POST /v1/admin/gc-blobs` удаляет нереференсные объекты старше `blob_gc_grace_secs` (по умолчанию 3600).
- Каталог задаётся `server.blob_dir`; по умолчанию рядом с `mail.tide` в `blobs/`.
