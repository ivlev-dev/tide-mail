# Attachments

Вложения хранятся внутри `Message` (`Vec<Attachment>`) и сжимаются вместе с payload. Для больших вложений формат допускает вынос blob в отдельную секцию, но текущая версия хранит данные inline.

## Отправка с вложениями

```rust
SendWithAttachmentsRequest {
    account_id,
    envelope_from,
    envelope_to,
    subject,
    text,
    html: Option<String>,
    attachments: Vec<AttachmentData {
        filename,
        content_type,
        data,
    }>,
}
```

`POST /v1/send/attachments` собирает MIME:

- `multipart/alternative` для text/html;
- `multipart/mixed` при наличии файлов;
- base64, line wrap 76;
- проверка CRLF в заголовках и лимит 64 МиБ на вложения.

## Скачивание

```http
GET /v1/attachments/{message_id}/{attachment_id}
Authorization: Bearer <token>
```

`attachment_id` — индекс вложения в `Message` (он же `AttachmentMeta.id`). Ответ:

```http
200 OK
Content-Type: <content_type>
Content-Disposition: attachment; filename="<filename>"
```

Проверяется принадлежность письма аккаунту токена. Sync-клиент может получить тот же blob через `BLOB_REQUEST` с range.

## Ограничения

- Inline-хранение увеличивает размер записи; для больших файлов нужен blob-store.
- Нет virus-scan hook; его можно добавить как `SpamFilter`/external command.
- Нет отдельного upload-эндпоинта: файл передаётся вместе с отправкой или приходит по SMTP.
