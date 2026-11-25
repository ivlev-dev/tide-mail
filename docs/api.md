# REST API

HTTP/1.1, тела запросов и ответов — SilentProto (`application/silent`). JSON используется только для `/health`.

## Аутентификация

```http
POST /v1/auth/login
Content-Type: application/silent

AuthRequest { account_id, password, device_id, device_name }
```

Ответ:

```http
200 OK
Content-Type: application/silent

AuthResponse { token, refresh_token?, expires_at, account }
```

Далее:

```http
Authorization: Bearer <token>
```

`POST /v1/auth/logout` отзывает токен. Токены живут в памяти процесса и сбрасываются при рестарте.

## Эндпоинты

| Метод | Путь | Тело | Ответ |
|---|---|---|---|
| GET | `/health` | — | JSON |
| POST | `/v1/auth/login` | `AuthRequest` | `AuthResponse` |
| POST | `/v1/auth/logout` | — | `AckResponse` |
| POST | `/v1/mailboxes` | `MailboxListRequest` | `MailboxListResponse` |
| POST | `/v1/folders/list` | `FolderListRequest` | `MailboxListResponse` |
| POST | `/v1/folders/create` | `FolderCreateRequest` | `AckResponse` |
| POST | `/v1/folders/rename` | `FolderRenameRequest` | `AckResponse` |
| POST | `/v1/folders/delete` | `FolderDeleteRequest` | `AckResponse` |
| POST | `/v1/messages/list` | `ListRequest` | `ListResponse` |
| POST | `/v1/messages/get` | `GetMessageRequest` | `GetMessageResponse` |
| POST | `/v1/search` | `SearchRequest` | `SearchResponse` |
| POST | `/v1/messages/flags` | `FlagsRequest` | `AckResponse` |
| POST | `/v1/messages/delete` | `DeleteRequest` | `AckResponse` |
| POST | `/v1/messages/move` | `MoveRequest` | `AckResponse` |
| POST | `/v1/send` | `SendRequest` | `SendResponse` |
| POST | `/v1/send/attachments` | `SendWithAttachmentsRequest` | `SendResponse` |
| GET | `/v1/attachments/{message_id}/{attachment_id}` | — | raw file |
| POST | `/v1/admin/snapshot` | — | `AckResponse` |
| POST | `/v1/admin/compact` | — | `AckResponse` |
| POST | `/v1/admin/backup` | — | `AckResponse` |

`account_id` во всех запросах должен совпадать с аккаунтом токена.

Админ-эндпоинты требуют заголовок `X-Admin-Token`, равный `server.admin_token`. Если токен не задан, админ-API отключён.

## Поиск

```rust
SearchRequest {
    account_id,
    query,                 // общий текст: subject + body
    subject: Option<String>,
    body: Option<String>,
    from: Option<String>,
    mailbox: Option<String>,
    include_deleted: bool,
    limit,
    offset,
}
```

`SearchResponse` содержит `hits: Vec<SearchHit>`, `total`, `took_micros`. `SearchHit` = `MessageMeta` + `score` + `snippet`.

Поиск идёт по in-memory индексу, без обращения к диску. Поддерживаются AND-термы, поля, фильтры аккаунта/папки/флагов.

## Ошибки

```rust
ErrorResponse { code, message, retryable }
```

HTTP-статус совпадает с `code` для типовых ошибок: 400, 401, 404, 500, 503.

## Пример клиента

```rust
use silent_protocol::SilentProto;
use tide_proto::{AuthRequest, SearchRequest};

let login = AuthRequest {
    account_id: "alice@example.com".into(),
    password: "secret".into(),
    device_id: "laptop".into(),
    device_name: "Laptop".into(),
};
let body = login.encode()?;

// POST /v1/auth/login с Content-Type: application/silent
// AuthResponse::decode(&response_body)?
```

Полный E2E-пример: `crates/tide-server/tests/e2e.rs`.

## Соответствие доменной модели

- `tide_core::Message` — полное письмо, включая raw MIME и вложения.
- `tide_proto::MessageMeta` — метаданные для списков/поиска.
- `tide_proto::MessageBody` — text/html, вложения, raw.
- Вложения в API адресуются индексом (`AttachmentMeta.id`), blob можно забрать через sync `BLOB_REQUEST`.

## Вложения

`GET /v1/attachments/...` отдаёт raw bytes с `Content-Type` и `Content-Disposition`. `attachment_id` — индекс в `Message.attachments` (он же `AttachmentMeta.id`). Лимит загрузки — 64 МиБ.

## CORS и TLS

- CORS включён: `Access-Control-Allow-Origin: *`, `OPTIONS` возвращает 204.
- `http_tls = true` включает HTTPS на `http_addr` с тем же сертификатом, что SMTP/sync.
