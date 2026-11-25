# Sync protocol

`tide-sync` — бинарный протокол синхронизации вместо IMAP/JMAP. Транспорт — TCP с TLS (ALPN `tide-sync/1`), кадры фиксированного формата, payload — SilentProto.

## Кадр

```
0..4    magic "TDS1"
4       version (1)
5       kind
6..8    flags u16
8..12   payload_len u32
12..16  payload_crc32c
16..    payload
```

Максимальный payload — 16 МиБ. Заголовок проверяется по magic/version/длине, payload — по CRC32C. Ошибка кадра закрывает соединение или возвращает `ERROR`.

## Типы кадров

| Kind | Сообщение |
|---|---|
| 1 | `HELLO` |
| 2 | `HELLO_OK` |
| 3 | `AUTH` |
| 4 | `AUTH_OK` |
| 5 | `PULL` |
| 6 | `CHANGES` |
| 7 | `PUSH` |
| 8 | `PUSH_OK` |
| 9 | `ACK` |
| 10 | `WATCH` |
| 11 | `EVENT` |
| 12 | `BLOB_REQUEST` |
| 13 | `BLOB_CHUNK` |
| 14 | `ERROR` |
| 15 | `PING` |
| 16 | `PONG` |

## Handshake

```
client → HELLO { protocol_version, client_id, capabilities }
server → HELLO_OK { protocol_version, server_id, capabilities, server_time }
client → AUTH { account_id, token, device_id }
server → AUTH_OK { account_id, cursor }
```

После `AUTH_OK` сессия готова к `PULL`/`PUSH`/`WATCH`/`BLOB_REQUEST`.

## Курсоры

```rust
Cursor { lane: u32, seq: u64 }
```

Аккаунт закреплён за lane, все его изменения имеют монотонный `seq`. `AUTH_OK` возвращает текущий head; для первичной синхронизации клиент запрашивает `PULL` с `seq = 0`.

`CHANGES.next_cursor` — позиция после последнего отданного изменения, `has_more` — есть ли ещё.

## Изменения

`SyncChange`:

- `kind`: `UPSERT`, `DELETE`, `FLAGS`, `MOVE`
- `message_id`, `seq`
- `meta: MessageMeta` для upsert/flags/move
- `flags` для FLAGS
- `mailbox` для MOVE
- `deleted`
- `payload` — зарезервировано под тело/вложения

`PULL` фильтрует по аккаунту, лимиту, папке и `include_deleted`.

## Push

`PUSH { account_id, txn_id, operations }`:

| Operation | Действие |
|---|---|
| `FLAGS` | абсолютная установка флагов |
| `DELETE` | удаление |
| `MOVE` | смена папки |
| `PUT_MESSAGE` | пока не поддержано сервером |

`txn_id` идемпотентен: повторный push с тем же `txn_id` возвращает сохранённый результат. Ответ `PUSH_OK` содержит `applied`, `rejected`, `cursor`.

## Blob

`BLOB_REQUEST { message_id, attachment_id, offset, length }` → `BLOB_CHUNK { data, eof }`. `attachment_id` — индекс вложения в сообщении (в API он же `AttachmentMeta.id`).

## Watch

`WATCH` возвращает `EVENT` при наличии изменения после курсора или пустой `CHANGES`. Транспортный слой может повторять запрос для long-poll; в TCP-сессии сервер отвечает сразу.

## TLS

Сервер использует тот же сертификат, что и SMTP. ALPN: `tide-sync/1`, `http/1.1`. Если TLS не настроен, sync работает в plain-режиме для локальной разработки.

## Пример

```rust
let (mut client, hello) = ClientSession::new("device-1", "laptop");
write_frame(&mut stream, hello);
client.handle(read_frame(&mut stream))?;

let auth = client.auth_frame("alice@example.com", token, "device-1")?;
write_frame(&mut stream, auth);
client.handle(read_frame(&mut stream))?;

let pull = client.pull_frame_at("alice@example.com", Cursor { lane: 2, seq: 0 }, 100, None)?;
write_frame(&mut stream, pull);
match client.handle(read_frame(&mut stream))? {
    ClientEvent::Changes(changes) => { /* apply */ }
    _ => {}
}
```

## Ограничения

- Нет сжатия кадров (capability зарезервирована).
- Нет постоянной server-side очереди push между рестартами клиента: клиент повторяет с `txn_id`.
- `PUT_MESSAGE` через sync пока отклоняется; новые письма создаются через SMTP/REST send.
