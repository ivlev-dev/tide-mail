# Antivirus scanning

Проверка вложений/сырого письма перед сохранением.

## Синхронный и асинхронный режим

```toml
[antivirus]
enabled = true
async_scan = false
quarantine_folder = "Quarantine"
infected_folder = "Virus"
```

- `async_scan = false` — письмо сканируется до ответа SMTP/API.
- `async_scan = true` — входящее письмо сразу кладётся в `Quarantine`, SMTP отвечает `250`, фоновый поток сканирует:
  - clean → `INBOX`;
  - infected → `Virus`;
  - scanner error → остаётся в `Quarantine`.

Rescan существующих писем:

```http
POST /v1/admin/rescan
X-Admin-Token: ...
```

При старте воркер сам ставит в очередь всё, что лежит в `Quarantine`.

## Режимы

- **ClamAV TCP**: `INSTREAM`-протокол на `clamav_addr` (обычно `127.0.0.1:3310`).
- **External command**: команда получает письмо на stdin, печатает результат; признаки заражения — `FOUND` или ненулевой exit code.

```toml
[antivirus]
enabled = true
clamav_addr = "127.0.0.1:3310"
# command = "clamdscan"

[server]
blob_dir = "./data/blobs"
```

## Где вызывается

- SMTP inbound/submission: до маршрутизации и записи.
- REST `/v1/send` и `/v1/send/attachments`.
- Sync `PUT_MESSAGE`.

Заражённое письмо отклоняется:

```text
550 5.7.1 Message rejected by antivirus scanner
```

Для API — `ErrorResponse` с сообщением сканера.

## Ограничения

- Карантин — папка, без UI release; письмо можно переместить вручную через API/IMAP-клиент.
- Async scan использует in-memory очередь; после рестарта Quarantine пересканируется.
- Нет проверки уже сохранённых писем и повторного scan при обновлении баз.
- External command — доверенная конфигурация администратора.
