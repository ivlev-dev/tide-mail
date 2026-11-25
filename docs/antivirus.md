# Antivirus scanning

Проверка вложений/сырого письма перед сохранением.

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

- Нет карантина: письмо не сохраняется.
- Нет асинхронного scan-queue; при медленном ClamAV SMTP-сессия ждёт.
- Нет проверки уже сохранённых писем и повторного scan при обновлении баз.
- External command — доверенная конфигурация администратора.
