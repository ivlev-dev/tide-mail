# Tide Mail

All-in-one почтовый сервер на Rust: SMTP с TLS/STARTTLS, собственное mmap-хранилище, полнотекстовый поиск, бинарный REST API на `silent-protocol` и sync-протокол вместо IMAP/JMAP.

Репозиторий: <https://github.com/ivlev-dev/tide-mail>

## Архитектура

```
                    +-------------------+
  SMTP 25/587  ---> |  tide-smtp        | ---+
                    |  sans-IO session  |    |
                    +-------------------+    |
                                             v
  HTTP REST    ---> +-------------------+  +------------------+
  silent-proto      |  tide-server      |->|  tide-store      |
                    |  monoio/io_uring  |  |  mail.tide mmap  |
  Sync TCP/TLS ---> +-------------------+  |  lanes + FTS     |
                                             +------------------+
```

- `tide-core` — доменная модель, MIME-парсинг (`mail-parser`), треды, флаги.
- `tide-proto` — SilentProto-схемы REST/sync и фрейминг `TDS1`.
- `tide-store` — один файл `mail.tide`, lane-sharded append-only log, `RWF_DSYNC`, восстановление, инвертированный индекс.
- `tide-smtp` — sans-IO SMTP: парсер, состояние, reply, клиент.
- `tide-sync` — sans-IO синхронизация: handshake, курсоры, pull/push/watch/blob.
- `tide-server` — сервер на monoio: N io_uring-воркеров, SMTP, HTTP, sync, outbound-очередь.

## Быстрый старт

```bash
cargo run -p tide-server -- tide.toml
```

При первом запуске будет создан `tide.toml`. Заполните `[[accounts]]` и запустите снова.

```toml
[server]
hostname = "mail.local"
data_path = "./data/mail.tide"
data_lanes = 8
lane_capacity_mb = 512
workers = 2
http_addr = "127.0.0.1:8080"
smtp_addr = "127.0.0.1:2525"
submission_addr = "127.0.0.1:5870"
sync_addr = "127.0.0.1:9093"
token_ttl_hours = 168
outbound_enabled = false

[tls]
self_signed = true

[[accounts]]
email = "alice@mail.local"
password = "change-me"
name = "Alice"
```

Docker:

```bash
docker compose up --build
```

Для io_uring в контейнере нужен `seccomp:unconfined` (уже указан в compose).

## SMTP

- Порты 25/587 (в примере 2525/5870), STARTTLS, AUTH PLAIN/LOGIN.
- ESMTP: SIZE, 8BITMIME, SMTPUTF8, PIPELINING.
- Входящие письма маршрутизируются локальным аккаунтам, парсятся и индексируются.
- Submission с внешними получателями ставит письма в outbound-очередь (если `outbound_enabled`).

```python
import smtplib
from email.message import EmailMessage

msg = EmailMessage()
msg["From"] = "bob@example.com"
msg["To"] = "alice@mail.local"
msg["Subject"] = "Tide hello"
msg.set_content("Hello from SMTP")

with smtplib.SMTP("127.0.0.1", 2525) as smtp:
    smtp.send_message(msg)
```

## REST API

Тела — SilentProto (`application/silent`), авторизация — Bearer-токен.

| Метод | Путь |
|---|---|
| POST | `/v1/auth/login` |
| POST | `/v1/auth/logout` |
| POST | `/v1/mailboxes` |
| POST | `/v1/messages/list` |
| POST | `/v1/messages/get` |
| POST | `/v1/search` |
| POST | `/v1/messages/flags` |
| POST | `/v1/messages/delete` |
| POST | `/v1/messages/move` |
| POST | `/v1/send` |

Подробности и типы: [docs/api.md](docs/api.md).

## Хранилище

Один файл, mmap, без отдельного WAL:

- superblock A/B с generation и CRC32C;
- lane на аккаунт, каждый lane — свой io_uring-ring и writer-поток;
- батч пишется одним `IORING_OP_WRITE` с `RWF_DSYNC`;
- footer батча — commit-запись, torn tail отбрасывается;
- разные аккаунты пишутся параллельно, внутри lane порядок сохраняется;
- подтверждённая запись переживает `kill -9` и потерю питания.

Подробности: [docs/storage.md](docs/storage.md).

## Sync

Собственный бинарный протокол вместо IMAP/JMAP:

- кадры `TDS1` с CRC32C;
- handshake → auth → pull/push/watch/blob;
- курсор `(lane, seq)`, идемпотентный `txn_id`;
- TLS с ALPN `tide-sync/1`;
- server push через `WATCH`.

Подробности: [docs/sync.md](docs/sync.md).

## Тесты

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

E2E-тест (`crates/tide-server/tests/e2e.rs`) поднимает сервер и проверяет:

1. SMTP-доставку;
2. бинарный REST login/search/get/list/flags;
3. sync handshake, pull и push.

## Ограничения текущей версии

- Векторный семантический поиск и эмбеддинги отложены; секция в формате зарезервирована.
- Нет online-компакции и снапшотов индекса: индекс пересобирается при старте.
- Outbound: нет MX-резолва, DKIM-подписи, opportunistic TLS ипостоянной очереди.
- Нет SPF/DKIM/DMARC-проверки входящих.
- HTTP API без TLS/CORS; для production ставить за reverse proxy.
- `PUT_MESSAGE` через sync пока не поддержан.

## Лицензия

MIT.
