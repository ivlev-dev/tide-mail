# Tide Mail

All-in-one почтовый сервер на Rust: SMTP с TLS/STARTTLS/implicit TLS, собственное mmap-хранилище, полнотекстовый поиск, бинарный REST API на `silent-protocol` и sync-протокол вместо IMAP/JMAP.

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
http_tls = false
smtp_addr = "127.0.0.1:2525"
smtps_addr = "127.0.0.1:4650"
# lmtp_addr = "127.0.0.1:2424"
submission_addr = "127.0.0.1:5870"
sync_addr = "127.0.0.1:9093"
token_ttl_hours = 168
outbound_enabled = false
outbound_tls = true
dsn_enabled = true
mta_sts = true
dane = false
admin_token = "change-admin-token"
# report_dir = "./data/reports"
dmarc_reports = true
tls_rpt = true

[tls]
self_signed = true

[email_auth]
enabled = true
reject_spf_fail = false
reject_dmarc_fail = false

[spam]
enabled = true
threshold = 5.0
reject_threshold = 15.0

[dkim]
# domain = "mail.local"
# selector = "default"
# private_key_path = "./certs/dkim.key"

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

- Порты 25/465/587 (в примере 2525/4650/5870), LMTP, implicit TLS, STARTTLS, AUTH PLAIN/LOGIN.
- ESMTP: SIZE, 8BITMIME, SMTPUTF8, PIPELINING, CHUNKING/BDAT, BINARYMIME, DSN, REQUIRETLS, FUTURERELEASE, DELIVERBY.
- Trace-заголовки, IDNA, address literals, отклонение BURL.
- Входящие SPF/DKIM/DMARC/ARC/DKIM2, исходящие DKIM + opportunistic TLS + MTA-STS + DANE.
- DMARC aggregate/failure reports и TLS-RPT через outbound-очередь.
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

## Эксплуатация

- [Конфигурация](docs/configuration.md)
- [Blob-store вложений](docs/blob-store.md)
- [Antivirus scanning](docs/antivirus.md)
- [Backup и HA](docs/backup-ha.md)
- [Sharded index](docs/index-sharding.md)
- [RFC coverage](docs/rfc.md)
- [Аудит безопасности](docs/security.md)
- [Аудит производительности](docs/performance.md)

## Тесты

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

E2E-тест (`crates/tide-server/tests/e2e.rs`) поднимает сервер и проверяет:

1. SMTP-доставку и маршрутизацию спама в `Junk`;
2. бинарный REST login/search/get/list/flags, папки, вложения, download;
3. sync handshake, pull, push flags и `PUT_MESSAGE`;
4. snapshot и online-компакцию через admin API.

## Дополнительно

- Снапшоты индекса: пишутся в index lane, загружаются при старте, replay идёт с checkpoint.
- Group commit в lane, отдельный apply-поток, bulk-импорт, шардированные postings и параллельный поиск.
- Online-компакция: `POST /v1/admin/compact` (нужен `admin_token`).
- Outbound: MX-резолв, DKIM, opportunistic STARTTLS, персистентная очередь.
- Входящие SPF/DKIM/DMARC через `mail-auth` + `Authentication-Results`.
- HTTP TLS (`http_tls`) и CORS.
- `PUT_MESSAGE` через sync.
- Blob-store вложений, ClamAV/external antivirus, backup API, account-sharded индекс.

## Roadmap

- Векторный семантический поиск и эмбеддинги (секция в формате зарезервирована).
- ACL на уровне папок и JMAP-совместимый шлюз.
- Rate limit, audit log, virus-scan hook и шардирование postings.

## Лицензия

MIT.
