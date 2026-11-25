# Configuration

Полный пример — `deploy/tide.toml`. Ниже все ключи.

## `[server]`

| Ключ | Тип | Назначение |
|---|---|---|
| `hostname` | string | EHLO/сертификат/DSN |
| `data_path` | path | файл `mail.tide` |
| `blob_dir` | path? | blob-store вложений |
| `backup_dir` | path? | каталог backup-эндпоинта |
| `blob_gc_grace_secs` | u64 | grace period GC |
| `standby` | bool | ждать освобождения БД и стать primary |
| `data_lanes` | u16 | число data-lane (1..128) |
| `lane_capacity_mb` | u64 | ёмкость одного lane, МиБ |
| `workers` | usize | число io_uring-воркеров |
| `http_addr` | string | REST bind |
| `http_tls` | bool | HTTPS на `http_addr` |
| `smtp_addr` | string? | MX/приём |
| `smtps_addr` | string? | implicit TLS SMTP |
| `submission_addr` | string? | submission |
| `sync_addr` | string? | sync TCP |
| `token_ttl_hours` | u64 | TTL bearer-токенов |
| `outbound_enabled` | bool | включить исходящую очередь |
| `outbound_tls` | bool | opportunistic STARTTLS |
| `outbound_dir` | path? | очередь, по умолчанию рядом с `mail.tide` |
| `dsn_enabled` | bool | генерировать DSN |
| `mta_sts` | bool | проверять MTA-STS |
| `dane` | bool | проверять DANE TLSA |
| `snapshot_interval_secs` | u64 | автоснапшоты (0 = выключить) |
| `admin_token` | string? | доступ к `/v1/admin/*` |

## `[tls]`

```toml
cert_path = "/etc/tide/fullchain.pem"
key_path = "/etc/tide/privkey.pem"
self_signed = false
```

Если пути не заданы и `self_signed = true`, генерируется самоподписанный сертификат для `hostname`.

## `[email_auth]`

```toml
enabled = true
reject_spf_fail = false
reject_dmarc_fail = false
```

Требует системный DNS resolver.

## `[blob]`

```toml
backend = "local" # или "s3"
bucket = "tide-mail"
region = "us-east-1"
endpoint = "https://s3.example.com"
access_key_id = "..."
secret_access_key = "..."
prefix = "blobs"
allow_http = false
```

## `[antivirus]`

```toml
enabled = true
async_scan = false
quarantine_folder = "Quarantine"
infected_folder = "Virus"
clamav_addr = "127.0.0.1:3310"
# command = "clamdscan"
```

## `[spam]`

```toml
enabled = true
threshold = 5.0
reject_threshold = 15.0
dnsbl_zones = ["zen.spamhaus.org"]
external_command = "spamassassin"
```

`external_command` — доверенная команда администратора, без shell.

## `[dkim]`

```toml
domain = "example.com"
selector = "default"
private_key_path = "/etc/tide/dkim.key"
```

Ключ читается RSA PKCS#1/PKCS#8 PEM.

## `[[accounts]]`

```toml
email = "alice@example.com"
password = "change-me"
name = "Alice"
```

Пароль хешируется Argon2id при старте; в памяти хранится только хеш.

## Переменные окружения

Сейчас конфигурация только через TOML. Секреты рекомендуется монтировать файлами с правами `0600`.
