# SMTP

`tide-smtp` — sans-IO библиотека, сервер и клиент используют один и тот же парсер команд, reply-формат и state machine.

## Порты

| Порт | Назначение | AUTH | STARTTLS |
|---|---|---|---|
| 25 / `smtp_addr` | MX, приём почты | нет | да, если TLS настроен |
| 587 / `submission_addr` | submission | да | да |
| 465 / `smtps_addr` | implicit TLS | нет | не нужен |
| 24 / `lmtp_addr` | LMTP | нет | нет |

Порты задаются в `tide.toml`; в примере используются непривилегированные 2525/5870.

## ESMTP

Поддерживаются:

- `EHLO` / `HELO`
- `MAIL FROM`, `RCPT TO`, `DATA`, `RSET`, `NOOP`, `QUIT`
- `SIZE`, `8BITMIME`, `SMTPUTF8`, `PIPELINING`
- `CHUNKING` / `BDAT`
- `BINARYMIME` (только через `BDAT`)
- `DSN`: `RET`, `ENVID`, `NOTIFY`, `ORCPT`
- `REQUIRETLS`, `FUTURERELEASE`, `DELIVERBY`
- IDNA-домены и IPv4/IPv6 address literals
- `STARTTLS`
- `AUTH PLAIN`, `AUTH LOGIN`, cancel через `*`
- `VRFY`, `HELP`
- enhanced status codes
- trace-заголовки `Received`, `Return-Path`, `Delivered-To`, loop limit
- `LHLO` и per-recipient ответы в режиме LMTP
- `BURL` явно отклоняется с `504`

## LMTP

При `lmtp_addr` сервер работает в режиме LMTP: принимает только `LHLO`, а после `DATA`/`BDAT` возвращает отдельный ответ на каждого получателя. Это удобно для локальной доставки из внешнего MTA.

## Очередь и DSN

- `MAIL FROM ... RET=HDRS|FULL ENVID=...` и `RCPT TO ... NOTIFY=... ORCPT=...` проверяются и сохраняются.
- Параметры передаются следующему MTA в outbound-транзакции.
- `RET=FULL` включает полное исходное письмо в failure DSN, иначе только заголовки.
- `NOTIFY=SUCCESS` включает success DSN, `NOTIFY=NEVER` подавляет отчёты, `NOTIFY=FAILURE` включает только failure.
- `FUTURERELEASE=<секунды>` удерживает письмо в очереди до указанного времени.
- `DELIVERBY=<секунды>` задаёт дедлайн; после его истечения формируется failure DSN.
- `REQUIRETLS` требует TLS при outbound-доставке.

Ограничения: размер сообщения, число получателей, длина строки, таймауты соединения (на уровне транспорта).

## STARTTLS

1. Клиент отправляет `STARTTLS`.
2. Сервер отвечает `220 Ready to start TLS`.
3. Соединение оборачивается в `monoio-rustls`; состояние SMTP сбрасывается (`EHLO`, envelope, auth).
4. Клиент повторяет `EHLO` и, при необходимости, `AUTH`.

Сертификат берётся из `tls.cert_path` / `tls.key_path`. Если они не заданы и `self_signed = true`, генерируется самоподписанный сертификат для `server.hostname`.

## AUTH

- `AUTH PLAIN [base64(\0user\0password)]`
- `AUTH LOGIN` с двумя challenge (`Username:`, `Password:`)
- Пароли хранятся в конфиге и хешируются Argon2id при старте.
- На submission без TLS AUTH разрешён только если TLS не настроен (dev-режим).

## Спам и DSN

- Спам-движок (`[spam]`) добавляет `X-Spam-*` и маршрутизирует в `Junk`/отклоняет.
- DSN генерируется после трёх неудачных попыток outbound; входящие DSN помечаются `X-Tide-DSN`.
- Outbound применяет MTA-STS и DANE, если включены.
- Ошибки TLS и MTA-STS попадают в TLS-RPT, если задан `report_dir` и `tls_rpt = true`.

## DMARC и TLS-отчёты

```toml
[server]
report_dir = "./data/reports"
dmarc_reports = true
tls_rpt = true
```

- Aggregate-отчёты DMARC (`rua`) формируются раз в час из `dmarc.jsonl`.
- Failure-отчёты (`ruf`) отправляются сразу при DMARC-неудаче.
- TLS-RPT-отчёты формируются из `tlsrpt.jsonl` и отправляются как `application/tlsrpt+json`.
- Отчёты уходят через outbound-очередь, поэтому `outbound_enabled` должен быть включён.

## Приём

Локальные получатели определяются по списку `[[accounts]]`. Письмо парсится `mail-parser`, извлекаются заголовки, text/html, вложения, тред; для каждого локального получателя создаётся отдельная запись в его аккаунте (папка `INBOX`).

Для неизвестного домена на порту 25 возвращается `550 Relay access denied`.

## Входящая аутентификация

При `email_auth.enabled = true` сервер проверяет SPF, DKIM и DMARC через `mail-auth` и добавляет заголовок `Authentication-Results` перед сохранением. Проверка выполняется в blocking-пуле, чтобы не блокировать io_uring runtime.

```toml
[email_auth]
enabled = true
reject_spf_fail = false
reject_dmarc_fail = false

[dkim]
domain = "mail.local"
selector = "default"
private_key_path = "./certs/dkim.key"
```

- `reject_spf_fail` — отклонять `Fail`/`SoftFail` SPF.
- `reject_dmarc_fail` — отклонять при `DMARC Fail` и политике `reject`.
- `[dkim]` включает подпись исходящих писем.

## Отправка

Submission принимает внешних получателей, если `outbound_enabled = true`. Задание пишется в персистентную очередь `outbound/<id>.bin` и передаётся worker'у:

- MX-резолв через `hickory-resolver`, сортировка по preference;
- fallback на A/AAAA домена, если MX нет;
- подключение к порту 25;
- opportunistic STARTTLS, если сервер объявил его и `outbound_tls = true`;
- DKIM-подпись, если настроен `[dkim]`;
- три попытки с backoff; неудачное задание остаётся в очереди.

Ограничения: нет MTA-STS/DANE, нет DSN/bounce-обработки.

## Проверка вручную

```bash
python3 - <<'PY'
import smtplib
from email.message import EmailMessage
msg = EmailMessage()
msg["From"] = "bob@example.com"
msg["To"] = "alice@mail.local"
msg["Subject"] = "Tide hello"
msg.set_content("Hello from SMTP")
with smtplib.SMTP("127.0.0.1", 2525) as smtp:
    smtp.send_message(msg)
PY
```

Submission + STARTTLS:

```python
import smtplib, ssl
ctx = ssl._create_unverified_context()
with smtplib.SMTP("127.0.0.1", 5870) as smtp:
    smtp.starttls(context=ctx)
    smtp.login("alice@mail.local", "secret")
    smtp.send_message(msg)
```
