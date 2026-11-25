# SMTP

`tide-smtp` — sans-IO библиотека, сервер и клиент используют один и тот же парсер команд, reply-формат и state machine.

## Порты

| Порт | Назначение | AUTH | STARTTLS |
|---|---|---|---|
| 25 / `smtp_addr` | MX, приём почты | нет | да, если TLS настроен |
| 587 / `submission_addr` | submission | да | да |
| 465 / `smtps_addr` | implicit TLS | нет | не нужен |

Порты задаются в `tide.toml`; в примере используются непривилегированные 2525/5870.

## ESMTP

Поддерживаются:

- `EHLO` / `HELO`
- `MAIL FROM`, `RCPT TO`, `DATA`, `RSET`, `NOOP`, `QUIT`
- `SIZE`, `8BITMIME`, `SMTPUTF8`, `PIPELINING`
- `STARTTLS`
- `AUTH PLAIN`, `AUTH LOGIN`
- `VRFY`, `HELP`
- enhanced status codes

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

## Приём

Локальные получатели определяются по списку `[[accounts]]`. Письмо парсится `mail-parser`, извлекаются заголовки, text/html, вложения, тред; для каждого локального получателя создаётся отдельная запись в его аккаунте (папка `INBOX`).

Для неизвестного домена на порту 25 возвращается `550 Relay access denied`.

## Входящая аутентификация

При `email_auth.enabled = true` сервер проверяет SPF, DKIM и DMARC через `mail-auth` и добавляет заголовок `Authentication-Results` перед сохранением. Проверка выполняется в blocking-пуле, чтобы не блокировать io_uring runtime.

- `reject_spf_fail` — отклонять `Fail`/`SoftFail` SPF.
- `reject_dmarc_fail` — отклонять при `DMARC Fail` и политике `reject`.

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
