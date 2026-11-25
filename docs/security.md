# Аудит безопасности

Дата: 2026-11-25. Аудит проведён по коду и конфигурации репозитория.

## Модель угроз

- Удалённый SMTP-клиент, отправляющий почту/команды.
- Удалённый HTTP-клиент с/без Bearer-токена.
- Внешний SMTP-сервер, принимающий исходящую почту.
- Локальный пользователь без прав на файл БД.
- Вредоносное письмо: MIME-бомба, header injection, path traversal, спам.

## Что сделано

### Аутентификация и доступ

- Пароли: Argon2id с солью.
- API: случайный UUID-токен (122 бита), TTL, отзыв при logout.
- Admin API: отдельный `X-Admin-Token`, сравнение constant-time.
- `account_id` в каждом запросе сверяется с аккаунтом токена.
- SMTP submission: AUTH PLAIN/LOGIN, при настроенном TLS — только после STARTTLS.
- SMTP relay: inbound запрещает внешних получателей; submission — только при `outbound_enabled`.

### Транспорт

- SMTP STARTTLS и implicit TLS 465.
- HTTPS API при `http_tls = true`.
- Sync TLS с ALPN.
- Rustls, WebPKI-проверка сертификатов; self-signed только для dev.
- MTA-STS enforce + DANE TLSA (usage 3, SHA-256).

### Данные

- Один файл БД защищён `flock`; конкурентные процессы не откроют.
- CRC32C на заголовках, записях, батчах и снапшотах.
- `RWF_DSYNC` до подтверждения записи.
- Восстановление отбрасывает torn tail, не теряя подтверждённые батчи.
- `memmap` + bounds checks; `unsafe` изолирован в `tide-store`.
- Snapshot/compaction не меняют offset до atomic rename.

### Ввод

- SMTP: лимиты размера сообщения/строки/получателей, dot-stuffing, отклонение неизвестных команд.
- HTTP: лимит заголовков 64 КиБ, тела 64 МиБ.
- Вложения: лимит 64 МиБ, sanitization `Content-Type`/`filename`, запрет CRLF в заголовках.
- MIME парсится `mail-parser`, который не паникует на повреждённом вводе.
- Вложения: blob-store с SHA-256 ID, проверка 64-hex, atomic rename; ClamAV INSTREAM/external scan до сохранения.
- Спам: правила, DNSBL, external command без shell.
- SPF/DKIM/DMARC проверяются до сохранения; политики reject настраиваются.

## Найденные остаточные риски

| Риск | Уровень | Статус |
|---|---|---|
| Нет rate limit на SMTP/HTTP/API | высокий | не реализовано |
| Нет блокировки после серии неудачных AUTH | средний | не реализовано |
| Bearer-токены только в памяти и не ротируются | средний | by design MVP |
| CORS `*` при Bearer-токенах | низкий/средний | ограничить Origin в production |
| `http_tls` по умолчанию false | высокий в production | включить или reverse proxy |
| Нет шифрования БД at rest | средний | LUKS/ФС-шифрование |
| DANE fail-open при DNS-ошибке | средний | задокументировано |
| External spam command — доверенный ввод | средний | только admin-конфиг |
| Нет карантина заражённых писем | низкий | ClamAV/external scan до сохранения |
| DSN не имеет rate limit | низкий | мониторить |
| Admin token хранится в конфиге открытым текстом | средний | secrets manager/права 0600 |
| Нет audit log действий администратора | средний | roadmap |

## Рекомендации перед production

1. Включить `http_tls` и реальный сертификат.
2. Поставить reverse proxy с rate limit/WAF.
3. Ограничить CORS конкретным Origin.
4. Включить `email_auth`, `mta_sts`, `dane`, `spam`.
5. Закрыть 25/587/465/8080/9093 firewall-политикой; sync только для доверенных сетей.
6. Права `0600` на `mail.tide`, DKIM-ключ, `tide.toml`.
7. Настроить backup и мониторинг ошибок `outbound`.
8. Добавить rate limit на AUTH/RCPT и virus-scan hook.
