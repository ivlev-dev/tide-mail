# DSN и bounce

## Генерация DSN

После трёх неудачных попыток outbound создаёт DSN от `MAILER-DAEMON@<hostname>` на envelope-from исходного письма.

DSN:

- `multipart/report; report-type=delivery-status`;
- `message/delivery-status` с `Final-Recipient`, `Action: failed`, `Status: 5.0.0`, `Diagnostic-Code`, `Original-Message-ID`;
- `text/rfc822-headers` с заголовками оригинала;
- `Auto-Submitted: auto-replied`.

DSN пишется в ту же персистентную очередь `outbound/`; исходное задание удаляется после генерации, чтобы избежать дублей при рестарте.

## Входящий DSN

SMTP определяет `multipart/report` + `report-type=delivery-status` и добавляет:

```text
X-Tide-DSN: yes
```

Письмо проходит обычную маршрутизацию/индексацию. `Original-Message-ID` доступен поиску по телу/заголовкам.

## Конфигурация

```toml
[server]
dsn_enabled = true
```

## Ограничения

- Нет отдельной таблицы «bounce привязан к исходному Message.id»; связь доступна через `Original-Message-ID`.
- Нет DSN для null-sender (`MAIL FROM:<>`), чтобы не создавать петли.
- Нет rate-limit на DSN; при массовых отказах нужен внешний контроль.
