# RFC coverage

Ниже — фактическое покрытие, а не маркетинг. `Full` — реализовано и покрыто тестами, `Partial` — реализовано частично, `No` — отсутствует. IMAP и JMAP не планируются: Tide Mail использует собственный sync-протокол.

## SMTP

| RFC | Тема | Статус |
|---|---|---|
| RFC 5321 | SMTP | Partial |
| RFC 5321 §4.4 | Trace `Received` | Full |
| RFC 5321 §4.5.4.1 | `Received` loop limit | Full |
| RFC 1870 | `SIZE` | Full |
| RFC 6152 | `8BITMIME` | Full |
| RFC 6531/6532 | `SMTPUTF8` | Partial |
| RFC 2920 | `PIPELINING` | Full |
| RFC 3030 | `CHUNKING`/`BDAT` | Full |
| RFC 3030 | `BINARYMIME` | Partial |
| RFC 3461 | DSN-параметры `RET`, `ENVID`, `NOTIFY`, `ORCPT` | Full |
| RFC 3464 | Формат DSN | Partial |
| RFC 4954 | AUTH, initial response, cancel | Full |
| RFC 3207 | STARTTLS | Full |
| RFC 6409 | Submission | Full |
| RFC 8689 | `REQUIRETLS` | Partial |
| RFC 2033 | LMTP | Full |
| RFC 4468 | `BURL` | No |
| RFC 4865 | `FUTURERELEASE` | Partial |
| RFC 2852 | `DELIVERBY` | Partial |
| RFC 5321 §4.1.4 | Source routes | Partial |
| RFC 5321 §4.1.3 | Address literals | Full |
| RFC 5321 §4.1.2 | IDNA-домены | Full |

Что именно Partial:

- **RFC 5321**: основной протокол есть; нет части необязательных расширений и полного address rewriting.
- **SMTPUTF8**: UTF-8 адреса и IDNA работают; нет перекодирования заголовков и нормализации Unicode local-part.
- **BINARYMIME**: `BODY=BINARYMIME` принимается только через `BDAT`; outbound-клиент пока отправляет через `DATA`.
- **REQUIRETLS**: флаг принимается, сохраняется в очереди и учитывается при outbound TLS; нет полного цепочечного поведения RFC 8689.
- **DSN format**: multipart/report, `message/delivery-status`, `Original-Recipient`, `Original-Envelope-Id` и `RET=FULL` есть; нет всех опциональных полей.
- **FUTURERELEASE**: поддержана форма с задержкой в секундах; абсолютная дата из второго параметра игнорируется.
- **DELIVERBY**: дедлайн соблюдается и по истечении формируется failure DSN; опции `R`/`N` не влияют на поведение.
- **Source routes**: входящий source route отбрасывается при валидации адреса.

`BURL` явно отклоняется с `504 5.5.4`, а не игнорируется.

## Аутентификация почты

| RFC | Тема | Статус |
|---|---|---|
| RFC 7208 | SPF | Full (mail-auth) |
| RFC 6376 | DKIM | Full (mail-auth) |
| RFC 7489/9989 | DMARC | Full (mail-auth) |
| RFC 8601 | Authentication-Results | Full |
| RFC 8461 | MTA-STS | Partial |
| RFC 7672 | DANE | Partial |
| RFC 8460 | TLS-RPT | Partial |
| RFC 8617 | ARC | Partial |
| DKIM2 | draft | Partial |

Что именно Partial:

- **MTA-STS**: enforce, загрузка политики и reporting через TLS-RPT; нет полного набора отчётов о неудачной загрузке политики и дискового кеша с `max_age`.
- **DANE**: TLSA usage 2 и 3, selector 0/1, matching 1 (SHA-256); нет SHA-512 и остальных комбинаций.
- **TLS-RPT**: формируются и отправляются отчёты о TLS-сбоях, включая MTA-STS; нет учёта успешных сессий.
- **ARC**: проверка `ARC-Seal`/`ARC-Message-Signature`/`ARC-Authentication-Results`; подпись исходящих ARC-цепочек не реализована.
- **DKIM2**: проверка подписи и участие в DMARC; подпись исходящих сообщений DKIM2 не реализована.

## DMARC reporting

| RFC | Тема | Статус |
|---|---|---|
| RFC 7489/9990 | Aggregate reports (`rua`) | Full |
| RFC 6591/9991 | Failure reports (`ruf`) | Full |
| RFC 8460 | TLS-RPT reports | Partial |

- Aggregate-отчёты накапливаются в `dmarc.jsonl`, раз в час группируются по домену и `rua`, формируются XML и отправляются через outbound-очередь.
- Failure-отчёты формируются сразу при DMARC-неудаче, если в записи есть `ruf`.
- TLS-отчёты накапливаются в `tlsrpt.jsonl` и отправляются как `application/tlsrpt+json`.
- Отчёты сохраняются в `report_dir` (по умолчанию `reports` рядом с файлом БД).
- Нет проверки внешних `rua`/`ruf` через DMARC external destination verification.

## MIME и сообщения

| RFC | Тема | Статус |
|---|---|---|
| RFC 5322 | Формат сообщения | Full (mail-parser) |
| RFC 2045/2046 | MIME | Full (mail-parser) |
| RFC 2047 | Encoded words | Full (mail-parser) |
| RFC 2231 | MIME parameters | Full (mail-parser) |
| RFC 3464 | DSN body | Partial |
| RFC 3834 | Auto-Submitted | Partial |

## Не SMTP

- IMAP4rev1/rev2 — не поддерживается осознанно.
- JMAP — не поддерживается осознанно.
- ManageSieve — нет.
- CalDAV/CardDAV — нет.
- S/MIME, OpenPGP — нет.
- Собственный sync-протокол — есть.

## Приоритеты для следующего RFC-покрытия

1. Подпись ARC и DKIM2 для исходящих сообщений.
2. Outbound `BINARYMIME` через `BDAT`.
3. Полные DSN-поля и `pct`/external destination verification для DMARC.
4. `BURL`.
5. Абсолютные даты в `FUTURERELEASE`, опции `R`/`N` в `DELIVERBY`.
6. DANE SHA-512 и дополнительные TLSA-комбинации.
7. Успешные сессии в TLS-RPT и кеш MTA-STS на диске.
