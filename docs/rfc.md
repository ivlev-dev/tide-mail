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
| RFC 3030 | `BINARYMIME` | Full |
| RFC 3461 | DSN-параметры `RET`, `ENVID`, `NOTIFY`, `ORCPT` | Full |
| RFC 3464 | Формат DSN | Partial |
| RFC 4954 | AUTH, initial response, cancel | Full |
| RFC 3207 | STARTTLS | Full |
| RFC 6409 | Submission | Full |
| RFC 8689 | `REQUIRETLS` | Partial |
| RFC 2033 | LMTP | Full |
| RFC 4468 | `BURL` | Partial |
| RFC 4865 | `FUTURERELEASE` | Full |
| RFC 2852 | `DELIVERBY` | Full |
| RFC 5321 §4.1.4 | Source routes | Partial |
| RFC 5321 §4.1.3 | Address literals | Full |
| RFC 5321 §4.1.2 | IDNA-домены | Full |

Что именно Partial:

- **RFC 5321**: основной протокол есть; нет части необязательных расширений и полного address rewriting.
- **SMTPUTF8**: UTF-8 адреса и IDNA работают; нет перекодирования заголовков и нормализации Unicode local-part.
- **BINARYMIME**: входящий `BODY=BINARYMIME` принимается только через `BDAT`, outbound использует `BDAT`, если сервер объявил `CHUNKING`, и `BODY=BINARYMIME` для бинарных тел.
- **REQUIRETLS**: флаг принимается, сохраняется в очереди и учитывается при outbound TLS; нет полного цепочечного поведения RFC 8689.
- **DSN format**: multipart/report, `message/delivery-status`, `Original-Recipient`, `Original-Envelope-Id`, `RET=FULL`, `Arrival-Date`, `Deliver-By-Date` и `Future-Release-Request` есть.
- **FUTURERELEASE**: `HOLDFOR=<секунды>` и `HOLDUNTIL=<RFC 3339 UTC>`, EHLO объявляет максимум, проверяется конфликт с `DELIVERBY`.
- **DELIVERBY**: `BY=<секунды>;<R|N>`, `R` прекращает попытки и шлёт failure DSN `5.4.7`, `N` шлёт delayed DSN `4.4.7` и продолжает попытки; параметр передаётся дальше с оставшимся временем.
- **Source routes**: входящий source route отбрасывается при валидации адреса.
- **BURL**: команда `BURL <url> [LAST]` только для submission. Поддерживаются `https://` и базовые `imap://` URL с доверенным хостом из `[burl]`; `URLAUTH` и `imap://` без UID отклоняются. Это не полный RFC 4468: нет `URLFETCH`/`URLAUTH`.

BURL `https://` защищён от SSRF: только HTTPS, запрет приватных адресов и редиректов. BURL `imap://` работает через внутренний IMAP-клиент с STARTTLS/implicit TLS и allowlist хостов.

## Аутентификация почты

| RFC | Тема | Статус |
|---|---|---|
| RFC 7208 | SPF | Full (mail-auth) |
| RFC 6376 | DKIM | Full (mail-auth) |
| RFC 7489/9989 | DMARC | Full (mail-auth) |
| RFC 8601 | Authentication-Results | Full |
| RFC 8461 | MTA-STS | Partial |
| RFC 7672 | DANE | Full |
| RFC 8460 | TLS-RPT | Full |
| RFC 8617 | ARC | Partial |
| DKIM2 | draft | Partial |

Что именно Partial:

- **MTA-STS**: enforce, загрузка политики, reporting через TLS-RPT и дисковый кеш политик с учётом `max_age`.
- **DANE**: TLSA usage 2 и 3, selector 0/1, matching 0/1/2 (SHA-512 включён); для DANE-TA дополнительно валидируется цепь через WebPKI с найденным trust anchor.
- **TLS-RPT**: учитываются и успешные TLS-сессии, и сбои, включая MTA-STS.
- **ARC**: проверка входящих цепей и запечатывание следующего сета (`i=n+1`) при валидной цепи.
- **DKIM2**: проверка входящих подписей, участие в DMARC, продолжение цепочки для своего домена и подпись новых сообщений.

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
- Внешние `rua`/`ruf` проверяются через `<policy-domain>._report._dmarc.<destination>`, включая override-адреса.
- `pct` применяется к политике; исключённые сообщения помечаются `<reason><type>sampled_out</type></reason>`, `reject` вне выборки трактуется как `quarantine`.

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

1. `URLAUTH`/`URLFETCH` для полного RFC 4468.
2. Полные опциональные поля DSN и DMARC.
3. Отчёт MTA-STS о неудачной загрузке политики.
4. Wildcard-подтверждения external destination для DMARC.
