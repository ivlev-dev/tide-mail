# RFC coverage

Ниже — фактическое покрытие, а не маркетинг. `Full` — реализовано и покрыто тестами, `Partial` — реализовано частично, `No` — отсутствует.

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
| RFC 3030 | `BINARYMIME` | No |
| RFC 3461 | DSN-параметры `RET`, `ENVID`, `NOTIFY`, `ORCPT` | Partial |
| RFC 3464 | Формат DSN | Partial |
| RFC 4954 | AUTH, initial response, cancel | Full |
| RFC 3207 | STARTTLS | Full |
| RFC 6409 | Submission | Full |
| RFC 8689 | `REQUIRETLS` | Partial |
| RFC 2033 | LMTP | No |
| RFC 4468 | `BURL` | No |
| RFC 4865 | `FUTURERELEASE` | No |
| RFC 2852 | `DELIVERBY` | No |
| RFC 5321 §4.1.4 | Source routes | No |
| RFC 5321 §4.1.3 | Address literals | Partial |

Что именно Partial:

- **RFC 5321**: основной протокол есть; нет всех необязательных расширений, source routes, полной валидации address literals.
- **SMTPUTF8**: UTF-8 адреса и параметр работают; нет IDNA/нормализации доменов.
- **DSN**: параметры принимаются и проверяются; outbound-клиент не передаёт их следующему MTA; `RET=FULL` не влияет на вложение тела в DSN.
- **REQUIRETLS**: флаг принимается и учитывается при outbound TLS; нет полного цепочечного поведения RFC 8689.
- **DSN format**: multipart/report и message/delivery-status есть; нет полного набора опциональных полей и корреляции с `ENVID`.

## Аутентификация почты

| RFC | Тема | Статус |
|---|---|---|
| RFC 7208 | SPF | Full (mail-auth) |
| RFC 6376 | DKIM | Full (mail-auth) |
| RFC 7489/9989 | DMARC | Full (mail-auth) |
| RFC 8601 | Authentication-Results | Full |
| RFC 8461 | MTA-STS | Partial |
| RFC 7672 | DANE | Partial |
| RFC 8460 | TLS-RPT | No |
| RFC 8617 | ARC | No |
| DKIM2 | draft | No |

MTA-STS/DANE Partial: enforce и TLSA usage=3 SHA-256 есть; нет DANE-TA usage=2, MTA-STS reporting, TLS-RPT, кеша на диске.

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

- IMAP4rev1/rev2 — нет.
- JMAP — нет.
- ManageSieve — нет.
- CalDAV/CardDAV — нет.
- S/MIME, OpenPGP — нет.

## Приоритеты для следующего RFC-покрытия

1. Outbound DSN-параметры + `RET=FULL` + `ENVID` correlation.
2. `REQUIRETLS` end-to-end.
3. `BINARYMIME`.
4. LMTP.
5. IDNA/address literals/full address validation.
6. TLS-RPT, DANE-TA, MTA-STS testing/reporting.
7. ARC/DKIM2.
8. IMAP/JMAP gateway.
