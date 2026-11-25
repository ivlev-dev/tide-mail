# Spam filters

`tide-spam` — pluggable engine. Фильтр реализует `SpamFilter` и возвращает `SpamVerdict { score, rules, reject }`.

## Встроенные фильтры

### RuleFilter

Эвристики:

- SPF/DKIM/DMARC fail;
- спам-слова (`winner`, `casino`, `wire transfer`, …);
- ALL CAPS subject;
- много ссылок;
- только HTML;
- null sender;
- большое сообщение.

### DnsblFilter

Проверяет IPv4-адрес клиента в DNSBL-зонах (например `zen.spamhaus.org`). Private/loopback пропускаются. Каждый listing даёт +5.

### ExternalFilter

Запускает внешний бинарник (SpamAssassin, rspamd-клиент) с сообщением на stdin и разбирает:

- `X-Spam-Flag: Yes` → +5;
- `X-Spam-Score: N` → +N.

Команда задаётся строкой, без shell. Это доверенная конфигурация администратора.

## Конфигурация

```toml
[spam]
enabled = true
threshold = 5.0
reject_threshold = 15.0
dnsbl_zones = ["zen.spamhaus.org"]
external_command = "spamassassin"
```

- `score >= threshold` → папка `Junk`.
- `score >= reject_threshold` → SMTP `550 5.7.1`.
- Заголовки `X-Spam-*` добавляются до сохранения.

## Порядок обработки

1. SPF/DKIM/DMARC (`email_auth`), если включены.
2. Spam engine.
3. `Junk` или `INBOX`.
4. Индексация и store.

Spam-проверка выполняется в blocking-пуле, чтобы DNSBL/external command не блокировали io_uring runtime.
