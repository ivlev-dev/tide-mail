# MTA-STS и DANE

Обе политики применяются только к исходящей доставке.

## MTA-STS

1. Запрос `TXT _mta-sts.<domain>`.
2. Если есть `v=STSv1`, загружается `https://mta-sts.<domain>/.well-known/mta-sts.txt` (timeout 8s).
3. Политика кешируется в памяти на `min(max_age, 24h)`.
4. `mode: enforce` требует TLS и MX-хост из списка `mx:` (поддерживается `*.example.com`).
5. `mode: testing` не блокирует, `mode: none` игнорируется.

Если TXT-запрос не удался, политика считается отсутствующей. Если TXT есть, а HTTPS-загрузка не удалась, доставка отклоняется (fail closed).

## DANE

1. Для MX-хоста выполняется TLSA lookup `_25._tcp.<mx_host>`.
2. Поддерживаются `usage=3` (DANE-EE), `selector=0/1`, `matching=1` (SHA-256).
3. Для `selector=1` хешируется SubjectPublicKeyInfo, для `selector=0` — весь сертификат.
4. Если TLSA-записи есть, используется собственный `ServerCertVerifier`: сертификат принимается только при совпадении.
5. Если TLSA-записей нет, применяется обычная WebPKI-проверка.
6. Если TLSA lookup завершился ошибкой, запись считается отсутствующей (fail-open); это задокументировано в security audit как остаточный риск.

## Конфигурация

```toml
[server]
mta_sts = true
dane = false
outbound_tls = true
```

## Ограничения

- DANE не поддерживает `usage=2` (DANE-TA) и `matching=0` (full cert без хеша).
- Нет MTA-STS для входящей почты (политика применяется отправителем).
- Кеш MTA-STS только в памяти; после рестарта политика загружается заново.
