# Tide Mail

All-in-one email suite на Rust: SMTP, собственное mmap-хранилище, полнотекстовый поиск, бинарный REST API и sync-протокол вместо IMAP/JMAP.

## Статус

- [x] `tide-core` — доменная модель письма.
- [x] `tide-store` — один mmap-файл, lane-sharded append-only log, `RWF_DSYNC`, восстановление после сбоев, полнотекстовый индекс.
- [ ] `tide-proto` — SilentProto-схемы REST и sync, фрейминг.
- [ ] `tide-smtp` — библиотека SMTP (sans-IO сессия, клиент).
- [ ] `tide-sync` — библиотека синхронизации (sans-IO, курсоры, push/pull).
- [ ] `tide-server` — io_uring-сервер: SMTP, REST, sync.
- [ ] TLS / STARTTLS, Docker, E2E.

## Хранилище

Один файл `mail.tide`, доступ через mmap. Данные разбиты на lane по аккаунтам: каждый lane — независимый append-only журнал со своим io_uring-ring и `RWF_DSYNC` на батч. Разные аккаунты пишутся параллельно, внутри lane порядок сохраняется.

Батч самодостаточен: header + записи + footer с CRC32C. Оборванный хвост отбрасывается при recovery. Подтверждённая запись переживает `kill -9` и потерю питания.

Подробности: `docs/storage.md` (будет добавлено).

## Сборка

```bash
cargo test --workspace
cargo run -p tide-server
```

Требуется Linux с io_uring (ядро 5.6+).
