# Folders

Папки account-scoped и хранятся в том же `mail.tide` как `META`-записи `folder:<name>`.

Стандартные папки создаются при первом обращении:

| Папка | role |
|---|---|
| INBOX | inbox |
| Sent | sent |
| Drafts | drafts |
| Trash | trash |
| Archive | archive |
| Junk | junk |

## API

```text
POST /v1/folders/list     FolderListRequest { account_id }
POST /v1/folders/create   FolderCreateRequest { account_id, name }
POST /v1/folders/rename   FolderRenameRequest { account_id, old_name, new_name }
POST /v1/folders/delete   FolderDeleteRequest { account_id, name }
```

`POST /v1/mailboxes` — совместимый alias списка папок с количеством писем и unread.

## Правила

- Имя папки: 1..128 байт, без `/`, `\`, `:` и control-символов.
- Переименование переносит все письма и переписывает `MOVE`-записи.
- Удаление переносит письма в `Trash` и удаляет запись папки.
- Стандартные папки нельзя переименовать или удалить.
- Переименование/удаление идёт батчами по 500 писем, чтобы не превышать лимит батча.

## Spam

Письма, признанные спамом, маршрутизируются в `Junk` и получают заголовки:

```text
X-Spam-Score: 5.2
X-Spam-Status: Yes
X-Spam-Rules: rules:keyword:winner, dnsbl:dnsbl:zen.spamhaus.org
```
