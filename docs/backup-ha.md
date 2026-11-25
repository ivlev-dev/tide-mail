# Backup и HA

## Backup

Админ-эндпоинт:

```http
POST /v1/admin/backup
X-Admin-Token: <token>
```

Требует `server.backup_dir`.

Backup:

1. Берёт write-barrier: новые записи ждут, читатели работают.
2. Делает snapshot индекса.
3. Копирует `mail.tide`.
4. Копирует blob-store `blobs/`.
5. Пишет `manifest.json` с generation, количеством писем и timestamp.

Результат:

```text
backups/1764.../mail.tide
backups/1764.../blobs/...
backups/1764.../manifest.json
```

## Restore

Сервер должен быть остановлен (файл защищён `flock`).

```bash
systemctl stop tide
cp backups/<ts>/mail.tide /data/mail.tide
cp -a backups/<ts>/blobs /data/blobs
systemctl start tide
```

Либо указать `data_path`/`blob_dir` на backup-каталог и запустить отдельный экземпляр для проверки.

## HA: standby на общем хранилище

`server.standby = true` — процесс пытается открыть БД; если файл занят primary (`flock`), ждёт `standby_retry_secs` и повторяет. Когда primary умирает, standby автоматически acquires lock и начинает обслуживать.

```toml
[server]
standby = true
standby_retry_secs = 2
```

Это даёт автоматический failover для общего volume. Разделяемого консенсуса нет; split-brain предотвращается `flock`.

## HA: backup + orchestrator

Если общего volume нет, используйте актив-пассив через backup:

- один **active** экземпляр владеет `mail.tide` (flock не даст запустить второй writer);
- периодический `POST /v1/admin/backup` на общий backup-volume;
- orchestrator/keepalived/DNS переключает трафик на standby;
- standby восстанавливает последний backup и запускается;
- `/health` используется как readiness/liveness.

Это даёт RPO = интервал backup, RTO = время restore + старт. Для RPO≈0 нужна потоковая репликация lane-логов или внешний shared block storage с fencing; это roadmap.

## Рекомендации

- Backup на другой физический носитель.
- Проверять restore на отдельном инстансе.
- Хранить DKIM-ключ и конфиг отдельно от backup.
- Для production: reverse proxy, health-check, fencing, мониторинг отставания backup.
