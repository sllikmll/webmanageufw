# webmanageufw

`webmanageufw` — self-hosted веб-панель для удалённого управления **UFW** и **fail2ban** на Linux-серверах через SSH.

Проект заточен под простой, быстрый operational workflow:
- хранишь серверы в одной панели;
- заходишь в карточку нужного хоста;
- проверяешь SSH;
- смотришь состояние UFW / fail2ban;
- делаешь точечные действия без ручного SSH и вспоминания команд.

## Зачем это вообще

Когда серверов становится больше двух, начинается классика:
- где-то вход по key, где-то по password;
- на одном хосте `ufw` уже есть, на другом его ещё нет;
- fail2ban jail'ы надо быстро посмотреть прямо сейчас, а не через 5 `ssh`-вкладок;
- список IP, правил и банов живёт в голове, а голова, как известно, не SQLite.

`webmanageufw` закрывает именно этот скучный, но важный кусок рутины.

## Что умеет сейчас

### Серверы и доступ
- хранит список серверов в SQLite;
- поддерживает авторизацию по `password` или `SSH key`;
- хранит секреты в зашифрованном виде через `APP_ENCRYPTION_KEY`;
- поддерживает отдельный `sudo password`, если работа идёт не под root;
- позволяет редактировать карточку сервера;
- умеет проверять SSH-подключение.

### UFW
- показывает `ufw status numbered`;
- умеет `enable`, `disable`, `reload`;
- умеет добавлять и удалять UFW rules;
- если `ufw` не установлен — может поставить его кнопкой из UI.

### fail2ban
- показывает `fail2ban-client status` и список jail'ов;
- показывает забаненные IP по jail;
- умеет `banip` / `unbanip`;
- если `fail2ban` не установлен — может поставить его из UI.

### UI / UX
- защищён логином/паролем (`ADMIN_USERNAME` / `ADMIN_PASSWORD`);
- имеет dashboard summary на главной;
- поддерживает поиск и фильтрацию серверов;
- показывает quick facts по credential type и sudo readiness;
- даёт более user-friendly onboarding и empty states;
- использует SQL-level search/filter и индексы по часто используемым полям, чтобы список серверов открывался быстрее.

### Delivery
- собирается в Docker image;
- публикуется в GHCR через GitHub Actions;
- готов для развёртывания на отдельном хосте или VPS.

## UX принципы, по которым проект доработан

При доработке интерфейса использовались общепринятые best practices для internal/admin tools:

- **dashboard-first IA** — сначала обзор и быстрые сигналы, потом детали;
- **progressive disclosure** — на главной не валим всю операционку разом, а ведём в карточку сервера;
- **clear hierarchy** — summary → filters → cards → actions;
- **high-signal cards** — имя, host, auth type, sudo readiness, timestamps;
- **empty / warning states** — UI объясняет, что делать дальше, а не просто молчит;
- **опасные действия визуально выделены** — delete и destructive flows не маскируются под обычные кнопки;
- **operator-friendly copy** — интерфейс пишет по делу и человеческим языком.

## Ограничения текущей версии

- для не-root пользователя нужен `sudo password`, если команды идут через `sudo`;
- автоматическая установка пакетов сейчас рассчитана прежде всего на Debian/Ubuntu (`apt-get`);
- массовые действия по нескольким серверам пока не реализованы;
- нет audit log / history действий;
- пока нет полноценной role model с несколькими пользователями.

## Локальный запуск

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
export SECRET_KEY='change-me'
export APP_ENCRYPTION_KEY='change-this-key'
export ADMIN_USERNAME='admin'
export ADMIN_PASSWORD='adminpass'
python -m flask --app run:app run --debug
```

Открыть: `http://127.0.0.1:5000`

## Тесты

```bash
pytest tests/ -q
```

## Docker

```bash
docker build -t webmanageufw:local .
docker run --rm -p 8098:8080 \
  -e SECRET_KEY='change-me' \
  -e APP_ENCRYPTION_KEY='change-this-key' \
  -e ADMIN_USERNAME='admin' \
  -e ADMIN_PASSWORD='adminpass' \
  -v $(pwd)/data:/app/data \
  webmanageufw:local
```

## Docker Compose

```bash
cp docker-compose.yml /root/docker/webmanageufw/docker-compose.yml
mkdir -p /root/docker/webmanageufw/data
cd /root/docker/webmanageufw
# поменяй SECRET_KEY, APP_ENCRYPTION_KEY, ADMIN_USERNAME и ADMIN_PASSWORD

docker compose up -d
```

После этого UI будет доступен на `http://HOST:8098`.

## GitHub Container Registry

После push в `main` workflow публикует image сюда:

```text
ghcr.io/sllikmll/webmanageufw:latest
```

## Suggested roadmap

Нормальные следующие шаги для v2:

1. bulk actions по нескольким серверам;
2. SSH test + package readiness прямо на dashboard;
3. audit log действий;
4. health badges / last check timestamp;
5. multi-user auth и роли;
6. импорт серверов из `~/.ssh/config`.

## Безопасность

- обязательно меняй `SECRET_KEY` и `APP_ENCRYPTION_KEY` в production;
- не теряй `APP_ENCRYPTION_KEY`, иначе сохранённые credentials не расшифруются;
- лучше использовать отдельного automation-user с ограниченными правами, а не бездумный root-везде;
- если это торчит наружу — ставь reverse proxy, HTTPS и нормальный доступ, а не “ай потом закроем”. Потом обычно не закрывают 😏
