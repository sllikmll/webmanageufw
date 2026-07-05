# webmanageufw

`webmanageufw` — минимальный self-hosted сервис для управления **UFW** и **fail2ban** на удалённых Linux-серверах через SSH.

## Что умеет сейчас

- хранит список серверов в SQLite;
- поддерживает авторизацию по `password` или `SSH key`;
- хранит секреты в зашифрованном виде (через `APP_ENCRYPTION_KEY`);
- защищает UI через логин/пароль (`ADMIN_USERNAME` / `ADMIN_PASSWORD`);
- проверяет SSH-подключение;
- показывает `ufw status numbered`;
- умеет `enable`, `disable`, `reload` для UFW;
- умеет добавлять и удалять UFW rules;
- показывает `fail2ban-client status` и список jail'ов;
- умеет `banip` / `unbanip` для fail2ban;
- умеет подсказать, что `ufw` / `fail2ban` не установлены, и установить их кнопкой из UI;
- собирается в Docker image и публикуется в GHCR.

## Ограничения MVP

- для не-root пользователя нужен `sudo password`, если управление идёт через `sudo`.
- установка пакетов сейчас рассчитана прежде всего на Debian/Ubuntu (`apt-get`).

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

UI будет доступен на `http://HOST:8098`.

## GitHub Container Registry

После push в `main` workflow публикует image сюда:

```text
ghcr.io/sllikmll/webmanageufw:latest
```

## Безопасность

- обязательно меняй `SECRET_KEY` и `APP_ENCRYPTION_KEY` в production;
- не теряй `APP_ENCRYPTION_KEY`, иначе сохранённые credentials не расшифруются;
- лучше использовать отдельного automation-user с ограниченными правами, а не бездумный root-везде. Да, капитан очевидность, но всё же 😌
