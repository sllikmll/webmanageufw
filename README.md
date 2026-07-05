# webmanageufw

`webmanageufw` — минимальный self-hosted сервис для управления **UFW** и **fail2ban** на удалённых Linux-серверах через SSH.

## Что умеет сейчас

- хранит список серверов в SQLite;
- поддерживает авторизацию по `password` или `SSH key`;
- хранит секреты в зашифрованном виде (через `APP_ENCRYPTION_KEY`);
- проверяет SSH-подключение;
- показывает `ufw status numbered`;
- умеет `enable`, `disable`, `reload` для UFW;
- умеет добавлять и удалять UFW rules;
- показывает `fail2ban-client status` и список jail'ов;
- умеет `banip` / `unbanip` для fail2ban;
- собирается в Docker image и публикуется в GHCR.

## Ограничения MVP

- пока нет полноценного редактирования карточки сервера;
- команды ожидают, что на удалённой машине уже установлены `ufw` и `fail2ban`;
- для не-root пользователя нужен `sudo password`, если управление идёт через `sudo`.

## Локальный запуск

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
export SECRET_KEY='change-me'
export APP_ENCRYPTION_KEY='change-this-key'
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
docker run --rm -p 8098:8080   -e SECRET_KEY='change-me'   -e APP_ENCRYPTION_KEY='change-this-key'   -v $(pwd)/data:/app/data   webmanageufw:local
```

## Docker Compose

```bash
cp docker-compose.yml /root/docker/webmanageufw/docker-compose.yml
mkdir -p /root/docker/webmanageufw/data
cd /root/docker/webmanageufw
# поменяй SECRET_KEY и APP_ENCRYPTION_KEY

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
