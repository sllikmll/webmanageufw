# webmanageufw MVP Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Собрать веб-сервис, который хранит список удалённых серверов и управляет на них UFW и fail2ban по SSH.

**Architecture:** Flask-приложение с server-side HTML UI, SQLite для хранения серверов, Paramiko для SSH, шифрование credentials через Fernet-derived key из env. Доставка — Docker image в GHCR и deploy на `lin` как Compose-сервис.

**Tech Stack:** Python 3.12, Flask, SQLAlchemy, Paramiko, Cryptography, Gunicorn, Docker, GitHub Actions.

---

## MVP scope

1. CRUD серверов
2. Хранение password / ssh key / sudo password в зашифрованном виде
3. SSH test
4. Просмотр UFW status numbered
5. Enable / disable / reload UFW
6. Добавление и удаление UFW rules
7. Просмотр fail2ban status + jail details
8. Ban / unban IP
9. Dockerfile + Compose
10. GitHub Actions publish в GHCR
11. Деплой на `lin`

## Verification

- `pytest tests/ -q`
- открыть web UI локально/на `lin`
- проверить health endpoint
- проверить, что контейнер на `lin` поднят и отвечает по HTTP
