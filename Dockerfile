FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1     PYTHONUNBUFFERED=1     PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends     openssh-client     && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY app ./app
COPY run.py ./

RUN pip install .
RUN mkdir -p /app/data

ENV DATABASE_URL=sqlite:////app/data/app.db     SECRET_KEY=change-me     APP_ENCRYPTION_KEY=change-this-key

EXPOSE 8080

CMD ["gunicorn", "-b", "0.0.0.0:8080", "run:app"]
