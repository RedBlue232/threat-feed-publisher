FROM python:3.12-alpine

# Installer les dépendances système + supercronic (cron fiable pour Docker)
RUN apk add --no-cache curl ca-certificates gcc musl-dev libffi-dev && \
    pip install --no-cache-dir requests pymisp

# Supercronic : cron pensé pour les containers (logs stdout, gestion signaux)
ENV SUPERCRONIC_URL=https://github.com/aptible/supercronic/releases/download/v0.2.29/supercronic-linux-amd64 \
    SUPERCRONIC=/usr/local/bin/supercronic

RUN curl -fsSL "$SUPERCRONIC_URL" -o "$SUPERCRONIC" && \
    chmod +x "$SUPERCRONIC"

WORKDIR /app
COPY feed.py .
COPY misp_export.py .

# Fichier crontab (sera monté ou copié)
COPY crontab /app/crontab

CMD ["/usr/local/bin/supercronic", "/app/crontab"]
