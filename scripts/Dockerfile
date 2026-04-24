FROM python:3.12-alpine

# Installer les dépendances système + supercronic (cron fiable pour Docker)
# `git` requis pour cloner misp-warninglists (enrichment, voir ci-dessous).
RUN apk add --no-cache curl ca-certificates gcc musl-dev libffi-dev git && \
    pip install --no-cache-dir requests pymisp

# Supercronic : cron pensé pour les containers (logs stdout, gestion signaux)
ENV SUPERCRONIC_URL=https://github.com/aptible/supercronic/releases/download/v0.2.29/supercronic-linux-amd64 \
    SUPERCRONIC=/usr/local/bin/supercronic

RUN curl -fsSL "$SUPERCRONIC_URL" -o "$SUPERCRONIC" && \
    chmod +x "$SUPERCRONIC"

# misp-warninglists : embarqué au build pour reproductibilité.
# Le refresh se fait en rebuild de l'image (cadence : hebdo via CI/cron host).
# Shallow clone pour limiter la taille (~50 Mo vs ~150 Mo sinon).
RUN git clone --depth 1 https://github.com/MISP/misp-warninglists.git /app/warninglists && \
    rm -rf /app/warninglists/.git

WORKDIR /app
COPY feed.py .
COPY misp_export.py .
COPY suricata.py .
COPY enrich_warninglists.py .
COPY enrich_asn.py .
COPY enrich_tor.py .
COPY sanitize.py .

# Fichier crontab (sera monté ou copié)
COPY crontab /app/crontab

CMD ["/usr/local/bin/supercronic", "/app/crontab"]
