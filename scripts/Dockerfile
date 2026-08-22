# Image de base volontairement suivie par tag (pas par digest) : chaque rebuild
# récupère ainsi les correctifs de sécurité Alpine/Python. Un digest figé sans
# mécanisme de bump automatique accumulerait les CVE — le gain de
# reproductibilité ne vaut pas ce coût ici.
FROM python:3.12-alpine

# PYTHONDONTWRITEBYTECODE : /app appartient à root et le process tourne en
#   non-root (voir USER plus bas) — inutile de tenter d'écrire des .pyc.
# PYTHONUNBUFFERED : logs poussés immédiatement vers `docker logs`, sans quoi
#   le diagnostic d'un run se fait à l'aveugle.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Dépendances Python épinglées : `requests`/`pymisp` sont du code exécuté au
# runtime, c'est la surface d'approvisionnement qui compte. Les versions
# correspondent à celles déjà en production (build du 2026-08-22) : on fige un
# état connu bon plutôt que de subir la dernière version publiée à chaque build.
# Les outils de compilation ne servent qu'à construire d'éventuelles roues C et
# sont retirés ensuite — ils n'ont rien à faire dans l'image finale.
# `libffi` (runtime) est installé explicitement : il n'arrive sinon dans l'image
# que comme dépendance de `libffi-dev`, et `apk del .build-deps` l'emporterait
# avec lui — cassant l'import de pymisp au démarrage, longtemps après le build.
# Le smoke-test d'import ci-dessous fait échouer le build si c'était le cas.
RUN apk add --no-cache curl ca-certificates git libffi && \
    apk add --no-cache --virtual .build-deps gcc musl-dev libffi-dev && \
    pip install --no-cache-dir requests==2.34.2 pymisp==2.5.34.2 && \
    apk del .build-deps && \
    python -c "import requests, pymisp; print('smoke-test imports OK')"

# Supercronic : cron pensé pour les containers (logs stdout, gestion signaux).
# Le binaire est désormais vérifié par SHA256 avant d'être rendu exécutable —
# sans cette vérification, un artefact altéré en transit serait exécuté en
# confiance. Le digest provient de l'API GitHub pour cette release précise.
# NB : cela garantit l'intégrité du téléchargement, pas l'innocuité de l'upstream.
ENV SUPERCRONIC_VERSION=v0.2.49 \
    SUPERCRONIC_SHA256=a53ae236602c7338aba3fbaff40bda6300eae3b9fedb8261eb06cfe3724430c1 \
    SUPERCRONIC=/usr/local/bin/supercronic

RUN curl -fsSL "https://github.com/aptible/supercronic/releases/download/${SUPERCRONIC_VERSION}/supercronic-linux-amd64" -o "$SUPERCRONIC" && \
    echo "${SUPERCRONIC_SHA256}  ${SUPERCRONIC}" | sha256sum -c - && \
    chmod 0755 "$SUPERCRONIC"

# misp-warninglists : ce sont des DONNÉES (JSON lues par enrich_warninglists),
# pas du code exécuté — et leur fraîcheur est justement l'intérêt de la feature.
# On garde donc un clone de la branche courante plutôt qu'un commit figé, qui
# rendrait les listes obsolètes à chaque rebuild.
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
COPY crontab /app/crontab

# Exécution en non-root : le conteneur n'a besoin d'aucun privilège (il lit
# /app en seule lecture, écrit uniquement dans /tmp en DRY_RUN et parle à des
# API HTTP). Les fichiers restent la propriété de root, donc non modifiables
# par le process — le code exécuté ne peut pas se réécrire lui-même.
RUN adduser -D -u 10001 app
USER app

CMD ["/usr/local/bin/supercronic", "/app/crontab"]
