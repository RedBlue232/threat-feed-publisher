#!/usr/bin/env python3
"""Client GitHub partagé : lecture de fichiers et publication atomique.

`feed.py` et `misp_export.py` publient tous deux plusieurs fichiers qui n'ont
de sens qu'ensemble — un feed et son `status.json`, un event MISP et son
`manifest.json`. Les écrire un par un via l'API Contents produit un commit par
fichier et ouvre une fenêtre pendant laquelle le dépôt est incohérent.

L'API Git Data permet de créer les blobs, d'assembler l'arbre puis de déplacer
la référence de branche en une opération : soit tout est publié, soit rien.

Les fonctions prennent leur configuration en paramètre (pas de variable de
module) : les deux scripts ont des réglages distincts, et cela les rend
testables sans manipuler d'environnement.
"""

from __future__ import annotations

import base64
import logging

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger(__name__)

GH_API = "https://api.github.com"

# Nombre de tentatives de publication. Un échec de bascule de référence signifie
# que la branche a bougé entre la lecture de la base et l'écriture : on
# reconstruit le commit sur la nouvelle base plutôt que de forcer, ce qui
# écraserait le travail de l'autre processus. Observé en conditions réelles :
# feed.py et misp_export.py lancés simultanément se marchent dessus.
PUBLISH_ATTEMPTS = 3


def build_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def make_session() -> requests.Session:
    """Session HTTP avec réessais sur erreurs transitoires.

    Une publication enchaîne une vingtaine d'appels : sans réessai, un seul
    5xx/429 avorte l'ensemble.

    POST et PATCH sont réessayables sans risque de doublon ici :
      - POST /git/blobs et /git/trees sont adressés par contenu (même contenu =
        même sha), un réessai est un no-op ;
      - POST /git/commits peut créer un objet en double, mais il reste non
        référencé et sera ramassé par le GC de GitHub ;
      - PATCH /git/refs est protégé par le fast-forward (force absent).
    """
    session = requests.Session()
    retry = Retry(
        total=4,
        backoff_factor=1,  # attentes 1s, 2s, 4s, 8s
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "PUT", "POST", "PATCH"]),
        respect_retry_after_header=True,
    )
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session


def api(session, headers, owner, repo, method, endpoint, **kwargs) -> dict:
    """Appel JSON à l'API du dépôt. Lève sur statut d'erreur."""
    url = f"{GH_API}/repos/{owner}/{repo}{endpoint}"
    resp = session.request(method, url, headers=headers, timeout=60, **kwargs)
    resp.raise_for_status()
    return resp.json() if resp.content else {}


def get_file(session, headers, owner, repo, branch, path) -> dict | None:
    """Lit un fichier du dépôt. Retourne {"content", "sha"} ou None si absent.

    Gère les fichiers de plus de 1 Mo : l'API Contents refuse alors le contenu
    inline (403 too_large, ou content vide avec encoding "none" selon le media
    type). Sans ce repli, un `state/db.json` devenu trop gros rendrait chaque
    run fatal — `json.loads("")` — et le pipeline resterait mort jusqu'à
    intervention manuelle.
    """
    url = f"{GH_API}/repos/{owner}/{repo}/contents/{path}"
    params = {"ref": branch}
    resp = session.get(url, headers=headers, params=params, timeout=30)
    if resp.status_code == 404:
        return None
    if resp.status_code != 403:
        resp.raise_for_status()
        data = resp.json()
        if data.get("encoding") == "base64":
            return {"content": base64.b64decode(data["content"]).decode("utf-8"),
                    "sha": data["sha"]}

    log.warning("get_file: %s non disponible inline (probable > 1 Mo) — repli raw", path)
    raw = session.get(url, headers={**headers, "Accept": "application/vnd.github.raw+json"},
                      params=params, timeout=60)
    raw.raise_for_status()
    meta = session.get(url, headers={**headers, "Accept": "application/vnd.github.object+json"},
                       params=params, timeout=30)
    meta.raise_for_status()
    return {"content": raw.text, "sha": meta.json()["sha"]}


def _commit_once(session, headers, owner, repo, branch, outputs, message) -> str | None:
    """Une tentative : construit l'arbre complet et bascule la référence.

    Retourne le sha du commit, ou None si l'arbre résultant est identique à la
    base — inutile de créer un commit vide.
    """
    call = lambda m, e, **kw: api(session, headers, owner, repo, m, e, **kw)

    base_commit_sha = call("GET", f"/git/ref/heads/{branch}")["object"]["sha"]
    base_tree_sha = call("GET", f"/git/commits/{base_commit_sha}")["tree"]["sha"]

    tree_entries = []
    for path, content in sorted(outputs.items()):
        # base64 : accepte n'importe quel contenu, et la limite est de 100 Mo
        # par blob contre 1 Mo pour l'API Contents.
        blob = call("POST", "/git/blobs", json={
            "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
            "encoding": "base64",
        })
        tree_entries.append({"path": path, "mode": "100644", "type": "blob",
                             "sha": blob["sha"]})

    tree = call("POST", "/git/trees",
                json={"base_tree": base_tree_sha, "tree": tree_entries})
    if tree["sha"] == base_tree_sha:
        return None

    commit = call("POST", "/git/commits", json={
        "message": message, "tree": tree["sha"], "parents": [base_commit_sha],
    })
    # force absent/false : la bascule n'aboutit qu'en fast-forward, donc jamais
    # au détriment d'un commit concurrent.
    call("PATCH", f"/git/refs/heads/{branch}",
         json={"sha": commit["sha"], "force": False})
    return commit["sha"]


def publish_atomic(session, headers, owner, repo, branch, outputs, message,
                   attempts: int = PUBLISH_ATTEMPTS) -> str | None:
    """Publie tous les fichiers en UN commit. Retourne son sha, ou None si le
    contenu est inchangé."""
    if not outputs:
        return None
    for attempt in range(1, attempts + 1):
        try:
            return _commit_once(session, headers, owner, repo, branch, outputs, message)
        except requests.HTTPError as e:
            status = e.response.status_code if e.response is not None else None
            if status in (409, 422) and attempt < attempts:
                log.warning(
                    "Publication : la branche a bougé (HTTP %s), reconstruction "
                    "du commit — tentative %d/%d", status, attempt + 1, attempts,
                )
                continue
            raise
    raise RuntimeError("publication : nombre de tentatives épuisé")
