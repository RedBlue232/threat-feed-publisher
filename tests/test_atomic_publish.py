"""Publication atomique via l'API Git Data.

L'ancienne implémentation écrivait fichier par fichier via l'API Contents :
14 appels PUT, donc 14 commits. Une interruption en cours de route laissait le
dépôt incohérent — c'est arrivé le 9 juillet 2026, le serveur s'étant éteint en
pleine publication. Ici on construit l'arbre complet puis on déplace la
référence de branche en une seule opération.
"""
import base64
import json

import pytest
import requests

import feed


BASE_COMMIT = "commit-de-base"
BASE_TREE = "arbre-de-base"


class FausseReponse:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self.content = b"{}"

    def raise_for_status(self):
        if self.status_code >= 400:
            err = requests.HTTPError(f"HTTP {self.status_code}")
            err.response = self
            raise err

    def json(self):
        return self._payload


class FauxGitHub:
    """Enregistre les appels et rejoue des réponses plausibles de l'API."""

    def __init__(self, tree_sha="nouvel-arbre", patch_status=200, patch_status_puis=None):
        self.appels = []
        self.blobs = []
        self.tree_sha = tree_sha
        self.patch_status = patch_status
        self.patch_status_puis = patch_status_puis
        self.commits_crees = 0
        self.patchs = 0

    def request(self, method, url, headers=None, timeout=None, json=None, **kw):
        self.appels.append((method, url))
        if method == "GET" and "/git/ref/heads/" in url:
            return FausseReponse(200, {"object": {"sha": BASE_COMMIT}})
        if method == "GET" and "/git/commits/" in url:
            return FausseReponse(200, {"tree": {"sha": BASE_TREE}})
        if method == "POST" and url.endswith("/git/blobs"):
            self.blobs.append(json)
            return FausseReponse(200, {"sha": f"blob-{len(self.blobs)}"})
        if method == "POST" and url.endswith("/git/trees"):
            self.arbre_envoye = json
            return FausseReponse(200, {"sha": self.tree_sha})
        if method == "POST" and url.endswith("/git/commits"):
            self.commits_crees += 1
            self.commit_envoye = json
            return FausseReponse(200, {"sha": "commit-neuf-0123456789"})
        if method == "PATCH" and "/git/refs/heads/" in url:
            self.patchs += 1
            self.patch_envoye = json
            statut = self.patch_status
            if self.patchs > 1 and self.patch_status_puis is not None:
                statut = self.patch_status_puis
            return FausseReponse(statut, {})
        raise AssertionError(f"appel inattendu : {method} {url}")


@pytest.fixture
def sorties():
    return {"feeds/feed-all-7d.txt": "8.8.8.8\n",
            "state/status.json": '{"total": 1}\n',
            "feeds/feed-all-7d.json": '{"items": []}\n'}


def test_un_seul_commit_pour_tous_les_fichiers(monkeypatch, sorties):
    gh = FauxGitHub()
    monkeypatch.setattr(feed, "GH_SESSION", gh)
    feed.publish_github(sorties)

    assert len(gh.blobs) == len(sorties)      # un blob par fichier
    assert gh.commits_crees == 1              # un seul commit
    assert gh.patchs == 1                     # une seule bascule de référence
    assert gh.commit_envoye["parents"] == [BASE_COMMIT]
    assert gh.arbre_envoye["base_tree"] == BASE_TREE


def test_les_contenus_sont_transmis_intacts(monkeypatch, sorties):
    """Encodage base64 : le contenu doit revenir identique, accents compris."""
    sorties["feeds/accents.txt"] = "héllo — ünicode\n"
    gh = FauxGitHub()
    monkeypatch.setattr(feed, "GH_SESSION", gh)
    feed.publish_github(sorties)

    envoyes = {base64.b64decode(b["content"]).decode("utf-8") for b in gh.blobs}
    assert envoyes == set(sorties.values())
    assert all(b["encoding"] == "base64" for b in gh.blobs)


def test_arbre_complet_et_modes_de_fichier(monkeypatch, sorties):
    gh = FauxGitHub()
    monkeypatch.setattr(feed, "GH_SESSION", gh)
    feed.publish_github(sorties)

    entrees = gh.arbre_envoye["tree"]
    assert {e["path"] for e in entrees} == set(sorties)
    assert all(e["mode"] == "100644" and e["type"] == "blob" for e in entrees)


def test_aucun_commit_si_le_contenu_est_inchange(monkeypatch, sorties):
    """Si l'arbre résultant est identique à la base, créer un commit vide
    n'apporterait que du bruit."""
    gh = FauxGitHub(tree_sha=BASE_TREE)
    monkeypatch.setattr(feed, "GH_SESSION", gh)
    feed.publish_github(sorties)

    assert gh.commits_crees == 0
    assert gh.patchs == 0


def test_reconstruction_si_la_branche_a_bouge(monkeypatch, sorties):
    """Un run manuel concurrent d'un run cron fait échouer la bascule en
    fast-forward : on reconstruit sur la nouvelle base au lieu de forcer."""
    gh = FauxGitHub(patch_status=422, patch_status_puis=200)
    monkeypatch.setattr(feed, "GH_SESSION", gh)
    feed.publish_github(sorties)

    assert gh.patchs == 2          # première tentative rejetée, seconde acceptée
    assert gh.commits_crees == 2   # le commit est reconstruit sur la base fraîche


def test_echec_persistant_remonte(monkeypatch, sorties):
    gh = FauxGitHub(patch_status=422)
    monkeypatch.setattr(feed, "GH_SESSION", gh)
    with pytest.raises(requests.HTTPError):
        feed.publish_github(sorties)
    assert gh.patchs == feed.GH_PUBLISH_ATTEMPTS


def test_la_bascule_nest_jamais_forcee(monkeypatch, sorties):
    """Forcer écraserait un commit concurrent."""
    gh = FauxGitHub()
    monkeypatch.setattr(feed, "GH_SESSION", gh)
    feed.publish_github(sorties)
    assert gh.patch_envoye.get("force") is False


def test_une_erreur_non_conflictuelle_nest_pas_reessayee(monkeypatch, sorties):
    """Un 404 ou un 401 ne se résoudra pas en réessayant : il faut remonter
    tout de suite plutôt que de marteler l'API."""
    gh = FauxGitHub(patch_status=404)
    monkeypatch.setattr(feed, "GH_SESSION", gh)
    with pytest.raises(requests.HTTPError):
        feed.publish_github(sorties)
    assert gh.patchs == 1


def test_le_retry_http_couvre_les_methodes_de_l_api_git_data():
    retry = feed.GH_SESSION.get_adapter("https://api.github.com").max_retries
    assert {"POST", "PATCH"} <= set(retry.allowed_methods)
