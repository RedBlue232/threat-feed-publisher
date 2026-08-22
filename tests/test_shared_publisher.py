"""Module de publication partagé par feed.py et misp_export.py.

Il existe parce que les deux scripts publient des fichiers indissociables — un
feed et son status.json, un event MISP et son manifeste — et dupliquaient
jusqu'ici la même logique d'écriture GitHub.
"""
import base64

import pytest
import requests

import github_publish as gp


BASE_COMMIT = "commit-de-base"
BASE_TREE = "arbre-de-base"
HEADERS = {"Authorization": "Bearer test"}


class FausseReponse:
    def __init__(self, status=200, payload=None, text=""):
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self.text = text
        self.content = b"{}"

    def raise_for_status(self):
        if self.status_code >= 400:
            err = requests.HTTPError(f"HTTP {self.status_code}")
            err.response = self
            raise err

    def json(self):
        return self._payload


class FauxGitHub:
    def __init__(self, tree_sha="nouvel-arbre", patch_status=200, patch_status_puis=None):
        self.blobs, self.commits, self.patchs = [], 0, 0
        self.tree_sha = tree_sha
        self.patch_status = patch_status
        self.patch_status_puis = patch_status_puis

    def request(self, method, url, headers=None, timeout=None, json=None, **kw):
        if method == "GET" and "/git/ref/heads/" in url:
            return FausseReponse(200, {"object": {"sha": BASE_COMMIT}})
        if method == "GET" and "/git/commits/" in url:
            return FausseReponse(200, {"tree": {"sha": BASE_TREE}})
        if method == "POST" and url.endswith("/git/blobs"):
            self.blobs.append(json)
            return FausseReponse(200, {"sha": f"blob-{len(self.blobs)}"})
        if method == "POST" and url.endswith("/git/trees"):
            self.arbre = json
            return FausseReponse(200, {"sha": self.tree_sha})
        if method == "POST" and url.endswith("/git/commits"):
            self.commits += 1
            self.commit = json
            return FausseReponse(200, {"sha": "commit-neuf-0123456789"})
        if method == "PATCH" and "/git/refs/heads/" in url:
            self.patchs += 1
            self.patch = json
            statut = self.patch_status
            if self.patchs > 1 and self.patch_status_puis is not None:
                statut = self.patch_status_puis
            return FausseReponse(statut, {})
        raise AssertionError(f"appel inattendu : {method} {url}")


def publier(gh, fichiers, **kw):
    return gp.publish_atomic(gh, HEADERS, "o", "r", "main", fichiers, "msg", **kw)


@pytest.fixture
def fichiers():
    return {"a.json": '{"x":1}', "b.txt": "8.8.8.8\n", "c.csv": "u,1\n"}


def test_un_commit_pour_n_fichiers(fichiers):
    gh = FauxGitHub()
    assert publier(gh, fichiers) == "commit-neuf-0123456789"
    assert len(gh.blobs) == 3 and gh.commits == 1 and gh.patchs == 1
    assert gh.commit["parents"] == [BASE_COMMIT]
    assert gh.arbre["base_tree"] == BASE_TREE


def test_contenus_transmis_intacts(fichiers):
    fichiers["accents.txt"] = "héllo — ünicode\n"
    gh = FauxGitHub()
    publier(gh, fichiers)
    recus = {base64.b64decode(b["content"]).decode("utf-8") for b in gh.blobs}
    assert recus == set(fichiers.values())


def test_aucun_commit_si_contenu_inchange(fichiers):
    gh = FauxGitHub(tree_sha=BASE_TREE)
    assert publier(gh, fichiers) is None
    assert gh.commits == 0 and gh.patchs == 0


def test_rien_a_publier(fichiers):
    gh = FauxGitHub()
    assert publier(gh, {}) is None
    assert gh.blobs == []


def test_reconstruction_si_la_branche_a_bouge(fichiers):
    """Cas observé en production : feed.py et misp_export.py lancés en même
    temps. La bascule non forcée refuse d'écraser, on rebâtit sur la base
    fraîche."""
    gh = FauxGitHub(patch_status=422, patch_status_puis=200)
    assert publier(gh, fichiers) is not None
    assert gh.patchs == 2 and gh.commits == 2


def test_echec_persistant_remonte(fichiers):
    gh = FauxGitHub(patch_status=422)
    with pytest.raises(requests.HTTPError):
        publier(gh, fichiers)
    assert gh.patchs == gp.PUBLISH_ATTEMPTS


def test_erreur_non_conflictuelle_non_reessayee(fichiers):
    gh = FauxGitHub(patch_status=404)
    with pytest.raises(requests.HTTPError):
        publier(gh, fichiers)
    assert gh.patchs == 1


def test_bascule_jamais_forcee(fichiers):
    gh = FauxGitHub()
    publier(gh, fichiers)
    assert gh.patch.get("force") is False


def test_entrees_d_arbre_bien_formees(fichiers):
    gh = FauxGitHub()
    publier(gh, fichiers)
    assert {e["path"] for e in gh.arbre["tree"]} == set(fichiers)
    assert all(e["mode"] == "100644" and e["type"] == "blob" for e in gh.arbre["tree"])


def test_entetes_et_session():
    h = gp.build_headers("secret-token")
    assert h["Authorization"] == "Bearer secret-token"
    assert h["X-GitHub-Api-Version"] == "2022-11-28"
    retry = gp.make_session().get_adapter("https://api.github.com").max_retries
    assert retry.total == 4
    assert {"GET", "PUT", "POST", "PATCH"} <= set(retry.allowed_methods)


class SessionLecture:
    def __init__(self, reponses):
        self.reponses = reponses

    def get(self, url, headers=None, params=None, timeout=None):
        accept = (headers or {}).get("Accept", "")
        if "raw" in accept:
            return self.reponses["raw"]
        if "object" in accept:
            return self.reponses["object"]
        return self.reponses["defaut"]


def test_lecture_base64():
    contenu = base64.b64encode(b'{"a":1}').decode()
    s = SessionLecture({"defaut": FausseReponse(200, {"encoding": "base64",
                                                      "content": contenu, "sha": "s1"})})
    assert gp.get_file(s, HEADERS, "o", "r", "main", "x.json") == {"content": '{"a":1}', "sha": "s1"}


def test_lecture_fichier_absent():
    s = SessionLecture({"defaut": FausseReponse(404)})
    assert gp.get_file(s, HEADERS, "o", "r", "main", "x.json") is None


def test_repli_raw_au_dela_de_1mo():
    s = SessionLecture({
        "defaut": FausseReponse(403),
        "raw": FausseReponse(200, text='{"items":{"a":1}}'),
        "object": FausseReponse(200, {"sha": "sha-gros"}),
    })
    assert gp.get_file(s, HEADERS, "o", "r", "main", "db.json") == {
        "content": '{"items":{"a":1}}', "sha": "sha-gros"}
