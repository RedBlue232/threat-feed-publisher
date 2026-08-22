"""Client GitHub : réessais et lecture des fichiers volumineux."""
import base64

import feed


class FausseReponse:
    def __init__(self, status, payload=None, text=""):
        self.status_code = status
        self._payload = payload
        self.text = text

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


def test_session_reessaie_les_erreurs_transitoires():
    """Un run publie plusieurs fichiers : un 5xx isolé ne doit pas tout avorter."""
    retry = feed.GH_SESSION.get_adapter("https://api.github.com").max_retries
    assert retry.total == 4
    assert {429, 500, 502, 503, 504} <= set(retry.status_forcelist)
    assert {"GET", "PUT"} <= set(retry.allowed_methods)


def test_lecture_normale_base64(monkeypatch):
    contenu = base64.b64encode(b'{"a":1}').decode()
    monkeypatch.setattr(feed.GH_SESSION, "get",
        lambda *a, **k: FausseReponse(200, {"encoding": "base64", "content": contenu, "sha": "s1"}))
    assert feed.gh_get_file("state/db.json") == {"content": '{"a":1}', "sha": "s1"}


def test_fichier_absent(monkeypatch):
    monkeypatch.setattr(feed.GH_SESSION, "get", lambda *a, **k: FausseReponse(404))
    assert feed.gh_get_file("absent.json") is None


def test_fichier_vide_nest_pas_confondu_avec_un_fichier_trop_gros(monkeypatch):
    monkeypatch.setattr(feed.GH_SESSION, "get",
        lambda *a, **k: FausseReponse(200, {"encoding": "base64", "content": "", "sha": "s0"}))
    assert feed.gh_get_file("vide.json") == {"content": "", "sha": "s0"}


def test_repli_raw_au_dela_de_1mo(monkeypatch):
    """Au-delà de 1 Mo l'API Contents refuse le contenu inline. Sans repli,
    json.loads('') rendait chaque run fatal et le pipeline restait mort."""
    def faux_get(url, headers=None, params=None, timeout=None):
        accept = (headers or {}).get("Accept", "")
        if "raw" in accept:
            return FausseReponse(200, text='{"items":{"a":1}}')
        if "object" in accept:
            return FausseReponse(200, {"sha": "sha-gros", "content": "", "encoding": "none"})
        return FausseReponse(403)

    monkeypatch.setattr(feed.GH_SESSION, "get", faux_get)
    assert feed.gh_get_file("state/db.json") == {"content": '{"items":{"a":1}}', "sha": "sha-gros"}
