"""Push MISP : c'est un canal secondaire, sa panne ne doit pas annuler un run
dont les feeds sont déjà publiés."""
import feed


def test_connexion_impossible_nannule_pas_le_run(monkeypatch):
    """Un 403 (clé révoquée, rôle sans accès API) tuait le run en exit 1 alors
    que les 14 fichiers venaient d'être publiés."""
    def explose(*a, **k):
        raise RuntimeError("403 Authentication failed")

    monkeypatch.setattr(feed, "PYMISP_AVAILABLE", True)
    monkeypatch.setattr(feed, "PyMISP", explose, raising=False)
    monkeypatch.setattr(feed, "MISP_URL", "https://misp.test")
    monkeypatch.setattr(feed, "MISP_KEY", "k" * 40)

    feed.push_misp({"items": {"1.1.1.1": {}}}, [])   # ne doit rien lever


def test_aucune_connexion_si_misp_non_configure(monkeypatch):
    tente = {"v": False}

    def marqueur(*a, **k):
        tente["v"] = True

    monkeypatch.setattr(feed, "PYMISP_AVAILABLE", True)
    monkeypatch.setattr(feed, "PyMISP", marqueur, raising=False)
    monkeypatch.setattr(feed, "MISP_URL", "")
    feed.push_misp({"items": {}}, [])
    assert not tente["v"]


def test_aucune_connexion_si_pymisp_absent(monkeypatch):
    tente = {"v": False}

    def marqueur(*a, **k):
        tente["v"] = True

    monkeypatch.setattr(feed, "PYMISP_AVAILABLE", False)
    monkeypatch.setattr(feed, "PyMISP", marqueur, raising=False)
    feed.push_misp({"items": {}}, [])
    assert not tente["v"]
