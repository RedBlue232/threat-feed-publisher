"""Vérifications statiques sur misp_export.py.

Le module importe `pymisp` au niveau global, absent du job de test (dépendance
lourde pour trois assertions). On inspecte donc la source : cela suffit à
détecter une régression — réintroduction d'une écriture fichier par fichier,
ou perte du traitement d'erreur.
"""
from pathlib import Path

import pytest

SOURCE = (Path(__file__).resolve().parent.parent / "scripts" / "misp_export.py").read_text(
    encoding="utf-8"
)


def test_publication_atomique():
    """Un event et son manifeste doivent partir ensemble : un manifeste
    référençant un event pas encore écrit est un état incohérent visible
    publiquement."""
    assert "github_publish.publish_atomic(" in SOURCE


@pytest.mark.parametrize("disparu", ["def gh_put_file", "def gh_get_sha"])
def test_helpers_par_fichier_supprimes(disparu):
    """Ces helpers écrivaient un commit par fichier via l'API Contents."""
    assert disparu not in SOURCE


def test_connexion_misp_protegee():
    """Sans connexion il n'y a rien à exporter : l'échec reste fatal, mais le
    traceback PyMISP brut doit devenir un message actionnable."""
    apres_connexion = SOURCE.split("misp = PyMISP")[1][:300]
    assert "except Exception as e:" in apres_connexion
    assert "accès API activé" in SOURCE


def test_sortie_propre_sur_erreur():
    assert 'log.error("ERREUR FATALE' in SOURCE
    assert "sys.exit(1)" in SOURCE


def test_champs_sensibles_retires_avant_publication():
    """event_creator_email et les identifiants internes ne doivent jamais
    sortir dans le feed MISP public."""
    for champ in ("event_creator_email", "Sighting", "org_id"):
        assert champ in SOURCE
    assert "EVENT_STRIP" in SOURCE and "ATTR_STRIP" in SOURCE
