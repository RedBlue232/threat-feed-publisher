"""Arrondi horaire des timestamps publiés.

L'implémentation historique tronquait la chaîne ISO, ce qui étiquetait « Z »
un horodatage décalé : 13:47+02:00 devenait 13:00:00Z, soit deux heures dans
le futur. Les sources ne garantissent pas de renvoyer de l'UTC.
"""
import pytest

import feed


@pytest.mark.parametrize("entree,attendu", [
    ("2026-08-22T13:47:59Z",        "2026-08-22T13:00:00Z"),
    ("2026-08-22T13:47:59.123456Z", "2026-08-22T13:00:00Z"),
    ("2026-08-22T13:47:59+02:00",   "2026-08-22T11:00:00Z"),
    ("2026-08-22T01:30:00-05:00",   "2026-08-22T06:00:00Z"),
    ("2026-08-22T13:47:59",         "2026-08-22T13:00:00Z"),  # naïf => UTC
    ("2026-08-22T00:30:00+02:00",   "2026-08-21T22:00:00Z"),  # bascule de jour
])
def test_round_to_hour(entree, attendu):
    assert feed.round_to_hour(entree) == attendu


def test_round_to_hour_tolere_une_entree_illisible():
    """Un timestamp corrompu ne doit pas faire échouer toute la publication."""
    assert feed.round_to_hour("pas-une-date") == "pas-une-date"
