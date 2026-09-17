#!/usr/bin/env python3
"""Tests fuer pruefer-verdrahtet.py.

── WARUM DIE ZWEITE HAELFTE ────────────────────────────────────────────────

Der erste Block prueft `analysiere` gegen erfundene Eingaben. Das ist bequem
und deckt die Entscheidung ab - aber genau dort lag im ifc-lite-PR #4900 der
Fehler: beide Haelften nahmen eine eingespritzte "gibt es das?"-Funktion, jeder
Test reichte eine Attrappe, die Attrappe war richtig und die echte Funktion
falsch. Kein Test konnte fehlschlagen.

Deshalb fuehrt der zweite Block das Skript gegen einen echten, im
Temporaerverzeichnis gebauten Baum aus. Er deckt genau das ab, was die
Attrappe im ersten Block ersetzt: Dateien finden, Workflows lesen,
package.json auswerten, Rueckgabewert setzen.

Aufruf:  python3 scripts/pruefer-verdrahtet.test.py
         (nicht ueber `-m unittest`: der Bindestrich im Namen ist kein Modulname)
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HIER = Path(__file__).resolve().parent
QUELLE = HIER / "pruefer-verdrahtet.py"

_spec = importlib.util.spec_from_file_location("pruefer_verdrahtet", QUELLE)
modul = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
_spec.loader.exec_module(modul)


class Entscheidung(unittest.TestCase):
    """Der reine Teil: wer gilt als verdrahtet."""

    def test_im_workflow_genannt_gilt_als_verdrahtet(self):
        e = modul.analysiere(
            ["pruefe-a.py"],
            "run: python3 scripts/pruefe-a.py",
            {},
            {"pruefe-a.py": ""},
        )
        self.assertEqual(e["erreicht"], ["pruefe-a.py"])
        self.assertEqual(e["offen"], [])

    def test_ueber_ein_paketskript_das_die_ci_aufruft(self):
        e = modul.analysiere(
            ["pruefe-a.py"],
            "run: npm run pruefungen",
            {"pruefungen": "python3 scripts/pruefe-a.py"},
            {"pruefe-a.py": ""},
        )
        self.assertEqual(e["offen"], [])

    def test_paketskript_das_niemand_aufruft_verdrahtet_nichts(self):
        # Die Lehre aus ifc-lite #3062: ein Eintrag in package.json, den kein
        # Workflow je startet, laeuft so oft wie gar kein Eintrag.
        e = modul.analysiere(
            ["pruefe-a.py"],
            "run: npm run bauen",
            {"pruefungen": "python3 scripts/pruefe-a.py"},
            {"pruefe-a.py": ""},
        )
        self.assertEqual(e["offen"], ["pruefe-a.py"])

    def test_ein_erreichter_pruefer_zieht_den_nach_den_er_aufruft(self):
        e = modul.analysiere(
            ["pruefe-a.py", "pruefe-b.py"],
            "run: python3 scripts/pruefe-a.py",
            {},
            {"pruefe-a.py": "subprocess.run(['python3', 'scripts/pruefe-b.py'])",
             "pruefe-b.py": ""},
        )
        self.assertEqual(e["offen"], [])
        self.assertIn("pruefe-b.py", e["erreicht"])

    def test_kette_endet_und_dreht_sich_nicht(self):
        # Zwei Pruefer, die einander nennen, duerfen keine Endlosschleife geben.
        e = modul.analysiere(
            ["pruefe-a.py", "pruefe-b.py"],
            "run: python3 scripts/pruefe-a.py",
            {},
            {"pruefe-a.py": "scripts/pruefe-b.py", "pruefe-b.py": "scripts/pruefe-a.py"},
        )
        self.assertEqual(e["offen"], [])

    def test_ausweg_wird_genannt_statt_versteckt(self):
        e = modul.analysiere(
            ["pruefe-a.py"],
            "",
            {},
            {"pruefe-a.py": "# @nicht-in-der-ci liest die Uhr des Entwicklers, nicht das Repo\n"},
        )
        self.assertEqual(e["offen"], [])
        self.assertEqual(
            e["ausweg"],
            {"pruefe-a.py": "liest die Uhr des Entwicklers, nicht das Repo"},
        )

    def test_prosa_ueber_den_ausweg_entschuldigt_nichts(self):
        # Beim ersten Selbstlauf hat das Skript sich selbst entschuldigt: sein
        # Kopf ERKLAERT den Marker, und die Erkennung sah ihn mitten im Satz.
        e = modul.analysiere(
            ["pruefe-a.py"],
            "",
            {},
            {"pruefe-a.py": "# Wer will, schreibt `@nicht-in-der-ci <Grund>` in den Kopf.\n"},
        )
        self.assertEqual(e["ausweg"], {})
        self.assertEqual(e["offen"], ["pruefe-a.py"])

    def test_platzhalter_als_grund_zaehlt_nicht(self):
        e = modul.analysiere(
            ["pruefe-a.py"], "", {}, {"pruefe-a.py": "# @nicht-in-der-ci <Grund>\n"},
        )
        self.assertEqual(e["ausweg"], {})

    def test_ein_unverdrahteter_pruefer_faellt_auf(self):
        e = modul.analysiere(["pruefe-a.py"], "", {}, {"pruefe-a.py": ""})
        self.assertEqual(e["offen"], ["pruefe-a.py"])


class GegenEinenEchtenBaum(unittest.TestCase):
    """Die Naht: Dateien finden, Workflows lesen, Rueckgabewert setzen.

    Der Block oben kann das nicht sehen - dort ist jede dieser Antworten von
    Hand hineingereicht worden.
    """

    def baue(self, verzeichnis: Path, dateien: dict[str, str]) -> None:
        for pfad, inhalt in dateien.items():
            ziel = verzeichnis / pfad
            ziel.parent.mkdir(parents=True, exist_ok=True)
            ziel.write_text(inhalt, encoding="utf-8")

    def laufe(self, wurzel: Path) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(QUELLE), "--wurzel", str(wurzel)],
            capture_output=True, text=True,
        )

    def test_findet_den_unverdrahteten_pruefer_und_scheitert(self):
        with tempfile.TemporaryDirectory() as tmp:
            wurzel = Path(tmp)
            self.baue(wurzel, {
                "scripts/pruefe-a.py": "print('a')\n",
                "scripts/tief/pruefe-b.py": "print('b')\n",
                ".github/workflows/pruefungen.yml":
                    "jobs:\n  p:\n    steps:\n      - run: python3 scripts/pruefe-a.py\n",
            })
            lauf = self.laufe(wurzel)

            self.assertEqual(lauf.returncode, 1)
            self.assertIn("pruefe-b.py", lauf.stdout)
            self.assertNotIn("scripts/pruefe-a.py\n", lauf.stdout.split("niemand auf")[-1])

    def test_gruen_wenn_alles_verdrahtet_ist(self):
        with tempfile.TemporaryDirectory() as tmp:
            wurzel = Path(tmp)
            self.baue(wurzel, {
                "scripts/pruefe-a.py": "print('a')\n",
                "package.json": json.dumps({"scripts": {"pruefungen": "python3 scripts/pruefe-a.py"}}),
                ".github/workflows/ci.yml": "steps:\n  - run: npm run pruefungen\n",
            })
            lauf = self.laufe(wurzel)

            self.assertEqual(lauf.returncode, 0, lauf.stdout + lauf.stderr)
            self.assertIn("1 Pruefer, 1 verdrahtet", lauf.stdout)

    def test_kein_pruefer_gefunden_sagt_das_statt_gruen_zu_melden(self):
        # "0 Probleme" ist auch, was ein Pruefer meldet, der nichts angesehen
        # hat. Die beiden Faelle muessen unterscheidbar bleiben.
        with tempfile.TemporaryDirectory() as tmp:
            lauf = self.laufe(Path(tmp))

            self.assertEqual(lauf.returncode, 0)
            self.assertIn("kein Pruefer", lauf.stdout)

    def test_test_dateien_zaehlen_nicht_als_pruefer(self):
        with tempfile.TemporaryDirectory() as tmp:
            wurzel = Path(tmp)
            self.baue(wurzel, {"scripts/pruefe-a.test.py": "pass\n"})
            lauf = self.laufe(wurzel)

            self.assertEqual(lauf.returncode, 0)
            self.assertIn("kein Pruefer", lauf.stdout)


if __name__ == "__main__":
    unittest.main()
