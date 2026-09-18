#!/usr/bin/env python3
"""Test fuer pruefe-verweise.py.

Ein Pruefer, der beim ersten Lauf "0 Befunde" meldet, ist von einem, der nichts
angesehen hat, nicht zu unterscheiden. Diese Faelle zeigen, dass er sieht.

Aufruf:  python3 scripts/pruefe-verweise.test.py
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

PRUEFER = Path(__file__).parent / "pruefe-verweise.py"


def lauf(dateien: dict[str, str]) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as ordner:
        wurzel = Path(ordner)
        for pfad, inhalt in dateien.items():
            ziel = wurzel / pfad
            ziel.parent.mkdir(parents=True, exist_ok=True)
            ziel.write_text(inhalt, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(PRUEFER), "--wurzel", str(wurzel)],
            capture_output=True,
            text=True,
            check=False,
        )


FAELLE: list[tuple[str, dict[str, str], int, str]] = [
    (
        "heile Verweise gehen durch",
        {
            "spec/00.md": "siehe `10.md` §2 und [das](../docs/x.md)\n",
            "spec/10.md": "# T\n\n## 1 Eins\n\n## 2 Zwei\n",
            "docs/x.md": "# X\n",
        },
        0,
        "0 Befunde",
    ),
    (
        "eine Datei, die es nicht gibt",
        {"spec/00.md": "siehe `fehlt.md`\n"},
        1,
        "gibt es nicht",
    ),
    (
        "ein Abschnitt, den es nicht gibt",
        {
            "spec/00.md": "siehe `10.md` §9\n",
            "spec/10.md": "# T\n\n## 1 Eins\n",
        },
        1,
        "keinen Abschnitt 9",
    ),
    (
        "ein Link ins Leere",
        {"spec/00.md": "[weg](./weg.md)\n"},
        1,
        "zeigt ins Leere",
    ),
    (
        "externe Links werden nicht geprueft",
        {"spec/00.md": "[extern](https://example.invalid/a.md)\n"},
        0,
        "0 Befunde",
    ),
    (
        "kein Dokument da: laut scheitern, nicht still durchgehen",
        {"liesmich.txt": "nichts\n"},
        2,
        "keine Dokumente",
    ),
]


def main() -> int:
    fehler = 0
    for name, dateien, erwarteter_code, erwarteter_text in FAELLE:
        ergebnis = lauf(dateien)
        ausgabe = ergebnis.stdout + ergebnis.stderr
        if ergebnis.returncode != erwarteter_code:
            print(f"  FEHLER {name}: Code {ergebnis.returncode}, erwartet {erwarteter_code}")
            fehler += 1
        elif erwarteter_text not in ausgabe:
            print(f"  FEHLER {name}: '{erwarteter_text}' fehlt in der Ausgabe")
            fehler += 1
    print(f"pruefe-verweise.test: {len(FAELLE)} Faelle geprueft, {fehler} fehlgeschlagen.")
    return 1 if fehler else 0


if __name__ == "__main__":
    sys.exit(main())
