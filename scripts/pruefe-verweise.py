#!/usr/bin/env python3
"""Prueft, dass Verweise zwischen den Dokumenten ins Leere zeigen oder nicht.

── WARUM ES DAS BRAUCHT ────────────────────────────────────────────────────

Beim Schreiben von 30-handshake.md stand ein Verweis auf `50-sync.md`, das es
nicht gab, und das Record-Format war damit nirgends definiert. Beim Schreiben
von 20-transport.md behauptete ein Abschnitt, die Transportversion haenge im
Wurzelschluessel, waehrend der Handschlag nur drei Versionen band. Beide Male
fiel es beim Gegenlesen auf. Beim dritten Mal faellt es nicht auf.

Ein Dokumentensatz, dessen Verweise niemand prueft, ist eine Sammlung von
Dateien, die sich aufeinander berufen, ohne sich zu treffen.

── WAS ER PRUEFT ───────────────────────────────────────────────────────────

Alle .md-Dateien unter spec/, docs/ und in der Wurzel:

1. `dateiname.md` in Backticks: die Datei existiert, relativ zur verweisenden.
2. `dateiname.md` §N: die Zieldatei hat einen Abschnitt `## N ...`.
3. [text](pfad): der Pfad existiert.

── WAS ER NICHT PRUEFT ─────────────────────────────────────────────────────

Ob der verwiesene Abschnitt inhaltlich das sagt, was der Verweis behauptet.
Das kann nur ein Mensch, und genau daran sind beide Befunde oben haengen
geblieben, bis jemand hinsah.

Aufruf:  python3 scripts/pruefe-verweise.py [--wurzel PFAD]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

DOKUMENTE = ("spec", "docs")
# Dazu die Markdown-Dateien in der Wurzel. Die README verweist am haeufigsten
# nach spec/ und ist die Datei, die ein Leser zuerst sieht und die zuerst
# verrottet.
BACKTICK = re.compile(r"`([0-9A-Za-z._-]+\.md)`(?:\s+§(\d+))?")
MARKDOWN_LINK = re.compile(r"\[[^\]]*\]\(([^)#]+\.md)(?:#[^)]*)?\)")
ABSCHNITT = re.compile(r"^##\s+(\d+)\s")


def abschnitte(datei: Path) -> set[str]:
    return {
        treffer.group(1)
        for zeile in datei.read_text(encoding="utf-8").splitlines()
        if (treffer := ABSCHNITT.match(zeile))
    }


def main() -> int:
    zerleger = argparse.ArgumentParser(description=__doc__)
    zerleger.add_argument("--wurzel", default=".", type=Path)
    argumente = zerleger.parse_args()
    wurzel = argumente.wurzel.resolve()

    dateien = sorted(
        [pfad for ordner in DOKUMENTE for pfad in (wurzel / ordner).rglob("*.md")]
        + list(wurzel.glob("*.md"))
    )
    if not dateien:
        print(f"pruefe-verweise: keine Dokumente unter {'/, '.join(DOKUMENTE)}/", file=sys.stderr)
        return 2

    befunde: list[str] = []
    verweise = 0
    abschnitt_cache: dict[Path, set[str]] = {}

    for datei in dateien:
        text = datei.read_text(encoding="utf-8")
        hier = datei.relative_to(wurzel)

        for treffer in BACKTICK.finditer(text):
            name, nummer = treffer.group(1), treffer.group(2)
            verweise += 1
            ziel = datei.parent / name
            if not ziel.exists():
                befunde.append(f"{hier}: `{name}` gibt es nicht")
                continue
            if nummer is None:
                continue
            if ziel not in abschnitt_cache:
                abschnitt_cache[ziel] = abschnitte(ziel)
            if nummer not in abschnitt_cache[ziel]:
                befunde.append(f"{hier}: `{name}` hat keinen Abschnitt {nummer}")

        for treffer in MARKDOWN_LINK.finditer(text):
            ziel_text = treffer.group(1)
            if ziel_text.startswith(("http://", "https://")):
                continue
            verweise += 1
            if not (datei.parent / ziel_text).exists():
                befunde.append(f"{hier}: Link auf {ziel_text} zeigt ins Leere")

    for befund in befunde:
        print(f"  {befund}", file=sys.stderr)
    print(
        f"pruefe-verweise: {verweise} Verweise in {len(dateien)} Dateien geprueft, "
        f"{len(befunde)} Befunde."
    )
    return 1 if befunde else 0


if __name__ == "__main__":
    sys.exit(main())
