#!/usr/bin/env python3
"""Prueft, ob jeder Pruefer im Projekt auch tatsaechlich aufgerufen wird.

── WARUM ES DAS BRAUCHT ────────────────────────────────────────────────────

Ein Pruefer, den niemand startet, ist von einem Pruefer, der nichts findet,
nicht zu unterscheiden. Beide melden nichts. Beide sehen aus wie Ordnung.

Im ifc-lite-Repo ist genau das passiert (deren #3062): ein Gate-Skript wurde
samt Test eingecheckt, ohne Schritt in der CI, ohne Eintrag in package.json,
ohne Turbo-Aufgabe. Niemandem fiel es auf, weil ein nie gelaufener Pruefer
dieselbe Stille erzeugt wie ein zufriedener. Ihre Lehre daraus, woertlich:
ein Eintrag in package.json, den kein Workflow je aufruft, laeuft genauso oft
wie gar kein Eintrag.

Dieses Skript ist der Pruefer dafuer. Es ist bewusst das einzige, das sich um
andere Pruefer kuemmert; alles Weitere gehoert in die Pruefer selbst.

── WAS ES ALS PRUEFER ANSIEHT ──────────────────────────────────────────────

Jede Datei unter `scripts/` in beliebiger Tiefe, deren Name mit `pruefe`,
`pruef`, `check` oder `verify` beginnt, mit Endung .py, .sh, .mjs, .js oder
.ts. Die Namenskonvention ist die Anmeldung: wer einen Pruefer anders nennt,
meldet ihn nicht an und wird hier nicht vermisst. Das ist die bekannte Luecke,
keine Nachlaessigkeit.

── WAS ALS AUFRUF ZAEHLT ───────────────────────────────────────────────────

1. Der Dateiname steht in einem Workflow unter `.github/workflows/`.
2. Der Dateiname steht in einem Skript in `package.json` ODER `pyproject.toml`,
   und dessen Name wird seinerseits in einem Workflow aufgerufen. Eine Ebene
   Weiterreichung, mehr nicht - tiefere Ketten sind selten und die zusaetzliche
   Ungenauigkeit ist es nicht wert.
3. Ein bereits erreichter Pruefer nennt den Dateinamen (ruft ihn also auf oder
   importiert ihn).

── AUSWEG, DER SICHTBAR BLEIBT ─────────────────────────────────────────────

Ein Skript, das absichtlich nicht in der CI laufen soll, traegt in den ersten
40 Zeilen `@nicht-in-der-ci <Grund>`. Es wird dann aufgezaehlt statt versteckt.
Ein Ausweg ohne Grund ist ein Fehler, sonst waere es ein stilles Loch.

Aufruf:  python3 scripts/pruefer-verdrahtet.py [--wurzel PFAD]
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

PRAEFIXE = ("pruefe", "pruef", "check", "verify")
ENDUNGEN = (".py", ".sh", ".mjs", ".js", ".ts")
UEBERSPRINGEN = {"node_modules", "dist", "build", ".git", ".venv", "__pycache__", "target"}
# Der Marker muss die GANZE Kommentarzeile sein, und sein Grund darf kein
# Platzhalter sein. Die erste Fassung suchte ihn irgendwo in der Zeile - und
# entschuldigte damit dieses Skript selbst, weil sein Kopf den Marker erklaert.
# Ein Werkzeug, das seine eigene Anleitung fuer einen Befund haelt, ist genau
# die Falle, gegen die es gebaut wurde.
AUSWEG = re.compile(r"^\s*(?:#|//|\*)?\s*@nicht-in-der-ci\s+(?!<)(.+?)\s*$")


def ist_pruefer(pfad: Path) -> bool:
    name = pfad.name.lower()
    if name.endswith(".test.py") or ".test." in name or ".spec." in name:
        return False
    return name.startswith(PRAEFIXE) and pfad.suffix in ENDUNGEN


def sammle_pruefer(wurzel: Path) -> list[Path]:
    skripte = wurzel / "scripts"
    if not skripte.is_dir():
        return []
    return sorted(
        p for p in skripte.rglob("*")
        if p.is_file()
        and not UEBERSPRINGEN & set(p.relative_to(wurzel).parts)
        and ist_pruefer(p)
    )


def lies(pfad: Path) -> str:
    try:
        return pfad.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def ausweg_grund(inhalt: str) -> str | None:
    for zeile in inhalt.splitlines()[:40]:
        treffer = AUSWEG.search(zeile)
        if treffer:
            return treffer.group(1).strip()
    return None


def analysiere(
    pruefer: list[str],
    ci_text: str,
    paket_skripte: dict[str, str],
    inhalte: dict[str, str],
) -> dict:
    """Die eigentliche Entscheidung. Rein, damit der Test sie ohne Dateisystem
    durchspielen kann - und der Test am Ende fuehrt sie zusaetzlich gegen einen
    echten Baum, weil sonst nur die Attrappe geprueft waere und nicht die Naht.

    `pruefer`      Dateinamen (ohne Pfad)
    `ci_text`      aller Workflow-Text, aneinandergehaengt
    `paket_skripte` Name -> Befehlszeile aus package.json / pyproject.toml
    `inhalte`      Dateiname -> Inhalt des Pruefers
    """
    direkt = {p for p in pruefer if p in ci_text}

    ueber_paket = set()
    for name, befehl in paket_skripte.items():
        if not any(p in befehl for p in pruefer):
            continue
        if name in ci_text:
            ueber_paket |= {p for p in pruefer if p in befehl}

    erreicht = direkt | ueber_paket
    # Ein erreichter Pruefer, der einen anderen aufruft, erreicht diesen mit.
    for _ in range(len(pruefer)):
        gewachsen = set(erreicht)
        for p in erreicht:
            text = inhalte.get(p, "")
            gewachsen |= {q for q in pruefer if q != p and q in text}
        if gewachsen == erreicht:
            break
        erreicht = gewachsen

    mit_ausweg = {p: g for p in pruefer if (g := ausweg_grund(inhalte.get(p, "")))}
    offen = [p for p in pruefer if p not in erreicht and p not in mit_ausweg]
    return {"erreicht": sorted(erreicht), "ausweg": mit_ausweg, "offen": sorted(offen)}


def main() -> int:
    zerleger = argparse.ArgumentParser(description=__doc__)
    zerleger.add_argument("--wurzel", default=".", type=Path)
    argumente = zerleger.parse_args()
    wurzel = argumente.wurzel.resolve()

    pfade = sammle_pruefer(wurzel)
    if not pfade:
        # Kein Pruefer gefunden heisst nicht "alles verdrahtet". Es heisst
        # entweder "es gibt keine" oder "ich habe am falschen Ort gesucht",
        # und die beiden duerfen nicht gleich aussehen.
        print(f"pruefer-verdrahtet: kein Pruefer unter {wurzel}/scripts gefunden.")
        print("  Entweder gibt es hier keine, oder die Namenskonvention stimmt nicht")
        print(f"  (erwartet: Name beginnt mit {'/'.join(PRAEFIXE)}, Endung aus {', '.join(ENDUNGEN)}).")
        return 0

    ci_verzeichnis = wurzel / ".github" / "workflows"
    ci_dateien = sorted(ci_verzeichnis.glob("*.y*ml")) if ci_verzeichnis.is_dir() else []
    ci_text = "\n".join(lies(p) for p in ci_dateien)

    paket_skripte: dict[str, str] = {}
    paket = wurzel / "package.json"
    if paket.is_file():
        import json
        try:
            paket_skripte.update(json.loads(lies(paket)).get("scripts") or {})
        except json.JSONDecodeError:
            print(f"pruefer-verdrahtet: {paket} ist kein gueltiges JSON.", file=sys.stderr)
            return 1
    pyproject = wurzel / "pyproject.toml"
    if pyproject.is_file():
        # Bewusst lexikalisch statt per TOML-Parser: die Aufgaben stehen je nach
        # Werkzeug unter [tool.poe.tasks], [tool.hatch.envs...] oder anderswo,
        # und eine Zeile "name = \"...pruefe-x.py...\"" faengt sie alle.
        for zeile in lies(pyproject).splitlines():
            treffer = re.match(r'\s*([\w.-]+)\s*=\s*["\'](.+)["\']\s*$', zeile)
            if treffer:
                paket_skripte.setdefault(treffer.group(1), treffer.group(2))

    inhalte = {p.name: lies(p) for p in pfade}
    ergebnis = analysiere([p.name for p in pfade], ci_text, paket_skripte, inhalte)

    nach_name = {p.name: p.relative_to(wurzel).as_posix() for p in pfade}

    print(
        f"pruefer-verdrahtet: {len(pfade)} Pruefer, "
        f"{len(ergebnis['erreicht'])} verdrahtet, "
        f"{len(ergebnis['ausweg'])} mit Ausweg, "
        f"{len(ergebnis['offen'])} offen "
        f"({len(ci_dateien)} Workflow-Datei(en) gelesen)."
    )
    for name, grund in sorted(ergebnis["ausweg"].items()):
        print(f"  kein CI-Gate laut Erklaerung: {nach_name[name]} - {grund}")

    if ergebnis["offen"]:
        print()
        print("Diese Pruefer ruft niemand auf. Sie laufen so oft wie gar nicht vorhanden:")
        for name in ergebnis["offen"]:
            print(f"  {nach_name[name]}")
        print()
        print("Abhilfe: einen Schritt in .github/workflows/ ergaenzen, oder ein Skript")
        print("in package.json/pyproject.toml, das ein Workflow aufruft - oder die Zeile")
        print("`@nicht-in-der-ci <Grund>` in den Kopf der Datei, wenn das Absicht ist.")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
