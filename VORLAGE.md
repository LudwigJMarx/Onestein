# Projektvorlage

Das Gerüst, mit dem ein neues eigenes Projekt anfängt, statt es sich über
Jahre zu erarbeiten. Angewendet mit:

```bash
werkzeuge/neues-projekt <name> [--freelance]
```

## Was drin ist

| Datei | Zweck |
|---|---|
| `AGENTS.md` | Gerüst der Hausregeln. `CLAUDE.md` zeigt nur darauf. |
| `scripts/pruefer-verdrahtet.py` | prüft, dass jeder Prüfer auch aufgerufen wird |
| `scripts/pruefer-verdrahtet.test.py` | dessen Test, 13 Fälle |
| `.github/workflows/pruefungen.yml` | ruft beide auf, bevor irgendetwas anderes läuft |

Python 3, nur Standardbibliothek. Läuft auch in einem Node-Projekt, weil die
GitHub-Läufer beides mitbringen; `package.json` und `pyproject.toml` werden
beide als Quelle für Skriptnamen gelesen.

## Woher die Regeln stammen

Nicht aus Lehrbüchern. Jede stammt aus einem Vorfall in einem fremden Repo,
den wir beim Mitarbeiten gesehen haben — oder aus einem eigenen Fehler.

| Regel | Vorfall |
|---|---|
| Ein Prüfer, den niemand aufruft, ist eine Datei | `LTplus-AG/ifc-lite` #3062: Gate-Skript samt Test eingecheckt, ohne CI-Schritt. Unsichtbar wie gar kein Gate. |
| Ein Prüfer sagt, was er angesehen hat | dieselbe Quelle: „0 Probleme" ist auch, was ein Prüfer meldet, der nichts gelesen hat |
| Handeln und Prüfen sind zwei Schritte | `ifc-lite` #633 hat Worker-URLs umgeschrieben, #637 musste denselben Fehler nachträglich beheben — die Ersetzung hatte eine Datei übersehen, und niemand sah aufs Ergebnis |
| Eine Attrappe verschiebt das Risiko in die Naht | `ifc-lite` #4900, unser eigener PR: beide Hälften nahmen eine eingespritzte „gibt es das?"-Funktion, jeder Test reichte eine Attrappe. Die Attrappe war richtig, die echte Funktion falsch, kein Test konnte fehlschlagen. Zwei Review-Bots fanden es sofort. |
| Die Verdrahtung wird mitgeprüft | derselbe PR, dritter Review-Befund: alle Tests riefen die Funktionen direkt auf und wären grün geblieben, wenn der Bauablauf sie nicht mehr startet |
| Nie auf Quelltext zusichern | `ifc-lite` #2396: ein Test las den Funktionskörper aus und blieb 5/5 grün, nachdem der Handler durch eine leere Funktion ersetzt worden war |
| Ein Ausweg wird genannt, nicht versteckt | `ifc-lite` führt Ausnahmen mit Begründung und einer Obergrenze, die nur sinken darf (#2434) |

`eigene/ekur` hat einen Teil davon bereits selbst erarbeitet — „Eine Suche, die
nichts findet, sieht aus wie eine leere Ablage" und „Prüfer melden, sie räumen
nicht auf" stehen dort seit Längerem. Die Vorlage ergänzt, was dort fehlt: die
Verdrahtungsprüfung, die Naht-Regel und der benannte Ausweg.

## Der Prüfer hat sich beim ersten Lauf selbst erwischt

Gegen die eigene Vorlage ausgeführt, meldete `pruefer-verdrahtet.py`:

```
1 Pruefer, 1 verdrahtet, 1 mit Ausweg, 0 offen
  kein CI-Gate laut Erklaerung: scripts/pruefer-verdrahtet.py - <Grund>`. Es wird ...
```

Sein eigener Kopf **erklärt** den Ausweg-Marker, und die Erkennung sah ihn
mitten im Satz. Ein Werkzeug, das seine eigene Anleitung für einen Befund hält.
Der Marker muss jetzt die ganze Kommentarzeile sein und darf keinen Platzhalter
als Grund tragen; zwei Tests halten das fest.

Das gehört hierher, weil es die Vorlage beschreibt: die Regeln sind nicht
gemeint, sie sind ausgeführt.

## Was die Vorlage nicht mitbringt

Kein Linter, kein Testwerkzeug, keine Sprachwahl, keine Lizenz. Das hängt am
Projekt, und eine Vorlage, die es vorwegnimmt, wird beim ersten Projekt
umgebaut und beim zweiten ignoriert.
