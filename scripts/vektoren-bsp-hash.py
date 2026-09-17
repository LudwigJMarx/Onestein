#!/usr/bin/env python3
"""Erzeugt die Testvektoren fuer die Hash-Konstruktionen aus BSP.

Der Oracle ist hashlib.blake2b aus der Standardbibliothek, also eine von
unserer unabhaengige Implementierung von BLAKE2b. Das ist nicht der
Interop-Nachweis gegen Briar - der braucht die Java-Implementierung - aber es
ist mehr als ein Selbstgespraech: unsere Rust-Fassung und CPythons C-Fassung
muessen sich einig sein, sonst liegt der Fehler bei uns.

    python3 scripts/vektoren-bsp-hash.py

Gibt Rust aus. Die Ausgabe gehoert nach crates/sync/tests/spec_vectors.rs,
sie wird nicht automatisch hineingeschrieben: ein Generator, der seine eigenen
Erwartungen ueberschreibt, kann nicht fehlschlagen.

Spec: BSP 1.4 (HASH), 2.3 (group_id), 2.4 (body_hash, message_id).
"""

import hashlib

HASH_LEN = 32


def h(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=HASH_LEN).digest()


def bsp_hash(*teile: bytes) -> bytes:
    """HASH(x_1, ..., x_n) = H(int_32(len(x_1)) || x_1 || ...)."""
    roh = b""
    for teil in teile:
        roh += len(teil).to_bytes(4, "big") + teil
    return h(roh)


def rust(name: str, wert: bytes) -> str:
    bytes_je_zeile = 8
    zeilen = []
    for start in range(0, len(wert), bytes_je_zeile):
        stueck = wert[start:start + bytes_je_zeile]
        zeilen.append("    " + " ".join(f"0x{b:02x}," for b in stueck))
    return f"const {name}: [u8; {len(wert)}] = [\n" + "\n".join(zeilen) + "\n];"


# Feste Beispielwerte. Sie sind frei gewaehlt, aber ab jetzt unveraenderlich:
# wer sie aendert, aendert die Vektoren und damit den Nachweis.
CLIENT_ID = b"com.example.test"
CLIENT_MAJOR = 1
GROUP_DESCRIPTOR = bytes([0x01, 0x02])
MESSAGE_BODY = b"hello"
TIMESTAMP = 1_600_000_000_000

group_id = bsp_hash(
    b"org.briarproject.bramble/GROUP_ID",
    (1).to_bytes(1, "big"),
    CLIENT_ID,
    CLIENT_MAJOR.to_bytes(4, "big"),
    GROUP_DESCRIPTOR,
)
body_hash = bsp_hash(
    b"org.briarproject.bramble/MESSAGE_BLOCK",
    (1).to_bytes(1, "big"),
    MESSAGE_BODY,
)
message_id = bsp_hash(
    b"org.briarproject.bramble/MESSAGE_ID",
    (1).to_bytes(1, "big"),
    group_id,
    TIMESTAMP.to_bytes(8, "big"),
    body_hash,
)

print("// Erzeugt von scripts/vektoren-bsp-hash.py, Oracle: CPython hashlib.")
print(f"// python3 {hashlib.__name__}, BLAKE2b, digest_size={HASH_LEN}")
print()
print(rust("HASH_OF_NOTHING", bsp_hash()))
print(rust("HASH_OF_ONE_EMPTY_ARGUMENT", bsp_hash(b"")))
print(rust("HASH_OF_A_AND_BC", bsp_hash(b"a", b"bc")))
print(rust("GROUP_ID", group_id))
print(rust("BODY_HASH", body_hash))
print(rust("MESSAGE_ID", message_id))
