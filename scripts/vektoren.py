#!/usr/bin/env python3
"""Erzeugt die Testvektoren fuer die Bezeichner aus spec/40-identity.md und
spec/50-sync.md.

Der Oracle ist hashlib.blake2b aus der Standardbibliothek, also eine von
unserer unabhaengige Implementierung von BLAKE2b. Das ist kein Nachweis, dass
die Dokumente richtig sind, sondern nur, dass Rust und CPython dieselbe
Rahmung und dieselbe Primitive rechnen.

    python3 scripts/vektoren.py

Gibt Rust aus. Die Ausgabe gehoert von Hand in die Testdateien: ein Generator,
der seine eigenen Erwartungen ueberschreibt, kann nicht fehlschlagen.
"""

import hashlib

HASH_LEN = 32
IDENTITY_VERSION = 1
SYNC_VERSION = 1


def bsp_hash(*teile: bytes) -> bytes:
    """HASH(x_1, ..., x_n) = H(int_32(len(x_1)) || x_1 || ...), spec/05-primitives.md."""
    roh = b""
    for teil in teile:
        roh += len(teil).to_bytes(4, "big") + teil
    return hashlib.blake2b(roh, digest_size=HASH_LEN).digest()


def prf(schluessel: bytes, nachricht: bytes) -> bytes:
    """PRF(k, m), spec/05-primitives.md: keyed BLAKE2b."""
    return hashlib.blake2b(nachricht, key=schluessel, digest_size=HASH_LEN).digest()


def kdf(schluessel: bytes, *teile: bytes) -> bytes:
    """KDF(k, x_1, ..., x_n) = PRF(k, int_32(len(x_1)) || x_1 || ...)."""
    roh = b""
    for teil in teile:
        roh += len(teil).to_bytes(4, "big") + teil
    return prf(schluessel, roh)


def rust(name: str, wert: bytes) -> str:
    zeilen = [
        "    " + " ".join(f"0x{b:02x}," for b in wert[i:i + 16])
        for i in range(0, len(wert), 16)
    ]
    return f"const {name}: [u8; {len(wert)}] = [\n" + "\n".join(zeilen) + "\n];"


# Feste Beispielwerte, frei gewaehlt und ab jetzt unveraenderlich: wer sie
# aendert, aendert die Vektoren und damit den Nachweis. Die Schluessel sind
# Fuellmuster in der richtigen Laenge, keine echten Schluessel.
ROOT_ED25519 = bytes([0x11]) * 32
ROOT_MLDSA = bytes([0x22]) * 1952
DEVICE_SIGNING = bytes([0x33]) * 32
CLIENT_ID = b"com.example.test"
CLIENT_MAJOR = 1
GROUP_DESCRIPTOR = bytes([0x01, 0x02])
MESSAGE_BODY = b"hello"
TIMESTAMP = 1_600_000_000_000

identity_id = bsp_hash(
    b"org.onestein.identity/IDENTITY_ID",
    IDENTITY_VERSION.to_bytes(1, "big"),
    ROOT_ED25519,
    ROOT_MLDSA,
)
group_id = bsp_hash(
    b"org.onestein.sync/GROUP_ID",
    SYNC_VERSION.to_bytes(1, "big"),
    CLIENT_ID,
    CLIENT_MAJOR.to_bytes(4, "big"),
    GROUP_DESCRIPTOR,
)
body_hash = bsp_hash(
    b"org.onestein.sync/MESSAGE_BLOCK",
    SYNC_VERSION.to_bytes(1, "big"),
    MESSAGE_BODY,
)
message_id = bsp_hash(
    b"org.onestein.sync/MESSAGE_ID",
    SYNC_VERSION.to_bytes(1, "big"),
    group_id,
    TIMESTAMP.to_bytes(8, "big"),
    identity_id,
    DEVICE_SIGNING,
    body_hash,
)
to_sign = bsp_hash(
    b"org.onestein.sync/MESSAGE_SIGNATURE",
    SYNC_VERSION.to_bytes(1, "big"),
    message_id,
)

print("// Erzeugt von scripts/vektoren.py, Oracle: CPython hashlib.")
print()
print(rust("HASH_OF_NOTHING", bsp_hash()))
print(rust("HASH_OF_ONE_EMPTY_ARGUMENT", bsp_hash(b"")))
print(rust("HASH_OF_A_AND_BC", bsp_hash(b"a", b"bc")))
print(rust("IDENTITY_ID", identity_id))
print(rust("GROUP_ID", group_id))
print(rust("BODY_HASH", body_hash))
print(rust("MESSAGE_ID", message_id))
print(rust("TO_SIGN", to_sign))

# --- Transport, spec/20-transport.md -------------------------------------

TRANSPORT_VERSION = 1
ROOT_KEY = bytes([0x44]) * 32
TRANSPORT_ID = b"org.onestein.transport.tor"
STREAM_NUMBER = 7
# Periode 25 h, also 90000 s. T liegt in Periode 700, die Anfangsschluessel
# gehoeren zu Periode 699.
PERIODE_T = 700

a_tag = kdf(ROOT_KEY, b"org.onestein.transport/A_TAG_KEY", TRANSPORT_ID)
a_header = kdf(ROOT_KEY, b"org.onestein.transport/A_HEADER_KEY", TRANSPORT_ID)
b_tag = kdf(ROOT_KEY, b"org.onestein.transport/B_TAG_KEY", TRANSPORT_ID)
b_header = kdf(ROOT_KEY, b"org.onestein.transport/B_HEADER_KEY", TRANSPORT_ID)


def rotiere(schluessel: bytes, periode: int) -> bytes:
    return kdf(schluessel, b"org.onestein.transport/ROTATE", periode.to_bytes(8, "big"))


# Von Periode 699 auf 700, dann auf 701.
a_tag_700 = rotiere(a_tag, 700)
a_tag_701 = rotiere(a_tag_700, 701)
tag_700 = prf(
    a_tag_700,
    TRANSPORT_VERSION.to_bytes(2, "big") + STREAM_NUMBER.to_bytes(8, "big"),
)[:16]

print(rust("PRF_OF_KEY_AND_ABC", prf(ROOT_KEY, b"abc")))
print(rust("KDF_OF_KEY_AND_A_BC", kdf(ROOT_KEY, b"a", b"bc")))
print(rust("A_TAG_KEY_INITIAL", a_tag))
print(rust("A_HEADER_KEY_INITIAL", a_header))
print(rust("B_TAG_KEY_INITIAL", b_tag))
print(rust("B_HEADER_KEY_INITIAL", b_header))
print(rust("A_TAG_KEY_PERIOD_700", a_tag_700))
print(rust("A_TAG_KEY_PERIOD_701", a_tag_701))
print(rust("TAG_PERIOD_700_STREAM_7", tag_700))
