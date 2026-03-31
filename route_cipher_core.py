"""
route_cipher_core.py
====================
Core library — Route Cipher + Custom Hash + Authentication Pipeline.

DISCLAIMER: Educational implementation only. Not for production use.
No external libraries used (no hashlib, no cryptography module).

Import this file from your test/runner script:
    from route_cipher_core import sender_encrypt, receiver_decrypt
"""

import math


# ============================================================
# SECTION 1: ROUTE CIPHER
# ============================================================
#
# Encryption steps:
#   1. Normalise message (uppercase, remove spaces).
#   2. Compute rows = ceil(len(message) / cols).
#   3. Pad with 'X' to fill rows × cols matrix (row-major).
#   4. Read out columns top-to-bottom → ciphertext.
#
# Decryption steps:
#   1. rows = len(ciphertext) / cols
#   2. Rebuild each column from ciphertext chunks.
#   3. Read row-major → padded plaintext.
#   4. Strip trailing 'X' padding.

def _build_matrix(text: str, cols: int) -> list[list[str]]:
    """Fill a 2D list row-by-row from an already-padded string."""
    rows = len(text) // cols
    return [list(text[r * cols : (r + 1) * cols]) for r in range(rows)]


def encrypt_route_cipher(message: str, cols: int) -> tuple[str, int, int]:
    """
    Encrypt using a columnar Route Cipher.

    Args:
        message : Plaintext string.
        cols    : Number of columns (the shared key).

    Returns:
        (ciphertext, rows, cols)
    """
    message = message.upper().replace(" ", "")
    rows = math.ceil(len(message) / cols)
    padded = message.ljust(rows * cols, "X")          # pad with 'X'
    matrix = _build_matrix(padded, cols)

    # Read column by column
    ct = "".join(matrix[r][c] for c in range(cols) for r in range(rows))
    return ct, rows, cols


def decrypt_route_cipher(ciphertext: str, cols: int) -> str:
    """
    Decrypt a columnar Route Cipher ciphertext.

    Args:
        ciphertext : Encrypted string.
        cols       : Number of columns (the shared key).

    Returns:
        Plaintext with trailing 'X' padding stripped.
    """
    rows = len(ciphertext) // cols
    columns = [list(ciphertext[c * rows : (c + 1) * rows]) for c in range(cols)]
    plaintext = "".join(columns[c][r] for r in range(rows) for c in range(cols))
    return plaintext.rstrip("X")


# ============================================================
# SECTION 2: CUSTOM HASH FUNCTION
# ============================================================
#
# Inspired by the Merkle-Damgård construction.
# Produces a fixed 8-character (32-bit) hex digest.
#
# Per-block compression (4 bytes per block):
#   state ^= block_value          — XOR  (confusion)
#   state  = rotate_left(state,7) — bit rotation (diffusion)
#   state  = (state+block) % 2^32 — modular add (non-linearity)
#   state ^= (block >> 3)         — extra avalanche
#
# Known limitations (educational use only):
#   • 32-bit digest → birthday collisions after ~65k messages.
#   • No salt → vulnerable to rainbow tables.
#   • Not second-preimage resistant under dedicated attack.

_HASH_IV = 0xDEADBEEF
_MOD32   = 0x100000000      # 2^32


def _rotate_left_32(value: int, shift: int) -> int:
    """Circular left rotation of a 32-bit unsigned integer."""
    shift &= 31
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF


def custom_hash(message: str) -> str:
    """
    Compute a custom 32-bit hash of a string.

    Args:
        message : Any string.

    Returns:
        8-character uppercase hex digest.
    """
    data = message.encode("utf-8")

    # Pad to a multiple of 4 bytes
    pad_len = (4 - len(data) % 4) % 4
    data = data + b"\x00" * pad_len

    # Append 4-byte little-endian length tag
    orig_len = len(message.encode("utf-8"))
    data = data + (orig_len & 0xFFFFFFFF).to_bytes(4, "little")

    # Compress each 4-byte block into state
    state = _HASH_IV
    for i in range(0, len(data), 4):
        bv     = int.from_bytes(data[i : i + 4], "big")
        state  = (state ^ bv) & 0xFFFFFFFF
        state  = _rotate_left_32(state, 7)
        state  = (state + bv) % _MOD32
        state  = (state ^ (bv >> 3)) & 0xFFFFFFFF

    # Final mix
    state ^= (state >> 16) & 0xFFFFFFFF
    return format(state, "08X")


# ============================================================
# SECTION 3: AUTHENTICATION + CONFIDENTIALITY PIPELINE
# ============================================================
#
# Sender:   M → H(M) → payload = M ∥ H(M) → Encrypt(payload)
# Receiver: Decrypt → split M and H(M) → recompute H'(M) → compare

HASH_LENGTH = 8     # must match custom_hash output length


def sender_encrypt(message: str, cols: int) -> dict:
    """
    Sender-side pipeline: hash → concatenate → encrypt.

    Args:
        message : Plaintext message to send.
        cols    : Route Cipher key (number of columns).

    Returns:
        dict with keys 'ciphertext', 'rows', 'cols'.
    """
    message = message.upper().replace(" ", "")

    h_m     = custom_hash(message)
    payload = message + h_m

    print(f"  [Sender] Message         : {message}")
    print(f"  [Sender] Hash H(M)       : {h_m}")
    print(f"  [Sender] Payload M||H(M) : {payload}")

    ciphertext, rows, cols_used = encrypt_route_cipher(payload, cols)

    print(f"  [Sender] Ciphertext      : {ciphertext}")
    print(f"  [Sender] Matrix shape    : {rows} rows × {cols_used} cols")

    return {"ciphertext": ciphertext, "rows": rows, "cols": cols_used}


def receiver_decrypt(packet: dict, cols: int) -> dict:
    """
    Receiver-side pipeline: decrypt → split → verify hash.

    Args:
        packet : dict returned by sender_encrypt (or modified for tamper test).
        cols   : Route Cipher key (must match sender's key).

    Returns:
        dict with 'message', 'received_hash', 'computed_hash', 'authenticated'.
    """
    payload = decrypt_route_cipher(packet["ciphertext"], cols)
    print(f"  [Receiver] Decrypted payload : {payload}")

    if len(payload) < HASH_LENGTH:
        print("  [Receiver] ERROR: payload too short to contain a hash.")
        return {"authenticated": False, "reason": "Payload too short"}

    received_hash = payload[-HASH_LENGTH:]
    recovered_msg = payload[:-HASH_LENGTH]
    computed_hash = custom_hash(recovered_msg)

    print(f"  [Receiver] Recovered message : {recovered_msg}")
    print(f"  [Receiver] Received hash     : {received_hash}")
    print(f"  [Receiver] Computed hash     : {computed_hash}")

    authenticated = (received_hash == computed_hash)
    status = "AUTHENTIC — message is unmodified" if authenticated \
             else "TAMPERED  — hash mismatch, message rejected"
    print(f"  [Receiver] Auth result       : {'✓' if authenticated else '✗'} {status}")

    return {
        "message"       : recovered_msg,
        "received_hash" : received_hash,
        "computed_hash" : computed_hash,
        "authenticated" : authenticated,
    }
