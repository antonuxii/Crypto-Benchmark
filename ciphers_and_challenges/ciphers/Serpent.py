#!/usr/bin/env python3
"""
Serpent-128 single-block encryption with custom rounds (1..32), matching libgcrypt.

- Encrypts exactly one 128-bit block (16 bytes).
- Key is 128 bits (16 bytes).
- Uses Serpent's *bitsliced* S-box layer and key schedule.

Based on the official specifications of the cipher: https://www.cl.cam.ac.uk/archive/rja14/Papers/serpent.pdf and https://www.cl.cam.ac.uk/archive/rja14/serpent.html
"""

MASK32 = 0xFFFFFFFF
PHI = 0x9E3779B9

SBOXES = [
    [3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12],
    [15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4],
    [8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2],
    [0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14],
    [1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13],
    [15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1],
    [7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0],
    [1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6],
]


def rotl32(x: int, r: int) -> int:
    x &= MASK32
    return ((x << r) | (x >> (32 - r))) & MASK32


def s_bitslice(box: int, w0: int, w1: int, w2: int, w3: int):
    """
    Bitsliced S-box: for each bit position k, form a 4-bit value from
    (w0_k, w1_k, w2_k, w3_k), substitute, then write bits back.
    """
    s = SBOXES[box & 7]
    y0 = y1 = y2 = y3 = 0
    for k in range(32):
        v = ((w0 >> k) & 1) | (((w1 >> k) & 1) << 1) | (((w2 >> k) & 1) << 2) | (((w3 >> k) & 1) << 3)
        o = s[v]
        y0 |= (o & 1) << k
        y1 |= ((o >> 1) & 1) << k
        y2 |= ((o >> 2) & 1) << k
        y3 |= ((o >> 3) & 1) << k
    return (y0 & MASK32, y1 & MASK32, y2 & MASK32, y3 & MASK32)


def linear_trans(w0: int, w1: int, w2: int, w3: int):
    w0 = rotl32(w0, 13)
    w2 = rotl32(w2, 3)
    w1 = (w1 ^ w0 ^ w2) & MASK32
    w3 = (w3 ^ w2 ^ ((w0 << 3) & MASK32)) & MASK32
    w1 = rotl32(w1, 1)
    w3 = rotl32(w3, 7)
    w0 = (w0 ^ w1 ^ w3) & MASK32
    w2 = (w2 ^ w3 ^ ((w1 << 7) & MASK32)) & MASK32
    w0 = rotl32(w0, 5)
    w2 = rotl32(w2, 22)
    return (w0, w1, w2, w3)


def key_schedule(key16: bytes):
    """
    Returns 33 subkeys, each as 4x32-bit words (sk[r][0..3]).
    For Serpent-128, pad to 256 bits by appending one '1' bit then zeros.
    In this word-oriented bitslice formulation, the usual byte padding is:
      key || 0x01 || 0x00... to 32 bytes
    """
    if len(key16) != 16:
        raise ValueError("Key must be exactly 16 bytes (128 bits).")

    k = key16 + b"\x01" + b"\x00" * (32 - 16 - 1)
    key_words = [int.from_bytes(k[4 * i : 4 * i + 4], "little") for i in range(8)]

    # Prekeys w[0..131]
    x = [0] * 140
    for i in range(8):
        x[i] = key_words[i]

    w = [0] * 132
    for i in range(8, 140):
        x[i] = rotl32(x[i - 8] ^ x[i - 5] ^ x[i - 3] ^ x[i - 1] ^ PHI ^ (i - 8), 11)
        w[i - 8] = x[i]

    # Subkeys sk[0..32], each 4 words, using S-box p = 32 + 3 - i
    sk = []
    for i in range(33):
        p = 32 + 3 - i
        a, b, c, d = w[4 * i + 0], w[4 * i + 1], w[4 * i + 2], w[4 * i + 3]
        sk.append(list(s_bitslice(p % 8, a, b, c, d)))

    return sk


def encrypt_block(pt: bytes, key: bytes, rounds: int) -> bytes:
    if len(pt) != 16:
        raise ValueError("Plaintext must be exactly 16 bytes.")
    if not (1 <= rounds <= 32):
        raise ValueError("rounds must be in 1..32.")

    sk = key_schedule(key)

    # State as 4 little-endian 32-bit words
    w0 = int.from_bytes(pt[0:4], "little")
    w1 = int.from_bytes(pt[4:8], "little")
    w2 = int.from_bytes(pt[8:12], "little")
    w3 = int.from_bytes(pt[12:16], "little")

    # Rounds 0..rounds-1
    for r in range(rounds):
        w0 ^= sk[r][0]; w1 ^= sk[r][1]; w2 ^= sk[r][2]; w3 ^= sk[r][3]
        w0 &= MASK32; w1 &= MASK32; w2 &= MASK32; w3 &= MASK32

        w0, w1, w2, w3 = s_bitslice(r % 8, w0, w1, w2, w3)

        if r == rounds - 1:
            break
        w0, w1, w2, w3 = linear_trans(w0, w1, w2, w3)

    # Final key mixing with subkey[rounds]
    w0 ^= sk[rounds][0]; w1 ^= sk[rounds][1]; w2 ^= sk[rounds][2]; w3 ^= sk[rounds][3]
    w0 &= MASK32; w1 &= MASK32; w2 &= MASK32; w3 &= MASK32

    return (
        w0.to_bytes(4, "little")
        + w1.to_bytes(4, "little")
        + w2.to_bytes(4, "little")
        + w3.to_bytes(4, "little")
    )

# ----------------------------------------------------------
# UTILITIES FOR CHALLENGE GENERATION
# ----------------------------------------------------------

from secrets import token_bytes
import hashlib

BLOCK_BYTES = 128//8
KEY_BYTES = 128//8

def supreme_encryption(key: str, rounds: int, plaintext: str = ""):
    """
    Encrypt with Serpent for `rounds` rounds.

    Inputs:
      - key: 128-bit hex string (32 hex chars).
      - rounds: the number of rounds
      - plaintext: a 128-bit hex string (32 hex chars); if empty, random 128-bit plaintext is used.
    Output: 
        (plaintext_hex, ciphertext_hex) both 32 hex chars
    """
    key_bytes = bytes.fromhex(key)
    if plaintext == "":
        plain_bytes = token_bytes(BLOCK_BYTES)
    elif len(plaintext) != BLOCK_BYTES*2:
        raise ValueError(f"Error: plaintext must be {BLOCK_BYTES*2} hex chars ({BLOCK_BYTES*8} bits).")
    else:
        plain_bytes = bytes.fromhex(plaintext)
    encrypted = encrypt_block(plain_bytes, key_bytes, rounds)
    return plain_bytes.hex(), encrypted.hex()

def safety_check(rounds: int):
    """Computes the encryption of the string 'TEST' with reduced-round cipher of 'rounds' rounds. Right-zero padding"""
    key = bytes.fromhex("0"*KEY_BYTES*2)                                   # zero key
    plain = b"TEST".ljust(BLOCK_BYTES, b"\x00")             # pad to block-size
    return encrypt_block(plain, key, rounds).hex()

def kpa_target(key: str, rounds: int):
    """
    Computes target hash for KPA attack, where:
        target_hash = SHA3-224( b"Public" || SHA3-224(encryption(PT)) )
    where PT is '123456789abcdef0' left-padded to 64-bit.
    """
    pt_bytes = bytes.fromhex("123456789abcdef0").ljust(BLOCK_BYTES, b"\x00") # pad "123456789abcdef0"
    ciphertext = encrypt_block(pt_bytes, bytes.fromhex(key), rounds)
    s = hashlib.sha3_224(ciphertext).digest()
    return hashlib.sha3_224(b"Public" + s).hexdigest()