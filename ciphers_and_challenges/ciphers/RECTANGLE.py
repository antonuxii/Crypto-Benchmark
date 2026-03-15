#!/usr/bin/env python3
"""
RECTANGLE-80 (round-reduced) implementation, with big endian
- Block size: 64 bits (8 bytes)
- Key size:   80 bits (10 bytes), represented internally as 5x uint16 words
- Rounds:     user-chosen (default 25)

Based on the official documentation for the cipher: https://eprint.iacr.org/2014/084.pdf
and on this JavaScript implementation: https://github.com/m-walid/Rectangle-lightweight-block-cipher/blob/main/rectangle.js
Note: the linked javascript implementation is not correct, but it served to get a sense of the implementation
"""

from __future__ import annotations
from typing import List

MASK16 = 0xFFFF

SBOX = [0x06, 0x05, 0x0C, 0x0A, 0x01, 0x0E, 0x07, 0x09,
        0x0B, 0x00, 0x03, 0x0D, 0x08, 0x0F, 0x04, 0x02]

INV_SBOX = [0x09, 0x04, 0x0F, 0x0A, 0x0E, 0x01, 0x00, 0x06,
            0x0C, 0x07, 0x03, 0x08, 0x02, 0x0B, 0x05, 0x0D]

# 5-bit round constants RC[0..24] for RECTANGLE (full = 25 rounds)
RC = [
    0x01, 0x02, 0x04, 0x09, 0x12, 0x05, 0x0B, 0x16, 0x0C, 0x19,
    0x13, 0x07, 0x0F, 0x1F, 0x1E, 0x1C, 0x18, 0x11, 0x03, 0x06,
    0x0D, 0x1B, 0x17, 0x0E, 0x1D,
]


def rotl16(x: int, r: int) -> int:
    """Rotate a 16-bit integer left by r."""
    r &= 15
    x &= MASK16
    return ((x << r) | (x >> (16 - r))) & MASK16


def bytes_to_u16_words(block8: bytes) -> List[int]:
    """8 bytes -> 4 big-endian uint16 words."""
    if len(block8) != 8:
        raise ValueError("block must be exactly 8 bytes (64 bits)")
    return [int.from_bytes(block8[i:i + 2], "big") for i in range(0, 8, 2)]


def u16_words_to_bytes(words4: List[int]) -> bytes:
    """4 uint16 words -> 8 bytes (big-endian)."""
    if len(words4) != 4:
        raise ValueError("need exactly 4 words")
    return b"".join((w & MASK16).to_bytes(2, "big") for w in words4)


def parse_key_80_hex(key_hex: str) -> List[int]:
    """
    Parse an 80-bit key given as 20 hex chars (10 bytes) into 5 big-endian uint16 words.
    Example: "00010203040506070809" -> [0x0001, 0x0203, 0x0405, 0x0607, 0x0809]
    """
    key_hex = key_hex.strip().lower()
    if key_hex.startswith("0x"):
        key_hex = key_hex[2:]
    if len(key_hex) != 20:
        raise ValueError("RECTANGLE-80 key must be 80 bits = 20 hex characters (10 bytes)")
    key_bytes = bytes.fromhex(key_hex)
    return [int.from_bytes(key_bytes[i:i + 2], "big") for i in range(0, 10, 2)]


# ----------------------------
# Round transformations
# ----------------------------

def subcolumn_inplace(state_words: List[int], cols: int = 16) -> None:
    """
    Bit-sliced SubColumn:
      For each column bit position i, form a 4-bit value from state_words[0..3] bit i (LSB-first),
      apply SBOX, and write bits back.
    """
    for i in range(cols):
        col = ((state_words[0] >> i) & 1) \
            | (((state_words[1] >> i) & 1) << 1) \
            | (((state_words[2] >> i) & 1) << 2) \
            | (((state_words[3] >> i) & 1) << 3)

        new_col = SBOX[col]

        for row in range(4):
            bit = (new_col >> row) & 1
            if bit:
                state_words[row] |= (1 << i)
            else:
                state_words[row] &= ~(1 << i)

    for row in range(4):
        state_words[row] &= MASK16


def inv_subcolumn_inplace(state_words: List[int], cols: int = 16) -> None:
    """Inverse of SubColumn (uses INV_SBOX)."""
    for i in range(cols):
        col = ((state_words[0] >> i) & 1) \
            | (((state_words[1] >> i) & 1) << 1) \
            | (((state_words[2] >> i) & 1) << 2) \
            | (((state_words[3] >> i) & 1) << 3)

        new_col = INV_SBOX[col]

        for row in range(4):
            bit = (new_col >> row) & 1
            if bit:
                state_words[row] |= (1 << i)
            else:
                state_words[row] &= ~(1 << i)

    for row in range(4):
        state_words[row] &= MASK16


def shiftrow_inplace(state_words4: List[int]) -> None:
    """ShiftRow: row1<<<1, row2<<<12, row3<<<13 (row0 unchanged)."""
    state_words4[1] = rotl16(state_words4[1], 1)
    state_words4[2] = rotl16(state_words4[2], 12)
    state_words4[3] = rotl16(state_words4[3], 13)


def inv_shiftrow_inplace(state_words4: List[int]) -> None:
    """Inverse ShiftRow: rotate right by (1,12,13) == rotate left by (15,4,3)."""
    state_words4[1] = rotl16(state_words4[1], 15)
    state_words4[2] = rotl16(state_words4[2], 4)
    state_words4[3] = rotl16(state_words4[3], 3)


def add_round_key_inplace(state_words4: List[int], round_key4: List[int]) -> None:
    """XOR 4-word round key into 4-word state."""
    for i in range(4):
        state_words4[i] = (state_words4[i] ^ (round_key4[i] & MASK16)) & MASK16


# ------------------------------
# Key schedule (RECTANGLE-80)
# ------------------------------

def _key_sbox_on_4cols_inplace(key_words5: List[int]) -> None:
    """
    Key schedule S-box application on the 4 rightmost columns (bit positions 0..3)
    of the top 4 rows (words 0..3).
    """
    top4 = key_words5[:4]
    subcolumn_inplace(top4, cols=4)
    key_words5[:4] = top4


def _key_update_inplace(key_words5: List[int], round_idx: int) -> None:
    """
    Update the 5×16-bit key register in place (RECTANGLE-80).

      1) Apply S-box to 4 columns (bits 0..3) of rows 0..3.
      2) Generalized Feistel word update:
         row0' = (row0<<<8) XOR row1
         row1' = row2
         row2' = row3
         row3' = (row3<<<12) XOR row4
         row4' = row0
      3) XOR RC[round_idx] into the low 5 bits of row0.
    """
    if not (0 <= round_idx < len(RC)):
        raise ValueError(f"round_idx out of range for RC table: {round_idx}")

    _key_sbox_on_4cols_inplace(key_words5)

    old_row0 = key_words5[0] & MASK16
    key_words5[0] = (rotl16(key_words5[0], 8) ^ key_words5[1]) & MASK16
    key_words5[1] = key_words5[2] & MASK16
    key_words5[2] = key_words5[3] & MASK16
    key_words5[3] = (rotl16(key_words5[3], 12) ^ key_words5[4]) & MASK16
    key_words5[4] = old_row0

    key_words5[0] ^= (RC[round_idx] & 0x1F)
    key_words5[0] &= MASK16


def expand_round_keys(key_words5: List[int], rounds: int) -> List[List[int]]:
    """
    Expand to subkeys: [K0, K1, ..., K_{rounds}] where each Ki is 4×16-bit.
    Encryption uses:
      for r=0..rounds-1: AddRoundKey(Kr), SubColumn, ShiftRow
      final: AddRoundKey(K_rounds)
    """
    if rounds < 1:
        raise ValueError("rounds must be >= 1")
    if rounds > len(RC):
        raise ValueError(f"rounds too large for RC table ({len(RC)} max for RECTANGLE-80)")

    k = [w & MASK16 for w in key_words5]
    if len(k) != 5:
        raise ValueError("RECTANGLE-80 key register must have 5 words")

    keys: List[List[int]] = []
    keys.append(k[:4].copy())  # K0

    for r in range(rounds):
        _key_update_inplace(k, r)   # produces next key state
        keys.append(k[:4].copy())   # K_{r+1}

    return keys


# -------------------------
# Encryption / decryption
# -------------------------

def encrypt_block(block8: bytes, key_hex: str, rounds: int = 25) -> bytes:
    """Encrypt one 8-byte block (ECB single-block) with RECTANGLE-80 (reduced rounds allowed)."""
    state = bytes_to_u16_words(block8)
    key_words5 = parse_key_80_hex(key_hex)
    rks = expand_round_keys(key_words5, rounds)  # length rounds+1

    for r in range(rounds):
        add_round_key_inplace(state, rks[r])
        subcolumn_inplace(state, cols=16)
        shiftrow_inplace(state)

    add_round_key_inplace(state, rks[rounds])
    return u16_words_to_bytes(state)


def decrypt_block(block8: bytes, key_hex: str, rounds: int = 25) -> bytes:
    """Decrypt one 8-byte block (ECB single-block) with RECTANGLE-80 (reduced rounds allowed)."""
    state = bytes_to_u16_words(block8)
    key_words5 = parse_key_80_hex(key_hex)
    rks = expand_round_keys(key_words5, rounds)

    # undo final key
    add_round_key_inplace(state, rks[rounds])

    for r in range(rounds - 1, -1, -1):
        inv_shiftrow_inplace(state)
        inv_subcolumn_inplace(state, cols=16)
        add_round_key_inplace(state, rks[r])

    return u16_words_to_bytes(state)

# -------------------------
# Correctenss Check
# -------------------------

def test_vectors():
    """Tests against the test vectors provided in the offical RECTANGLE paper (Table 10). """
    # TEST 1
    s = "0" * 16
    k = "0" * 20
    encrypted = int(supreme_encryption(k, 25, s)[1], 16)
    expected = int("0010110110010110111000110101010011101000101100010000100001110100", 2)
    if encrypted == expected:
        print("Test 1 Succesful")
    else:
        print("Test 1 Failed :(")
        return
    
    # TEST 2
    s = "f" * 16
    k = "f" * 20
    encrypted = int(supreme_encryption(k, 25, s)[1], 16)
    expected = int("1001100101000101101010100011010010101110001111010000000100010010", 2)
    if encrypted == expected:
        print("Test 2 Succesful")
    else:
        print("Test 2 Failed :(")
        return

# ----------------------------------------------------------
# UTILITIES FOR CHALLENGE GENERATION
# ----------------------------------------------------------

from secrets import token_bytes
import hashlib

BLOCK_BYTES = 64//8
KEY_BYTES = 80//8

def supreme_encryption(key: str, rounds: int, plaintext: str = ""):
    """
    Encrypt with RECTANGLE for `rounds` rounds.

    Inputs:
      - key: 80-bit hex string (20 hex chars).
      - rounds: the number of rounds
      - plaintext: a 64-bit hex string (16 hex chars); if empty, random 64-bit plaintext is used.
    Output: 
        (plaintext_hex, ciphertext_hex) both 16 hex chars
    """
    if plaintext == "":
        plain_bytes = token_bytes(BLOCK_BYTES)
    elif len(plaintext) != BLOCK_BYTES*2:
        raise ValueError(f"Error: plaintext must be {BLOCK_BYTES*2} hex chars ({BLOCK_BYTES*8} bits).")
    else:
        plain_bytes = bytes.fromhex(plaintext)
    encrypted = encrypt_block(plain_bytes, key, rounds)
    return plain_bytes.hex(), encrypted.hex()

def safety_check(rounds: int):
    """Computes the encryption of the string 'TEST' with reduced-round cipher of 'rounds' rounds. Right-zero padding"""
    key = "0"*KEY_BYTES*2                                   # zero key
    plain = b"TEST".ljust(BLOCK_BYTES, b"\x00")             # pad to block-size
    return encrypt_block(plain, key, rounds).hex()

def kpa_target(key: str, rounds: int):
    """
    Computes target hash for KPA attack, where:
        target_hash = SHA3-224( b"Public" || SHA3-224(encryption(PT)) )
    where PT is '123456789abcdef0' left-padded to 64-bit.
    """
    pt_bytes = bytes.fromhex("123456789abcdef0").ljust(BLOCK_BYTES, b"\x00") # pad "123456789abcdef0"
    ciphertext = encrypt_block(pt_bytes, key, rounds)
    s = hashlib.sha3_224(ciphertext).digest()
    return hashlib.sha3_224(b"Public" + s).hexdigest()