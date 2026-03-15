"""
This script is just a python wrapper for encryption with SPEEDY, by calling the SPEEDY.c custom round implementation.
SPEEDY.c is the official code published for the SPEEDY family of ciphers, and can be found at https://github.com/Chair-for-Security-Engineering/SPEEDY/tree/main 
"""

import ctypes
from ctypes import POINTER, c_ubyte, c_int, c_void_p
from secrets import token_bytes
import hashlib
import os

BLOCK_BYTES = 192 // 8
KEY_BYTES = 192 // 8

# Get the directory where this script (SPEEDY.py) is located
_here = os.path.dirname(os.path.abspath(__file__))
# Construct the full path to the shared object
_so_path = os.path.join(_here, "SPEEDY.so")

lib = ctypes.CDLL(_so_path)

lib.Encrypt.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte), POINTER(c_ubyte), c_int]
lib.Encrypt.restype = None

def encrypt_block(key: bytes, plaintext: bytes, rounds: int) -> bytes:
    """
    Encrypt a single block using the SPEEDY cipher.
    
    Inputs:
      - key: 24 bytes (192 bits)
      - plaintext: 24 bytes (192 bits)
      - rounds: 1..9
    Output:
      - ciphertext: 24 bytes (192 bits)
    """
    # Ensure inputs are correct length
    if len(key) != KEY_BYTES:
        raise ValueError(f"Key must be {KEY_BYTES} bytes, got {len(key)}")
    if len(plaintext) != BLOCK_BYTES:
        raise ValueError(f"Plaintext must be {BLOCK_BYTES} bytes, got {len(plaintext)}")
    if not (1 <= rounds <= 9):
        raise ValueError(f"Rounds must be between 1 and 9, got {rounds}")
    
    # Create ciphertext buffer
    ciphertext = (c_ubyte * BLOCK_BYTES)()
    
    # Call C function
    lib.Encrypt(
        ctypes.cast(plaintext, POINTER(c_ubyte)),
        ctypes.cast(key, POINTER(c_ubyte)),
        ciphertext,
        rounds
    )
    
    # Convert result to bytes
    return bytes(ciphertext)

def supreme_encryption(key: str, rounds: int, plaintext: str = ""):
    """
    Encrypt with SPEEDY for `rounds` rounds.

    Inputs:
      - key: 192-bit hex string (48 hex chars).
      - rounds: the number of rounds
      - plaintext: a 192-bit hex string (48 hex chars); if empty, random 192-bit plaintext is used.
    Output: 
        (plaintext_hex, ciphertext_hex) both 48 hex chars
    """
    key_bytes = bytes.fromhex(key)

    if plaintext == "":
        pt_bytes = token_bytes(BLOCK_BYTES)
    elif len(plaintext) != BLOCK_BYTES*2:
        raise ValueError(f"Error: plaintext must be {BLOCK_BYTES*2} hex chars ({BLOCK_BYTES*8} bits).")
    else:
        pt_bytes = bytes.fromhex(plaintext)
    ct_bytes = encrypt_block(key_bytes, pt_bytes, rounds)
    return pt_bytes.hex(), ct_bytes.hex()

def safety_check(rounds: int):
    """Computes the encryption of the string 'TEST' with reduced-round cipher of 'rounds' rounds. Right-zero padding"""
    key = bytes.fromhex("0"*KEY_BYTES*2)                # zero key
    plain = b"TEST".ljust(BLOCK_BYTES, b"\x00")      # pad
    ct_bytes = encrypt_block(key, plain, rounds)
    return ct_bytes.hex()

def kpa_target(key: str, rounds: int):
    """
    Computes target hash for KPA attack, where:
        target_hash = SHA3-224( b"Public" || SHA3-224(encryption(PT)) )
    where PT is '123456789abcdef0' left-padded to 192-bit.
    """
    key_bytes = bytes.fromhex(key)
    pt_bytes = bytes.fromhex("123456789abcdef0").ljust(BLOCK_BYTES, b"\x00") # pad "123456789abcdef0"
    ct_bytes = encrypt_block(key_bytes, pt_bytes, rounds)
    s = hashlib.sha3_224(ct_bytes).digest()
    return hashlib.sha3_224(b"Public" + s).hexdigest()