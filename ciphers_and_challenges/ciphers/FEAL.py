"""
This script is just a python wrapper for encryption with FEAL, by calling the FEAL.c custom round implementation.
The FEAL.c we reference can be found at https://gist.github.com/odzhan/f0cb8657060199b93540f710f4883485
"""

import ctypes
from ctypes import POINTER, c_ubyte, c_int, c_void_p, c_uint64, c_uint16
from secrets import token_bytes
import hashlib
import os

BLOCK_BYTES = 8
KEY_BYTES = 8

# Get the directory where this script (FEAL.py) is located
_here = os.path.dirname(os.path.abspath(__file__))
# Construct the full path to the shared object
_so_path = os.path.join(_here, "FEAL.so")

lib = ctypes.CDLL(_so_path)

# void key_schedule(uint64_t K, uint16_t *Ki, int N)
lib.key_schedule.argtypes = [c_uint64, POINTER(c_uint16), c_int]
lib.key_schedule.restype = None

# uint64_t encrypt(uint64_t M, uint16_t *Ki, int N)
lib.encrypt.argtypes = [c_uint64, POINTER(c_uint16), c_int]
lib.encrypt.restype = c_uint64

# uint64_t decrypt(uint64_t C, uint16_t *Ki, int N)
lib.decrypt.argtypes = [c_uint64, POINTER(c_uint16), c_int]
lib.decrypt.restype = c_uint64

def encrypt_block(key: bytes, plaintext: bytes, rounds: int) -> bytes:
    """
    Encrypt a single block using the FEAL cipher.
    
    Inputs:
      - key: 8 bytes (64 bits)
      - plaintext: 8 bytes (64 bits)
      - rounds: must be even, 2..32
    Output:
      - ciphertext: 8 bytes (64 bits)
    """
    # Ensure inputs are correct length
    if len(key) != KEY_BYTES:
        raise ValueError(f"Key must be {KEY_BYTES} bytes, got {len(key)}")
    if len(plaintext) != BLOCK_BYTES:
        raise ValueError(f"Plaintext must be {BLOCK_BYTES} bytes, got {len(plaintext)}")
    if not (2 <= rounds <= 32) or rounds % 2 != 0:
        raise ValueError(f"Rounds must be even and between 2 and 32, got {rounds}")
    
    # Convert bytes to uint64_t (big-endian)
    key_int = int.from_bytes(key, byteorder='big')
    plaintext_int = int.from_bytes(plaintext, byteorder='big')
    
    # Allocate subkey array (N + 8 subkeys)
    total_subkeys = rounds + 8
    Ki = (c_uint16 * total_subkeys)()
    
    # Generate subkeys
    lib.key_schedule(key_int, Ki, rounds)
    
    # Encrypt
    ciphertext_int = lib.encrypt(plaintext_int, Ki, rounds)
    
    # Convert uint64_t back to bytes (big-endian)
    return ciphertext_int.to_bytes(BLOCK_BYTES, byteorder='big')

def decrypt_block(key: bytes, ciphertext: bytes, rounds: int) -> bytes:
    """
    Decrypt a single block using the FEAL cipher.
    
    Inputs:
      - key: 8 bytes (64 bits)
      - ciphertext: 8 bytes (64 bits)
      - rounds: must be even, 2..32
    Output:
      - plaintext: 8 bytes (64 bits)
    """
    # Ensure inputs are correct length
    if len(key) != KEY_BYTES:
        raise ValueError(f"Key must be {KEY_BYTES} bytes, got {len(key)}")
    if len(ciphertext) != BLOCK_BYTES:
        raise ValueError(f"Ciphertext must be {BLOCK_BYTES} bytes, got {len(ciphertext)}")
    if not (2 <= rounds <= 32) or rounds % 2 != 0:
        raise ValueError(f"Rounds must be even and between 2 and 32, got {rounds}")
    
    # Convert bytes to uint64_t (big-endian)
    key_int = int.from_bytes(key, byteorder='big')
    ciphertext_int = int.from_bytes(ciphertext, byteorder='big')
    
    # Allocate subkey array (N + 8 subkeys)
    total_subkeys = rounds + 8
    Ki = (c_uint16 * total_subkeys)()
    
    # Generate subkeys
    lib.key_schedule(key_int, Ki, rounds)
    
    # Decrypt
    plaintext_int = lib.decrypt(ciphertext_int, Ki, rounds)
    
    # Convert uint64_t back to bytes (big-endian)
    return plaintext_int.to_bytes(BLOCK_BYTES, byteorder='big')

def supreme_encryption(key: str, rounds: int, plaintext: str = ""):
    """
    Encrypt with FEAL for `rounds` rounds.

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
    plain = b"TEST".ljust(BLOCK_BYTES, b"\x00")         # pad
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