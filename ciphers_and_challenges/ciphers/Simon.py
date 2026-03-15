""" 
Simon block cipher implementation taken from https://github.com/inmcm/Simon_Speck_Ciphers/tree/master/Python/simonspeckciphers/simon, full credit goes to the author inmcm
The original script was only modified in order to support Simon encryption with a custom number of rounds, and 
it was simplified to encrypt with 64-bit key, 32-bit blocks, and always in ECB mode with hex string inputs/outputs.
"""

from __future__ import print_function
from collections import deque

__author__ = 'inmcm'

class SimonCipher(object):
    """Simon Block Cipher Object - Simplified for 32-bit blocks and 64-bit keys"""

    # Z0 sequence (stored bit reversed for easier usage)
    z0 = 0b01100111000011010100100010111110110011100001101010010001011111

    def __init__(self, key_hex, rounds=32):
        """
        Initialize an instance of the Simon block cipher.
        :param key_hex: Str representing the hex encoding of the key (16 hex chars for 64 bits)
        :param rounds: Int representing the number of rounds used for encryption (max 32)
        :return: None
        """

        # Fixed configuration: 32-bit blocks, 64-bit keys
        self.block_size = 32
        self.word_size = 16
        self.key_size = 64
        self.zseq = self.z0
        self.rounds = rounds

        # Create Properly Sized bit mask for truncating addition and left shift outputs
        self.mod_mask = 0xFFFF  # (2^16 - 1)

        # Parse the given key and validate length
        if len(key_hex) != 16:  # 64 bits = 16 hex chars
            print("Invalid key. Must be 16 hex characters (64 bits)")
            raise ValueError("Key must be 16 hex characters")
        
        try:
            self.key = int(key_hex, 16)
        except ValueError:
            print("Invalid key format. Must be hexadecimal string")
            raise

        # Pre-compile key schedule
        # For 64-bit key and 16-bit word size: m = 4
        m = 4
        self.key_schedule = []

        # Create list of subwords from encryption key
        k_init = [((self.key >> (16 * (3 - x))) & self.mod_mask) for x in range(4)]

        k_reg = deque(k_init)  # Use queue to manage key subwords

        round_constant = 0xFFFC  # (2^16 - 1) ^ 3

        # Generate all round keys
        for x in range(self.rounds):

            rs_3 = ((k_reg[0] << 13) + (k_reg[0] >> 3)) & self.mod_mask

            # m == 4, so apply the additional XOR
            rs_3 = rs_3 ^ k_reg[2]

            rs_1 = ((rs_3 << 15) + (rs_3 >> 1)) & self.mod_mask

            c_z = ((self.zseq >> (x % 62)) & 1) ^ round_constant

            new_k = c_z ^ rs_1 ^ rs_3 ^ k_reg[3]

            self.key_schedule.append(k_reg.pop())
            k_reg.appendleft(new_k)

    def encrypt_round(self, x, y, k):
        """
        Complete One Feistel Round
        :param x: Upper 16 bits of current plaintext
        :param y: Lower 16 bits of current plaintext
        :param k: Round Key
        :return: Upper and Lower ciphertext segments
        """

        # Generate all circular shifts
        ls_1_x = ((x >> 15) + (x << 1)) & self.mod_mask
        ls_8_x = ((x >> 8) + (x << 8)) & self.mod_mask
        ls_2_x = ((x >> 14) + (x << 2)) & self.mod_mask

        # XOR Chain
        xor_1 = (ls_1_x & ls_8_x) ^ y
        xor_2 = xor_1 ^ ls_2_x
        new_x = k ^ xor_2

        return new_x, x

    def decrypt_round(self, x, y, k):
        """Complete One Inverse Feistel Round
        :param x: Upper 16 bits of current ciphertext
        :param y: Lower 16 bits of current ciphertext
        :param k: Round Key
        :return: Upper and Lower plaintext segments
        """

        # Generate all circular shifts
        ls_1_y = ((y >> 15) + (y << 1)) & self.mod_mask
        ls_8_y = ((y >> 8) + (y << 8)) & self.mod_mask
        ls_2_y = ((y >> 14) + (y << 2)) & self.mod_mask

        # Inverse XOR Chain
        xor_1 = k ^ x
        xor_2 = xor_1 ^ ls_2_y
        new_x = (ls_1_y & ls_8_y) ^ xor_2

        return y, new_x

    def encrypt(self, plaintext_hex):
        """
        Process new plaintext into ciphertext based on current cipher object setup
        :param plaintext_hex: Hex string representing value to encrypt (8 hex chars for 32 bits)
        :return: Hex string representing encrypted value (8 hex chars)
        """
        try:
            # Convert hex string to integer
            plaintext = int(plaintext_hex, 16)
            b = (plaintext >> 16) & self.mod_mask
            a = plaintext & self.mod_mask
        except (ValueError, TypeError):
            print('Invalid plaintext!')
            print('Please provide plaintext as hex string')
            raise

        b, a = self.encrypt_function(b, a)

        ciphertext = (b << 16) + a

        # Convert integer to hex string (8 hex chars for 32 bits)
        return format(ciphertext, '08x')

    def decrypt(self, ciphertext_hex):
        """
        Process new ciphertext into plaintext based on current cipher object setup
        :param ciphertext_hex: Hex string representing value to decrypt (8 hex chars for 32 bits)
        :return: Hex string representing decrypted value (8 hex chars)
        """
        try:
            # Convert hex string to integer
            ciphertext = int(ciphertext_hex, 16)
            b = (ciphertext >> 16) & self.mod_mask
            a = ciphertext & self.mod_mask
        except (ValueError, TypeError):
            print('Invalid ciphertext!')
            print('Please provide ciphertext as hex string')
            raise

        a, b = self.decrypt_function(a, b)

        plaintext = (b << 16) + a

        # Convert integer to hex string (8 hex chars for 32 bits)
        return format(plaintext, '08x')


    def encrypt_function(self, upper_word, lower_word):
        """
        Completes appropriate number of Simon Feistel function to encrypt provided words
        Round number is based off of number of elements in key schedule
        upper_word: int of upper 16 bits of plaintext input
        lower_word: int of lower 16 bits of plaintext input
        x,y:        int of Upper and Lower ciphertext words            
        """    
        x = upper_word
        y = lower_word 

        # Run Encryption Steps For Appropriate Number of Rounds
        for k in self.key_schedule:
             # Generate all circular shifts
            ls_1_x = ((x >> 15) + (x << 1)) & self.mod_mask
            ls_8_x = ((x >> 8) + (x << 8)) & self.mod_mask
            ls_2_x = ((x >> 14) + (x << 2)) & self.mod_mask

            # XOR Chain
            xor_1 = (ls_1_x & ls_8_x) ^ y
            xor_2 = xor_1 ^ ls_2_x
            y = x
            x = k ^ xor_2
            
        return x,y    

    def decrypt_function(self, upper_word, lower_word):    
        """
        Completes appropriate number of Simon Feistel function to decrypt provided words
        Round number is based off of number of elements in key schedule
        upper_word: int of upper 16 bits of ciphertext input
        lower_word: int of lower 16 bits of ciphertext input
        x,y:        int of Upper and Lower plaintext words            
        """
        x = upper_word
        y = lower_word

        # Run Encryption Steps For Appropriate Number of Rounds
        for k in reversed(self.key_schedule): 
             # Generate all circular shifts
            ls_1_x = ((x >> 15) + (x << 1)) & self.mod_mask
            ls_8_x = ((x >> 8) + (x << 8)) & self.mod_mask
            ls_2_x = ((x >> 14) + (x << 2)) & self.mod_mask

            # XOR Chain
            xor_1 = (ls_1_x & ls_8_x) ^ y
            xor_2 = xor_1 ^ ls_2_x
            y = x
            x = k ^ xor_2
            
        return x,y    

# ----------------------------------------------------------
# UTILITIES FOR CHALLENGE GENERATION
# ----------------------------------------------------------

from secrets import token_bytes
import hashlib

BLOCK_BYTES = 32 // 8  # 4 bytes for 32-bit blocks
KEY_BYTES = 64 // 8    # 8 bytes for 64-bit keys

def supreme_encryption(key: str, rounds: int, plaintext: str = ""):
    """
    Encrypt with Simon for `rounds` rounds.

    Inputs:
      - key: 64-bit hex string (16 hex chars).
      - rounds: the number of rounds, up to 32
      - plaintext: a 32-bit hex string (8 hex chars); if empty, random 32-bit plaintext is used.
    Output: 
        (plaintext_hex, ciphertext_hex) both 8 hex chars
    """

    cipher = SimonCipher(key, rounds)
    if plaintext == "":  # sample uniformly
        plaintext = token_bytes(BLOCK_BYTES).hex()
    elif len(plaintext) != BLOCK_BYTES*2:
        raise ValueError(f"Error: plaintext must be {BLOCK_BYTES*2} hex chars ({BLOCK_BYTES*8} bits).")
    encrypted = cipher.encrypt(plaintext)
    return plaintext, encrypted

def safety_check(rounds: int):
    """Computes the encryption of the string 'TEST' with reduced-round cipher of 'rounds' rounds. Right-zero padding"""
    key = "0"*KEY_BYTES*2  # zero key (16 hex chars)
    plain = b"TEST".ljust(BLOCK_BYTES, b"\x00")  # pad to 4 bytes
    cipher = SimonCipher(key, rounds)
    return cipher.encrypt(plain.hex())

def kpa_target(key: str, rounds: int):
    """
    Computes target hash for KPA attack, where:
        target_hash = SHA3-224( b"Public" || SHA3-224(encryption(PT)) )
    where PT is '12345678' right-padded to 32-bit.
    """
    cipher = SimonCipher(key, rounds)
    pt_bytes = b"12345678".ljust(BLOCK_BYTES, b"\x00")  # pad "12345678" to 4 bytes
    ciphertext = cipher.encrypt(pt_bytes.hex())
    s = hashlib.sha3_224(bytes.fromhex(ciphertext)).digest()
    return hashlib.sha3_224(b"Public" + s).hexdigest()