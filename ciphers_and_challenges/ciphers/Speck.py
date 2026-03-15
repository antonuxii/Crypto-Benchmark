""" 
Speck block cipher implementation taken from https://github.com/inmcm/Simon_Speck_Ciphers/tree/master/Python/simonspeckciphers/speck, full credit goes to the author inmcm
The original script was only modified in order to support Speck encryption with a custom number of rounds, and 
it was simplified to encrypt with 64-bit key, 32-bit blocks, and always in ECB mode with hex string inputs/outputs.
"""

from __future__ import print_function

class SpeckCipher(object):
    """Speck Block Cipher Object - Simplified for 32-bit blocks and 64-bit keys"""

    def __init__(self, key_hex, rounds=22):
        """
        Initialize an instance of the Speck block cipher.
        :param key_hex: Str representing the hex encoding of the key (16 hex chars for 64 bits)
        :param rounds: Int representing the number of rounds used for encryption (default 22)
        :return: None
        """

        # Fixed configuration: 32-bit blocks, 64-bit keys
        self.block_size = 32
        self.word_size = 16
        self.key_size = 64
        self.rounds = rounds

        # Create Properly Sized bit mask for truncating addition and left shift outputs
        self.mod_mask = 0xFFFF  # (2^16 - 1)

        # Mod mask for modular subtraction
        self.mod_mask_sub = 0x10000  # 2^16

        # Circular Shift Parameters for 32-bit blocks
        self.beta_shift = 2
        self.alpha_shift = 7

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
        self.key_schedule = [self.key & self.mod_mask]
        l_schedule = [(self.key >> (x * 16)) & self.mod_mask for x in range(1, 4)]

        for x in range(self.rounds - 1):
            new_l_k = self.encrypt_round(l_schedule[x], self.key_schedule[x], x)
            l_schedule.append(new_l_k[0])
            self.key_schedule.append(new_l_k[1])


    def encrypt_round(self, x, y, k):
        """Complete One Round of Feistel Operation"""
        rs_x = ((x << 9) + (x >> 7)) & self.mod_mask  # alpha_shift = 7

        add_sxy = (rs_x + y) & self.mod_mask

        new_x = k ^ add_sxy

        ls_y = ((y >> 14) + (y << 2)) & self.mod_mask  # beta_shift = 2

        new_y = new_x ^ ls_y

        return new_x, new_y

    def decrypt_round(self, x, y, k):
        """Complete One Round of Inverse Feistel Operation"""

        xor_xy = x ^ y

        new_y = ((xor_xy << 14) + (xor_xy >> 2)) & self.mod_mask  # beta_shift = 2

        xor_xk = x ^ k

        msub = ((xor_xk - new_y) + self.mod_mask_sub) % self.mod_mask_sub

        new_x = ((msub >> 9) + (msub << 7)) & self.mod_mask  # alpha_shift = 7

        return new_x, new_y

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

        b, a = self.decrypt_function(b, a)

        plaintext = (b << 16) + a

        # Convert integer to hex string (8 hex chars for 32 bits)
        return format(plaintext, '08x')

    def encrypt_function(self, upper_word, lower_word):
        """
        Completes appropriate number of Speck Feistel function to encrypt provided words
        Round number is based off of number of elements in key schedule
        upper_word: int of upper 16 bits of plaintext input
        lower_word: int of lower 16 bits of plaintext input
        x,y:        int of Upper and Lower ciphertext words
        """
        x = upper_word
        y = lower_word 

        # Run Encryption Steps For Appropriate Number of Rounds
        for k in self.key_schedule:
            rs_x = ((x << 9) + (x >> 7)) & self.mod_mask

            add_sxy = (rs_x + y) & self.mod_mask

            x = k ^ add_sxy

            ls_y = ((y >> 14) + (y << 2)) & self.mod_mask

            y = x ^ ls_y
            
        return x, y    

    def decrypt_function(self, upper_word, lower_word):
        """
        Completes appropriate number of Speck Feistel function to decrypt provided words
        Round number is based off of number of elements in key schedule
        upper_word: int of upper 16 bits of ciphertext input
        lower_word: int of lower 16 bits of ciphertext input
        x,y:        int of Upper and Lower plaintext words
        """
        x = upper_word
        y = lower_word

        # Run Encryption Steps For Appropriate Number of Rounds
        for k in reversed(self.key_schedule): 
            xor_xy = x ^ y

            y = ((xor_xy << 14) + (xor_xy >> 2)) & self.mod_mask

            xor_xk = x ^ k

            msub = ((xor_xk - y) + self.mod_mask_sub) % self.mod_mask_sub

            x = ((msub >> 9) + (msub << 7)) & self.mod_mask

        return x, y


# ----------------------------------------------------------
# UTILITIES FOR CHALLENGE GENERATION
# ----------------------------------------------------------

from secrets import token_bytes
import hashlib

BLOCK_BYTES = 32 // 8  # 4 bytes for 32-bit blocks
KEY_BYTES = 64 // 8    # 8 bytes for 64-bit keys

def supreme_encryption(key: str, rounds: int, plaintext: str = ""):
    """
    Encrypt with Speck for `rounds` rounds.

    Inputs:
      - key: 64-bit hex string (16 hex chars).
      - rounds: the number of rounds, up to 22
      - plaintext: a 32-bit hex string (8 hex chars); if empty, random 32-bit plaintext is used.
    Output: 
        (plaintext_hex, ciphertext_hex) both 8 hex chars
    """

    cipher = SpeckCipher(key, rounds)
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
    cipher = SpeckCipher(key, rounds)
    return cipher.encrypt(plain.hex())

def kpa_target(key: str, rounds: int):
    """
    Computes target hash for KPA attack, where:
        target_hash = SHA3-224( b"Public" || SHA3-224(encryption(PT)) )
    where PT is '12345678' right-padded to 32-bit.
    """
    cipher = SpeckCipher(key, rounds)
    pt_bytes = b"12345678".ljust(BLOCK_BYTES, b"\x00")  # pad "12345678" to 4 bytes
    ciphertext = cipher.encrypt(pt_bytes.hex())
    s = hashlib.sha3_224(bytes.fromhex(ciphertext)).digest()
    return hashlib.sha3_224(b"Public" + s).hexdigest()