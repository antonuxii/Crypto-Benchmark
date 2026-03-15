from secrets import randbits

# cipher: (rounds, key_size, block_size)
CIPHERS = {
    "PRESENT":  (31, 80, 64),
    "DES":      (16, 64, 64),
    "AES":      (10, 128, 128),
    "Blowfish": (16, 64, 64), # key length in Blowfish is variable, but we fix it at 8 bytes
    "RECTANGLE":(25, 80, 64),
    "SPEEDY":   (9, 192, 192),
    "FEAL":     (32, 64, 64), # NOTE: Only accepts even number of rounds
    "Serpent":  (32, 128, 128),
    "Simon":    (32, 64, 32),
    "Speck":    (22, 64, 32),
}

# -------------------------------------------------------------------------
# CHALLENGE GENERATION
# -------------------------------------------------------------------------

def create_challenge_entry(cipher: str, prompt: str, n_pairs: int | None, mode: str, rounds: int, goal: str, i: int):
    """
    Generates a single flat dictionary entry for a challenge.
    Used by the Manager to generate batches on the fly.
    The entry consists of the following fields:
        - "id" : the unique identifier of the challenge
        - "algorithm" : the name of the symmetric encryption algorithm used in the challenge, chosen from the above list CIPHERS
        - "attack" : CPA or KPA, sepcifying the attack style
        - "goal" : queries or complexity, defining what the LLM is asked to minimize
        - "rounds" : the number of rounds of the specified algorithm used for encryption
        - "key_size" : the key-size used for the cipher
        - "block_size: : the block-size of the cipher
        - "secret_key" : the secret key as a HEX string. It's length depends on the key-size.
    """        
    _, key_size, block_size = CIPHERS[cipher]
    
    # 1. Generate random key
    key_int = randbits(key_size)
    key_hex = key_int.to_bytes(key_size // 8, "big").hex()
        
    # 3. Create Flat Entry

    if n_pairs:
        return {
            "id": f"{cipher}_{prompt}_R{rounds}_{i}",
            "prompt": prompt,
            "n_pairs": n_pairs, # if prompt is 'fixed', pass how many pairs to generate
            "algorithm": cipher,
            "attack": mode,
            "goal": goal,
            "rounds": rounds,
            "key_size": key_size,
            "block_size": block_size,
            "secret_key": key_hex,
        }
    else:
        return {
            "id": f"{cipher}_{prompt}_R{rounds}_{i}",
            "prompt": prompt,
            "n_pairs": n_pairs,
            "algorithm": cipher,
            "attack": mode,
            "goal": goal,
            "rounds": rounds,
            "key_size": key_size,
            "block_size": block_size,
            "secret_key": key_hex,
        }
