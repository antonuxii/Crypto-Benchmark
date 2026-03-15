#!/usr/bin/env python3
import argparse
import importlib.util
import json
import math
import os
from pathlib import Path
import multiprocessing as mp
import time

# DYNAMIC MODULE LOADER
def load_cipher_module(algorithm: str):
    cipher_path = Path(__file__).resolve().parent / f"ciphers_and_challenges/ciphers/{algorithm}.py"
    if not cipher_path.exists():
        raise FileNotFoundError(f"Cipher file not found: {cipher_path}")

    # Temporarily add the cipher's directory to the path to find .so files
    cipher_dir = cipher_path.parent
    original_cwd = os.getcwd()
    os.chdir(cipher_dir)

    spec = importlib.util.spec_from_file_location(f"cipher_{algorithm}", str(cipher_path))
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)

    os.chdir(original_cwd)

    if not hasattr(mod, "supreme_encryption"):
        raise AttributeError(f"{cipher_path.name} has no supreme_encryption()")
    return mod

# GLOBALS
_CIPHER = None
_KEY = None
_ROUNDS = None

def _init_worker(algorithm: str, secret_key_hex: str, n_rounds: int):
    global _CIPHER, _KEY, _ROUNDS
    _CIPHER = load_cipher_module(algorithm)
    _KEY = secret_key_hex
    _ROUNDS = n_rounds

# WORKERS AND HELPERS
def _encrypt_batch(pts_hex):
    out = []
    for pt_hex in pts_hex:
        pt, ct = _CIPHER.supreme_encryption(_KEY, _ROUNDS, pt_hex)
        out.append((pt, ct))
    return out

def _random_batch(count: int):
    out = []
    for _ in range(count):
        pt, ct = _CIPHER.supreme_encryption(_KEY, _ROUNDS, "")
        out.append((pt, ct))
    return out

def _chunk_list(xs, n):
    for i in range(0, len(xs), n):
        yield xs[i:i+n]

# MAIN FUNCTION
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--algorithm", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--rounds", type=int, required=True)
    ap.add_argument("--mode", choices=["chosen", "random"], required=True)

    # chosen mode:
    ap.add_argument("--pts-list", default=None)  # list of hex strings

    # random mode:
    ap.add_argument("--n", type=int, default=0)

    # output:
    ap.add_argument("--out", required=True)

    # perf knobs:
    ap.add_argument("--workers", type=int, default=0)
    args = ap.parse_args()

    workers = args.workers or (os.cpu_count() or 4)

    ctx = mp.get_context("fork")

    if args.mode == "chosen":
        if not args.pts_json:
            raise ValueError("--pts-list required for mode=chosen")
        pts = json.loads(args.pts_json)
        if not isinstance(pts, list):
            raise ValueError("--pts-list must be a list")

        # chunking
        chunk_size = max(1, min(2000, math.ceil(len(pts) / (workers * 4))))
        chunks = list(_chunk_list(pts, chunk_size))

        with ctx.Pool(
            processes=workers,
            initializer=_init_worker,
            initargs=(args.algorithm, args.key, args.rounds),
        ) as pool:
            results = pool.map(_encrypt_batch, chunks)

        pairs = [p for chunk in results for p in chunk]

    else:  # random
        N = args.n
        if N <= 0:
            pairs = []
        else:
            batches = workers
            batch_size = math.ceil(N / batches)
            counts = [min(batch_size, N - i * batch_size) for i in range(batches) if i * batch_size < N]

            with ctx.Pool(
                processes=workers,
                initializer=_init_worker,
                initargs=(args.algorithm, args.key, args.rounds),
            ) as pool:
                results = pool.map(_random_batch, counts)

            pairs = [p for chunk in results for p in chunk]
    # Write output (overwrite)
    out_path = Path(args.out)
    with out_path.open("w", encoding="utf-8") as f:
        f.write("".join(f"{pt},{ct}\n" for pt, ct in pairs))

if __name__ == "__main__":
    main()
