import argparse
import json
import subprocess
import sys
from pathlib import Path
from inspect_ai.log import read_eval_log
import os

"""
run_manager.py dynamically generates challenges, so as to only prompt harder challenges if the easier ones have been succesful.
To do this, we use the function create_challenge_entry from ciphers_and_challenges/generate_challenges.py 
It then calls eval.py on the go with the dynamically populated challenges.
"""

sys.path.append(str(Path(__file__).parent / "data"))

from data.generate_challenges import CIPHERS, create_challenge_entry

def generate_batch(cipher, prompt, n_pairs, mode, rounds, goal, samples=10):
    return [create_challenge_entry(cipher, prompt, n_pairs, mode, rounds, goal, i) for i in range(samples)]

def run_manager(model_name, cipher, prompt, n_pairs, samples, round, start_at):
    # Define paths
    base_dir = Path(__file__).parent.resolve() 
    start = start_at if start_at is not None else 1
    step = 1
    max_rounds = CIPHERS[cipher][0] if round is None else round + 1

    if round is not None:
        start = round
        max_rounds = round
    if cipher == "FEAL": # only accepts even number of rounds:
        start, step = 2, 2

    # Create a unique filename for this specific worker
    unique_batch_file = f"ciphers_and_challenges/active_batch_{cipher}_{prompt}_KPA_complexity.jsonl"
    unique_batch_path = base_dir / unique_batch_file
    print(f"\n=== Starting {cipher} KPA ===")
    
    for r in range(start, max_rounds + 1, step):
        print(f"--- Round {r} ---")
        
        # 1) Generate Batch
        samples = generate_batch(cipher, prompt, n_pairs, "KPA", r, "complexity", samples) 

        # 2) Write to the unique file for this cipher family & mode
        with open(unique_batch_path, "w") as f:
            for s in samples:
                f.write(json.dumps(s) + "\n")
        
        # 3) Run Inspect with modified environment (which tells what batch we are working on)
        inspect_cmd = "inspect"
        possible_inspect = Path(sys.executable).parent / "inspect"
        if possible_inspect.exists():
            inspect_cmd = str(possible_inspect)

        env = os.environ.copy()
        env["TARGET_DATASET"] = unique_batch_file
        cmd = [
            inspect_cmd, "eval", "eval.py",
            "--model", model_name,
            "--max-tasks", "10",        
            "--max-connections", "10", 
            "--max-subprocesses", "10"
        ]
        print(f"Running batch of {len(samples)} samples...")

        # 4) Fetch batch results
        result = subprocess.run(cmd, cwd=base_dir, env=env)
        if result.returncode != 0:
            print(f"Error running inspect")
        
        # Find the most recently created log file from inspect's default location
        logs_dir = base_dir / "logs"
        log_files = sorted(logs_dir.glob("*.eval"), key=lambda f: f.stat().st_mtime, reverse=True)
        if not log_files:
            print("No log file found.")
            break
        log_path = log_files[0]
        
        # 5) Analyze batch results
        success_count = 0
        total_count = 0
        
        try:
            eval_log = read_eval_log(str(log_path))
            if eval_log.samples:
                total_count = len(eval_log.samples)
                for sample in eval_log.samples:
                    # Check if the score object exists and value is 1.0
                    if sample.scores:
                        score = list(sample.scores.values())[0]
                        if score.value == 1.0:
                            success_count += 1
        except Exception as e:
            print(f"Error parsing log: {e}")
        
        success_rate = (success_count / total_count) if total_count > 0 else 0
        print(f"Success Rate for Round {r}: {success_rate*100:.1f}% ({success_count}/{total_count})")
        
        # 6) Stopping Condition
        if success_count == 0:
            print(f"Zero success count at Round {r}. Stopping KPA for {cipher}.")
            break

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=str, default="openai/gpt-5.2")
    parser.add_argument("--cipher", type=str, required=True) # e.g., 'PRESENT'
    parser.add_argument("--prompt", type=str, default="planning") # 'original', 'fixed', 'planning'
    parser.add_argument("--n_pairs", type=int, default=None) # number of pt-ct pairs provided upfron to the model (in case that prompt == 'fixed')
    parser.add_argument("--start_at", type=int, default=None ) # round we start from
    parser.add_argument("--round", type=int, default=None) # single round run
    parser.add_argument("--samples", type=int, default=10) # number of samples per round

    args = parser.parse_args()
    if args.prompt == "fixed" and args.n_pairs is None:
        raise ValueError("Fixed number of plaintext ciphertext pairs missing. Specify with argument --n_pairs")
    run_manager(args.model, args.cipher, args.prompt, args.n_pairs, args.samples, args.round, args.start_at) 