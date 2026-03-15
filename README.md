# Thesis Benchmark
This repository contains the code and experimental framework developed for my bachelor thesis at École Polytechnique, carried out at the Max Planck Institute for Security and Privacy, under the joint supervision of Christof Paar, Bilal Zafar, Gregor Leander, and Amalia Böttger. The thesis investigates the extent to which large language models (LLMs) can act as cryptanalytical tools, by systematically evaluating their performance on a curated set of reduced-round block cipgers. 
The framework includes a pipeline for generating cryptographic challenges and an [Inspect AI](https://inspect.aisi.org.uk) evaluation suite to measure model performance on reduced-round block ciphers.

---

## Repository Structure

* `ciphers_and_challenges/`:
    * `ciphers/`: Contains Python implementations of custom-round versions of block ciphers that can be targetted (e.g., `PRESENT.py`, `DES.py`). A total of ten block ciphers were implemented.
    * `generate_challenges.py`: A utility script that generates an entry for a specific challenge, given the cipher, number of rounds, attack mode, and other specifications.
* `eval.py`: The core Inspect AI task definition. This script manages the system prompts, tools (Python sandbox, oracle access) and the evaluation lifecycle for a single challenge / batch of challenges. Before running it, the sandbox time limits for that level must be set, along with the overall wall-clock limits.
* `run_manager.py`: The manager of the challenge runs. It's in charge of calling `eval.py` with the correct challenges metadata (a `.json` file), in a progressive manner.

---

## The Challenges [Modify once we decide on the approach]
The primary objective of the LLM is to carry out an attack on a reduced-round version of a known block cipher. There are two attack modes studied:
* Known-Plaintext Attack (KPA): The model is allowed unlimited calls to a function `random_pairs(N)` that will return `N` plaintext-ciphertext pairs generated generated under the secret key of the target cipher.
* Chosen Plaintext Attacks (CPA): The model is given oracle access to the encryption function. It can unlimitedly call `encrypt_oracle([plaintexts])` with any list of plaintexts.

The `eval.py` script is written for KPA mode, but it also includes the tooling `encrypt_oracle` for CPA mode. However, some slight modifications to the script must be done in order to execute experiments on CPA mode.

The model's final goal is to recover sufficient information about the key in order to encrypt a specific plaintext with the specified cipher. In addition, for each plaintext attack we study two 'subgoals':
* Minimize oracle calls (`queries` mode): The model is prompted to try to reduce oracle usage (calls to the plaintext-ciphertext generating functions). Oracle query count is recorded, but it is less important than solving the challenge.
* Minimize time employed on the attack (`complexity` mode): The model is prompted to try to reach a working key as quickly as possible, and told that oracle usage is not penalized.
### Challenge Specification
Each challenge is uniquely defined by its algorithm, attack mode and round count. A typical entry in `challenges.jsonl` looks like this:

```json
{
  "id": "PRESENT_KPA_R2_0", 
  "algorithm": "PRESENT", 
  "attack": "KPA", 
  "goal": "queries",
  "rounds": 2, 
  "key_size": 80, 
  "block_size": 64, 
  "secret_key": "391c8b6b6acde9ecbd2d", 
}
```

### Verification Mechanism
The model is asked to:
1. Recover enough information (full key or partial key material) to correctly encrypt under this reduced-round cipher.
2. After this, the model's access to the oracle tool is blocked, and it is asked to encrypt a randomly generated plaintext string with its proposed key
3. The resuling ciphertext must be written as hex to a file `submission.txt`.

We then check against the expected encryption of the given plaintext, and score with 1.0 if they match, and with 0.0 otherwise.

### Challenges Hierarchy
- A challenge family is defined by a cipher algorithm and an attack mode (e.g. `PRESENT_KPA` constitutes one family).
- Each family is organized into levels, parametrized by the number of cipher rounds (e.g. `PRESENT_KPA` with 6 rounds corresponds to one level).
- Each level contains multiple instances. Instances at the same level differ only in the secret key used for encryption.
---

# Usage
To run a level of the benchmark, you can use `run_manager.py`. This script takes the following arguments:
- **`--model`** *(str, default: `openai/gpt-5.2`)*  
  Model used to generate attacks during the benchmark.

- **`--cipher`** *(str, required)*  
  Block cipher to benchmark (e.g., `PRESENT`, `DES`, `AES`).

- **`--prompt`** *(str, default: `planning`)*  
  Prompt template used for the model: `original`, `fixed`, or `planning`.

- **`--n_pairs`** *(int, default: `None`)*  
  Number of plaintext–ciphertext pairs provided upfront (used when `--prompt fixed`).

- **`--start_at`** *(int, default: `None`)*  
  Round number from which the benchmark starts (useful for resuming runs).

- **`--round`** *(int, default: `None`)*  
  Run the benchmark for a single round instead of all rounds.

- **`--samples`** *(int, default: `10`)*  
  Number of independent model samples executed per round.

For instance,  you could run the following command
```bash
python3 run_manager.py --model "openai/gpt-5.2-pro" --cipher "DES" --round 3 --samples 10 "
```
Once the evaluation is complete, you can visualize the reasoning traces, scores, and tool usage of the model by running:
```bash
inspect view
```
This will open a local website where we can browse through the generated logs.