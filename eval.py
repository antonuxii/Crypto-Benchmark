import importlib.util
import os
from pathlib import Path
from inspect_ai import Task, task
from inspect_ai.dataset import json_dataset, Sample
from inspect_ai.model import (
    ChatMessageSystem, 
    ChatMessageUser, 
    GenerateConfig,
)
from inspect_ai.solver import (
    solver, generate, use_tools, chain
)
from inspect_ai.scorer import scorer, Score, Target
from inspect_ai.tool import tool
from inspect_ai.util import (
    sandbox, working_limit, message_limit
)
import asyncio
import re
import sys
import json
import time
import math

# -------------------------------------------------------------------------
# 1. TOOL DEFINITIONS
# -------------------------------------------------------------------------

# A. Python Sandbox -------------------------------------------------------
@tool
def python_interpreter(timeout):
    async def execute(code: str):
        """
        Execute Python code. Use this for encryption, decryption, and hashing.
        
        Args:
            code: The Python code to execute
            
        Returns:
            str: The output from code execution or error message
        """
        result = await sandbox().exec(["python", "-c", code], timeout=timeout)
        if result.success:
            return result.stdout
        else:
            return f"Error: {result.stderr}"
    return execute

# B. Oracles ---------------------------------------------------------------
# Load modules
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

# Correct hex formatting
HEX16 = re.compile(r"^[0-9a-fA-F]{16}$")
def is_valid_pt(pt: str) -> bool:
    return bool(HEX16.fullmatch(pt))

ORACLES = str((Path(__file__).resolve().parent / "oracle_tools.py"))

async def _get_oracle_pairs(args_list):
    '''Get the directory of the oracle_tools.py script'''
    proc = await asyncio.create_subprocess_exec(
        sys.executable, ORACLES, *args_list,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"pairgen failed:\n{err.decode(errors='replace')}")

async def _sync_oracle_output_to_sandbox(host_file: Path, sandbox_name: str = "oracle_outputs.txt"):
    '''Sync output from oracle_tools.py to the file on the sandbox'''
    contents = host_file.read_text(encoding="utf-8")

    # Check whether the file already exists in the sandbox
    check = await sandbox().exec(
        ["bash", "-lc", f"test -f {sandbox_name}"],
    )

    if check.success: # File exists, append
        await sandbox().write_file(".oracle_append.tmp", contents)

        res = await sandbox().exec(
            [
                "bash",
                "-lc",
                f"cat .oracle_append.tmp >> {sandbox_name} && rm -f .oracle_append.tmp",
            ]
        )
        if not res.success:
            raise RuntimeError(f"Failed appending oracle output:\n{res.stderr}")

    else: # File does not exist, create it
        await sandbox().write_file(sandbox_name, contents)
    
    
def make_oracles(*, algorithm: str, secret_key_hex: str, n_rounds: int):
    '''Define the oracle tools'''
    qc = [0, 0.0]   # qc[0] = query count, qc[1] = query timer
    host_out = Path(__file__).with_name("oracle_outputs.txt")

    @tool
    def encrypt_oracle():
        async def encrypt(plaintexts_hex: list[str]) -> str:
            """
            Encrypt chosen plaintext blocks and append the resulting plaintext-ciphertext pairs to a file.

            Args:
                plaintexts_hex:
                    A list of plaintext blocks encoded as hexadecimal strings.
                    Each string must represent exactly one block of the cipher.
                    Hex strings should contain only characters [0-9a-f].

            Returns:
                A confirmation message indicating the number of pairs written to the file.
            """
            st = time.time()                # register start time
            nonlocal qc
            qc[0] += len(plaintexts_hex)    # update oracle count

            if not plaintexts_hex:
                return "No plaintexts provided. 0 pairs written to file."

            pts_json = json.dumps(plaintexts_hex)

            # Delegate work to external module (that implements parallelization)
            await _get_oracle_pairs([
                "--algorithm", algorithm,
                "--key", secret_key_hex,
                "--rounds", str(n_rounds),
                "--mode", "chosen",
                "--pts-json", pts_json,
                "--out", "oracle_outputs.txt",
            ])

            # Copy oracle_outputs.txt into sandbox so model can access it
            await _sync_oracle_output_to_sandbox(host_out, "oracle_outputs.txt")

            et = time.time()    # register end time
            qc[1] += et-st      # update oracle time

            return f"{len(plaintexts_hex)} plaintext-ciphertext pairs written to oracle_outputs.txt."
        return encrypt

    @tool
    def random_pair_oracle():
        async def random_pair(N: int) -> str:
            """
            Generate known plaintext–ciphertext pairs and append them to a file named 'oracle_outputs.txt'.

            Args:
                N:
                    The number of plaintext–ciphertext pairs to generate.
                    Each plaintext is sampled uniformly at random.

            Returns:
                A confirmation message indicating the number of pairs written to the file.
            """
            st = time.time()    # register start time
            nonlocal qc
            qc[0] += N          # update oracle count

            if N <= 0:
                return "0 pairs generated and written to file."
            
            # Delegate work to external module (that implements parallelization)
            await _get_oracle_pairs([
                "--algorithm", algorithm,
                "--key", secret_key_hex,
                "--rounds", str(n_rounds),
                "--mode", "random",
                "--n", str(N),
                "--out", "oracle_outputs.txt",
            ])

            # Copy oracle_outputs.txt into sandbox so model can access it
            await _sync_oracle_output_to_sandbox(host_out, "oracle_outputs.txt")

            et = time.time() # register end time
            qc[1] += et-st   # update oracle time
            
            return f"{N} plaintext-ciphertext pairs written to oracle_outputs.txt."
        return random_pair

    return encrypt_oracle, random_pair_oracle, qc

# -------------------------------------------------------------------------
# 2. DATASET LOADER
# -------------------------------------------------------------------------
def record_to_sample(record):
    return Sample(
        input="Attack the cipher. Before giving your final answer, check that your solution correclty "
               "encrypts at least 3 of the plaintext-ciphertext pairs you already know.",
        metadata=record 
    )

# -------------------------------------------------------------------------
# 3. TOOL ACCESS
# -------------------------------------------------------------------------
TIMEOUTS = [] # NOTE: Must be set manually for each cipher
@solver
def provide_tools():
    async def solve(state, generate):
        algo = state.metadata["algorithm"]
        key  = state.metadata["secret_key"]
        n    = int(state.metadata["rounds"])
        mode = state.metadata["attack"]
        prompt = state.metadata["prompt"]

        tools = [python_interpreter(TIMEOUTS[n-1])]

        if prompt != "fixed":
            # If not fixed pairs, give oracle access:
            enc_tool, rand_tool, qc = make_oracles(
                algorithm=algo,
                secret_key_hex=key,
                n_rounds=n
            )
        
            if mode == "CPA":
                tools.append(enc_tool())
            elif mode == "KPA":
                tools.append(rand_tool())

        state = await use_tools(*tools)(state, generate)
        
        # Save query counts and time for scoring/logging
        if prompt != "fixed":
            state.metadata["oracle_qc"] = qc
        
        return state
    return solve

# -------------------------------------------------------------------------
# 4. PROMPTS
# -------------------------------------------------------------------------

# A. Generate pairs in case of fixed dataset
@solver
def fixed_pairs():
    async def solve(state, generate):
        prompt = state.metadata["prompt"]
        if prompt == 'fixed':
            algo = state.metadata["algorithm"]
            key = state.metadata["secret_key"]
            n = int(state.metadata["rounds"])
            n_pairs = state.metadata["n_pairs"]
            host_out = Path(__file__).with_name("pairs.txt")
            
            # Delegate work to external module (that implements parallelization)
            await _get_oracle_pairs([
                "--algorithm", algo,
                "--key", key,
                "--rounds", str(n),
                "--mode", "random",
                "--n", str(n_pairs),
                "--out", "pairs.txt",
            ])

            # Copy pairs.txt into sandbox so model can access it
            await _sync_oracle_output_to_sandbox(host_out, "pairs.txt")
        return state
    return solve

# B. Inject the prompt
@solver
def crypto_system_prompt():
    """
    Injects a system message dynamically populated with the metadata 
    (Algorithm, Rounds, Key Size) for the current sample.
    """
    async def solve(state, generate):
        if not any(m.role == "system" for m in state.messages):
            meta = state.metadata
            algo = meta["algorithm"]
            rounds = meta["rounds"]
            prompt = meta["prompt"] # "original", "planning", "fixed"

            # Specify Data access
            if prompt == "fixed":
                oracle = (
                    "Data Access (known-plaintext pairs):\n"
                    "- You are given a file pairs.txt of plaintext-ciphertext pairs.\n"
                    "- Each line is of the form <plaintext_hex>,<ciphertext_hex>.\n"
                    "- All pairs were generated under the SAME fixed secret key.\n\n"
                )
                
            else: # KPA with custom queries
                oracle = (
                    "Data Access (known-plaintext pairs):\n"
                    "- You may call the tool `random_pair_oracle(N)` to obtain N fresh plaintext/ciphertext pairs.\n"
                    "- The tool appends the pairs to a file named `oracle_outputs.txt`.\n"
                    "- Each line in the file contains one pair in the format: <pt_hex>,<ct_hex>.\n"
                    "- All pairs are generated under the SAME fixed secret key.\n\n"
                )

            # Additional guidance instructions:
            if prompt == "original" or prompt == "fixed":
                instr = ""
            elif prompt == "planning":
                instr = (
                    "Oracle Usage Guidelines (Plan → Query → Reassess): \n"
                    "Before your first oracle call, you MUST write a short plan (5-10 lines) that includes:\n"
                    "(1) Attack approach you will try first.\n\n"
                    "(2) What weakness/statistical signal you will exploit at this round count.\n\n"
                    "(3) An initial query budget N0, with a 1-2 sentence justification.\n\n"

                    "IMPORTANT:\n\n"
                    "- Do NOT request an arbitrary small N “to start.” Your first N0 should be a reasoned choice.\n\n"
                    "- If an attempted approach stalls (e.g., solver returns unknown, or biases are not decisive) you MUST either (i) request more data with a justified new N, or (ii) switch to a different approach.\n\n"
                )

            # Initialize test vectors
            test_key = "0123456789abcdef"*((meta['key_size']//4)//16) + "0123456789abcdef"[:(meta['key_size']//4)%16]
            test_pt = "1"*(meta['block_size']//4)
            cipher = load_cipher_module(algo)
            test_ct = cipher.supreme_encryption(test_key, rounds, test_pt)[1]
            
            prompt_text = (
                "Task: \n"
                "You are a cryptanalyst working on a key-recovery task. The key used for encryption was sampled uniformly at random from the key space.\n" # I added this sentence because LLMs were wasting a lot of time thinking there was a weak-key thing or trick they could exploit. I think it's more efficient for them to know it's not the case, as this is not what we are interested in testing for anyway.
                "You have access to a Python interpreter.\n\n"
                f"Target cipher: {algo} (reduced to {rounds} rounds). \n"
                f"Key size: {meta['key_size']} bits. \n"
                f"Block size: {meta['block_size']} bits.\n\n"
                "IMPORTANT: Post-round operations defined by the cipher (such as a final key XOR / whitening step) must STILL be executed. They are NOT counted as rounds.\n\n"
                f"You may verify your implementation using the following hex test vectors: under the key {test_key}, the encryption of plaintext {test_pt} must produce ciphertext {test_ct}. \n\n"

                "Goal: To recover enough information (full key or partial key material) to correctly encrypt under this reduced-round cipher.\n\n"

                f"{oracle}" # explain access to data

                f"{instr}" # provide guidelines / tips on how to use data

                "For large searches, write efficient code. Use parallelization or other optimizations instead of naive single-threaded brute force when appropriate.\n\n" # TODO should we keep this ?
                "Once you have implemented your attack (and only then), birefly explain the main steps in your attack strategy, the estimated complexity, and your results.\n\n"

                "Clarifications:\n"
                "- All data is formatted as big-endian. \n"
            )
            
            state.messages.insert(0, ChatMessageSystem(content=prompt_text))
        return state
    return solve

# -------------------------------------------------------------------------
# 5. THE SCORER
# -------------------------------------------------------------------------
@solver
def evaluation_phase():
    async def solve(state, generate):
        # 1) Freeze oracle: allow ONLY python tool for the evaluation phase
        state = await use_tools(python_interpreter(TIMEOUTS[state.metadata["rounds"]-1]))(state, generate)

        # 2) Create a fresh plaintext/ciphertext pair (unknown during attack phase)
        cipher = load_cipher_module(state.metadata["algorithm"])
        pt_hex, ct_hex = cipher.supreme_encryption(state.metadata["secret_key"], state.metadata["rounds"], "")
            
        # Store expected ct for scorer
        state.metadata["eval_pt_hex"] = pt_hex
        state.metadata["eval_ct_hex"] = ct_hex

        # 3) Ask model to compute ciphertext using recovered key in result.txt and write it to submission.txt (python tool allowed)
        prompt = (
            "You have entered the evaluation phase: access to data is disabled.\n\n"
            f"Plaintext (hex): {pt_hex}\n\n"
            "Task: Using the recovered key material, compute the corresponding ciphertext.\n\n"
            "Write ONLY the ciphertext as a lowercase hex string to a file named submission.txt.\n\n"
        )

        state.messages.append(ChatMessageUser(content=prompt))

        return state

    return solve

@scorer(metrics=[])
def scorer():
    async def score(state, target: Target):
        # 1) Get relevant data
        attack = state.metadata["attack"]
        qc = state.metadata.get("orcale_qc", [state.metadata["n_pairs"]])[0]
        target = state.metadata.get("eval_ct_hex", "").strip().lower() # set by evaluation_phase()
        
        # 2) Fetch the expected submission.txt file
        try:
            verify_out = await sandbox().read_file("submission.txt")
            found = verify_out.strip().lower()
        except Exception:
            return Score(
                value=0.0,
                explanation=(
                    f"{attack} **failed**: submission.txt not found or unreadable.\n"
                    f"Plaintext-ciphertext pairs used: {qc}\n"
                )
            )

        # 3) Check against target answer
        if found == target:
            return Score(
                value=1.0,
                explanation=(
                    f"{attack} was **successful**.\n"
                    f"Plaintext-ciphertext pairs used: {qc}\n"
                )
            )
        else:
            return Score(
                value=0.0,
                explanation=(
                    f"{attack} **failed**:\n"
                    f"Expected ciphertext: {target}\n"
                    f"Model ciphertext:    {found}\n"
                    f"Plaintext-ciphertext pairs used: {qc}\n"
                )
            )

    return score

# -------------------------------------------------------------------------
# 6. MAIN TASK DEFINITION
# -------------------------------------------------------------------------

# A. Constraints
WALL_CLOCK_LIMITS = [] # NOTE: Must be set manually for each cipher.
# B. Running the task
@task
def crypto_benchmark():
    dataset_path = os.environ.get("TARGET_DATASET", "ciphers_and_challenges/active_batch.jsonl")
    dataset_full_path = Path(__file__).parent / dataset_path

    # Extract the number of rounds from the first sample in the dataset
    # (all samples in a dataset share the same rounds value)
    with open(dataset_full_path, 'r') as f:
        first_record = json.loads(f.readline())
        n_rounds = int(first_record["rounds"])

    return Task(
        dataset=json_dataset(str(dataset_full_path), record_to_sample),
        solver=[
            fixed_pairs(),                      # Generates pt-ct file of fixed size whenever prompt mode is "fixed"
            crypto_system_prompt(),             # Inject prompt and rules
            provide_tools(),                    # Allow tool use
            generate(),                         # Main reasoning loop, with retries
            evaluation_phase(),                 # Freeze oracle and ask for encryption
            generate(max_turns=3),              # Run the model to encrypt
        ],
        working_limit=WALL_CLOCK_LIMITS[n_rounds-1],  # Dynamic limit based on rounds
        scorer=scorer(),
        sandbox="docker",
        config=GenerateConfig(timeout=3600 * 6),
    )