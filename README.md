# Cryptography — Personal Cipher Reconstruction Project

This repository is a personal project exploring cryptography by reconstructing cipher algorithms from specifications and implementing them in Python. The goal is learning: understanding the algorithms at a low level, experimenting with modes of operation, and comparing results with established libraries.

## What this project is

- A hands-on collection of cipher implementations (currently includes an AES implementation in AES-CTR mode).
- A learning exercise to rebuild algorithms from standards/specifications rather than relying solely on high-level libraries.
- A playground for experimenting with different key sizes, modes, and internal transformations (SubBytes, ShiftRows, MixColumns, key expansion, etc.).

This is primarily a personal learning repository — the code is intended for educational purposes, not production use.

## Current status

- aes.py: Implements an AES-like cipher with AES-128/192/256 in CTR mode working end-to-end (interactive CLI). See notes below for details and usage.
- Other ciphers and experiments may be added over time as the project evolves.

Notes from the implementation:
- AES-128/192/256-CTR are implemented and tested in the script; the interactive prompt lets you choose the desired key size.
- Key expansion, rounds, and mode-of-operation code support 128, 192 and 256-bit keys. It's still recommended to validate with known test vectors for full confidence.

## How the project is being built

Approach and methodology:
- Read the algorithm specification (RFCs, FIPS) and implement the referenced transforms in pure Python.
- Start with a working minimal mode (CTR) and AES-128 to validate encryption/decryption flows.
- Add helper functions for key expansion, byte substitution (S-box), row shifts, and column mixing — testing each unit carefully.
- Iterate: test known vectors, adjust the implementation to match expected outputs, and add modes/features gradually.
- Keep the code simple and readable for learning; when needed, compare outputs with a standard crypto library (e.g., PyCryptodome) to validate correctness.

## How to use

Requirements:
- Python 3.8+ (recommended). No external dependencies are required for the current code, it uses only the Python standard library.

Run the AES interactive script:

```bash
python3 aes.py
```

Typical interactive session flow (aes.py):
1. The script prompts: "give me a text to encrypt"
2. Enter a plaintext string and press Enter.
3. Choose key size option: `1` (128), `2` (192), or `3` (256). For reliable results use `1` (128).
4. After encryption the script shows a small menu where you can:
   - press `k` to view the generated key (hex)
   - press `c` to view the ciphertext (hex)
   - press `n` to view the nonce (hex)
   - press `d` or anything else to decrypt and exit
5. The script decrypts and prints the decrypted message.

Programmatic usage (import as module):

The AES class is also usable from other Python code. Example:

```python
from aes import AES

aes = AES()
cipher_hex = aes.encrypt("hello world", bits=128)
# master key used by the script is stored in aes._master_key (bytes)
# To decrypt when you have the key bytes:
plaintext = aes.decrypt(cipher_hex, aes._master_key, bits=128)
print(plaintext)  # should be 'hello world'
```

Important: The current `encrypt` method returns a hex string that concatenates the nonce and ciphertext. The `decrypt` method expects that hex string and the key bytes.

## Security & warnings

- This implementation is for educational purposes only. Do not use this code for any real security-critical or production system.
- Proper cryptographic systems require careful attention to IV/nonce management, constant-time implementations, authenticated encryption (AEAD), safe key storage, and more.
- If you need real cryptography in production, use well-maintained libraries such as cryptography or PyCryptodome.

## Development notes

- Tests: There are no automated tests in the repository yet. Adding test vectors (NIST test vectors or comparison against a library) is recommended to validate correctness.
- Future work ideas:
  - Validate AES implementations against NIST test vectors (128, 192, 256) and add more modes (ECB/CBC/GCM) for comparison.
  - Add ECB/CBC/GCM implementations or wrapper usage with authenticated encryption.
  - Add unit tests with known test vectors.
  - Add comparison scripts that assert equivalence with PyCryptodome outputs.

## Contributing & personal notes

This is a personal project — contributions or suggestions are welcome, but the repository is mainly a learning notebook. If you plan to experiment with the code, please fork/copy and run locally.

If you'd like specific changes (adding tests, implementing more ciphers, or porting to other languages), open an issue or send a message with what you want to explore next.

## Other scripts in this repository

The repository contains a few smaller/older scripts that demonstrate basic cipher concepts. Short descriptions and usage are below.

- [ceasar.py](/Users/bryan/Documents/2025-2026/Improvement/Projects/Cryptography/ceasar.py)
  - What: A simple Caesar-style rotation cipher implemented over the printable ASCII range (32–126). The key is a single integer shift chosen randomly for each run.
  - How it works: The script maps each character by shifting its codepoint within the allowed range and wraps using modular arithmetic.
  - Usage:
    - Run interactively: `python3 ceasar.py`
    - You'll be prompted for text; the script displays the ciphertext and then decrypts it after a key-press.
  - Status: Educational/demo script. Works for printing and experimenting with rotation ciphers.

- [substitution.py](/Users/bryan/Documents/2025-2026/Improvement/Projects/Cryptography/substitution.py)
  - What: A random monoalphabetic substitution cipher over printable ASCII characters.
  - How it works: `generate_key()` creates a random bijection of the printable ASCII set (32–125). `encrypt()` and `decrypt()` use that mapping with Python's `str.translate`.
  - Usage:
    - Run interactively: `python3 substitution.py`
    - It prompts for text, prints the ciphertext, waits for a keypress, then prints the decrypted text.
  - Status: Working demo. The key is generated with Python's `random` module (not cryptographically secure).

- [rsa.py](/Users/bryan/Documents/2025-2026/Improvement/Projects/Cryptography/rsa.py)
  - What: Placeholder file for future RSA work. Currently empty.
  - Plan: Implement basic RSA key generation, encryption, and decryption for learning — validate with small key sizes and then upgrade algorithms and padding schemes.
  - Status: TODO — no implementation yet.


## Running the smaller scripts

Each script is self-contained and designed for quick interactive experiments. Example:

```bash
python3 ceasar.py
python3 substitution.py
# rsa.py currently has no code; open and edit to add an implementation
```

## Suggested next steps for these scripts

- Add simple unit tests that check encryption/decryption round-trips.
- Replace Python's `random` with `secrets` for any code where pseudo-randomness must be unpredictable (only if building cryptographically-relevant code).
- For RSA: implement key generation and small test vectors, then compare against a library implementation.

---

Created as a personal reconstruction and study of cipher algorithms. Not intended for production use.
