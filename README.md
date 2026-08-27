# Cryptography

A personal Python project for reconstructing and experimenting with classical
and modern cipher algorithms. The implementations are written from
specifications and are intended to support learning, not production security.

## Project structure

```text
.
├── sym_main.py
├── Symmetric_Ciphers/
│   ├── aes.py             # AES block-cipher transformations
│   ├── ciphers.py         # Symmetric-cipher base class
│   ├── modes.py           # AES-CTR implementation and AES-GCM scaffold
│   ├── ceasar.py          # Printable-ASCII Caesar cipher demo
│   └── substitution.py    # Printable-ASCII substitution cipher demo
└── Asymmetric_Ciphers/
    └── rsa.py             # Reserved for future RSA work
```

## Current status

### AES

- AES key expansion and block encryption are implemented for 128-, 192-, and
  256-bit keys.
- `AES_CTR` combines the AES block cipher with counter mode.
- The CTR demo generates a random key and an 8-byte nonce for each run.
- `sym_main.py` provides an interactive workflow for encryption, inspecting
  the key/ciphertext/nonce, decryption, and demonstrating a CTR bit-flipping
  attack.

`AES_GCM` is currently a scaffold: its encryption, decryption, GHASH, and
finite-field multiplication methods are not implemented yet.

### Classical cipher demonstrations

- `ceasar.py` implements a Caesar-style rotation over printable ASCII
  characters (code points 32–126).
- `substitution.py` creates a random monoalphabetic substitution over
  printable ASCII characters (code points 32–125).
- Both scripts support interactive encryption followed by decryption.

### Asymmetric ciphers

`Asymmetric_Ciphers/rsa.py` is currently empty and reserved for a future RSA
learning implementation.

## Requirements

- Python 3.8 or newer
- No third-party packages are required by the current source

## Running the demos

Run the AES-CTR demonstration from the repository root:

```bash
python3 sym_main.py
```

Enter a plaintext and select a key size:

```text
[1] 128
[2] 192
[3] 256
```

After encryption, the menu lets you:

- `k` — display the generated key in hexadecimal
- `c` — display the nonce and ciphertext in hexadecimal
- `n` — display the nonce
- `a` — demonstrate a CTR bit-flipping attack
- `d` or any other input — decrypt and exit

The attack example expects the plaintext `amount=00010`; it changes that
value to `amount=99999` without knowing the key. This demonstrates that CTR
provides confidentiality but does not authenticate ciphertext.

Run the classical cipher demos:

```bash
python3 Symmetric_Ciphers/ceasar.py
python3 Symmetric_Ciphers/substitution.py
```

## Programmatic usage

The AES-CTR mode can be imported from the package:

```python
from Symmetric_Ciphers.modes import AES_CTR

aes_ctr = AES_CTR()
ciphertext = aes_ctr.encrypt("hello world", bits=128)
key = aes_ctr._master_key
plaintext = aes_ctr.decrypt(ciphertext, key, bits=128)

assert plaintext == "hello world"
```

`encrypt()` returns a hexadecimal string containing the nonce followed by the
ciphertext. The generated key is currently exposed through the internal
`_master_key` attribute so the demo can decrypt its own output.

The classical cipher modules also expose `generate_key()`, `encrypt()`, and
`decrypt()` functions for experimentation.

## Development approach

The project is developed incrementally:

1. Read the relevant standard or algorithm specification.
2. Implement the primitive transformations in plain Python.
3. Build a small mode or interactive example around the primitives.
4. Compare results with known test vectors and established cryptographic
   libraries.
5. Add automated round-trip and test-vector coverage as implementations
   mature.

## Security warning

This project is educational and must not be used for real security. The
implementations have not been hardened or independently audited. In
particular, CTR mode does not provide integrity, the classical ciphers are
cryptographically insecure, and the substitution cipher uses Python's
non-cryptographic `random` module.

For production cryptography, use a maintained library such as
[cryptography](https://cryptography.io/) or
[PyCryptodome](https://pycryptodome.readthedocs.io/).

## Planned work

- Validate AES-128/192/256 against NIST test vectors.
- Add automated unit tests and library comparison tests.
- Complete AES-GCM, including authentication-tag verification.
- Implement RSA with appropriate padding and test vectors.
- Improve key and nonce handling in the interactive examples.
