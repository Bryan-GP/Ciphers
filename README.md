# Cryptography

A personal Python project for reconstructing and experimenting with classical
and modern symmetric cipher algorithms. The implementations are intentionally
simple, written from specifications, and meant for learning rather than for
production use.

## Project structure

```text
.
├── README.md
├── ctr_main.py             # Interactive AES-CTR demo
├── gcm_main.py             # Interactive AES-GCM demo
├── Symmetric_Ciphers/
│   ├── aes.py              # AES block-cipher primitive and key schedule
│   ├── ceasar.py           # Printable-ASCII Caesar cipher demo
│   ├── modes.py            # AES-CTR and AES-GCM implementations
│   ├── substitution.py     # Printable-ASCII substitution cipher demo
│   ├── symmetric.py        # Shared/legacy symmetric cipher helpers
│   └── __pycache__/
├── Asymmetric_Ciphers/
│   └── rsa.py              # Reserved for future RSA work
└── .git/
```

## Current status

### AES primitives

- AES key expansion and block encryption are implemented for 128-, 192-, and
  256-bit keys.
- The core block cipher logic operates in plain Python and supports key
  schedules for all standard AES key lengths.
- The implementation is structured so it can be reused by different modes.

### AES-CTR

- `AES_CTR` is fully implemented in `Symmetric_Ciphers/modes.py`.
- It generates a random key and nonce for each encryption run.
- The CTR demo in `ctr_main.py` supports interactive decryption and a
  bit-flipping attack demonstration.
- CTR mode gives confidentiality but no integrity, which is reflected in the
  attack example.

### AES-GCM

- `AES_GCM` is implemented in `Symmetric_Ciphers/modes.py`.
- It includes GHASH, finite-field multiplication, nonce handling, counter-mode
  encryption, and authentication-tag verification.
- Encryption and decryption both use AES with a random nonce and a per-message
  key, and the tag is checked before decrypting the plaintext.
- The interactive demo in `gcm_main.py` lets you encrypt a message, inspect the
  nonce/ciphertext/tag, test authentication failure with a tampered ciphertext,
  test a wrong key, and switch key sizes.

### Classical cipher demonstrations

- `ceasar.py` implements a Caesar-style rotation over printable ASCII
  characters (code points 32–126).
- `substitution.py` creates a random monoalphabetic substitution over
  printable ASCII characters (code points 32–125).
- Both scripts support interactive encryption and decryption.

### Asymmetric ciphers

- `Asymmetric_Ciphers/rsa.py` is still a placeholder for future RSA work.

## Requirements

- Python 3.8 or newer
- No third-party packages are required by the current source.

## Running the demos

Run the AES-CTR demonstration from the repository root:

```bash
python3 ctr_main.py
```

The script prompts for a plaintext and key size, then offers menu options to:

- view the generated key
- view the nonce and ciphertext
- view the nonce alone
- demonstrate a CTR bit-flipping attack
- decrypt and exit

Run the AES-GCM demonstration:

```bash
python3 gcm_main.py
```

The script prompts for a plaintext and key size, then offers menu options to:

- inspect the key, nonce, ciphertext, and authentication tag
- verify authentication failure when ciphertext is modified
- verify authentication failure when the key is wrong
- change the key size and re-encrypt the plaintext
- decrypt and exit

Run the classical cipher demos:

```bash
python3 Symmetric_Ciphers/ceasar.py
python3 Symmetric_Ciphers/substitution.py
```

## Programmatic usage

AES-CTR mode can be imported directly:

```python
from Symmetric_Ciphers.modes import AES_CTR

aes_ctr = AES_CTR()
ciphertext = aes_ctr.encrypt("hello world", bits=128)
key = aes_ctr._master_key
plaintext = aes_ctr.decrypt(ciphertext, key, bits=128)

assert plaintext == "hello world"
```

AES-GCM can also be used in the same way:

```python
from Symmetric_Ciphers.modes import AES_GCM

aes_gcm = AES_GCM()
ciphertext = aes_gcm.encrypt("hello world", key_bits=128)
key = aes_gcm._master_key
plaintext = aes_gcm.decrypt(ciphertext, key, key_bits=128)

assert plaintext == "hello world"
```

`encrypt()` returns a hexadecimal string containing the nonce, ciphertext, and
authentication tag. The generated key is exposed via the internal
`_master_key` attribute so the demo can decrypt its own output.

The classical cipher modules also expose `generate_key()`, `encrypt()`, and
`decrypt()` functions for experimentation.

## Security warning

This project is educational and must not be used for real security. The
implementations have not been hardened or independently audited. In
particular, CTR mode does not provide integrity, the classical ciphers are
cryptographically insecure, and the substitution cipher uses Python's
non-cryptographic `random` module.

For production cryptography, use a maintained library such as
[cryptography](https://cryptography.io/) or
[PyCryptodome](https://pycryptodome.readthedocs.io/).
