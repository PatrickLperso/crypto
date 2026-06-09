# Cryptography & PKI

![Tests](https://github.com/PatrickLperso/crypto/actions/workflows/ci.yml/badge.svg)

This repository is the work of Patrick L. to advance his skills in cryptography through Cryptopals and CryptoHack.

You can read some write-ups on his [Medium blog](https://medium.com/@patrickl.publique):
 - [Attacks against elliptic curves, from ECDH to ECDSA](https://medium.com/@patrickl.publique/attacks-on-elliptic-curves-pollard-polhig-invalid-curve-twist-lattice-18ac1abfb6c8)
 - [AES-GCM implementation and attacks](https://medium.com/@patrickl.publique/aes-gcm-nonce-reuse-attack-515f7acec3f7)

![screenshot](other/image.png)

## Structure

- `crypto_core/` — reusable cryptographic primitives and attacks (Galois fields, elliptic curves, AES, ECDSA, Pohlig-Hellman, invalid curve attack, etc.). Almost every script here is tested.
- `tests/crypto_core/` — pytest unit tests for the core library.
- `challenges/` — standalone CryptoHack / Cryptopals solving scripts. These are network-bound, one-shot scripts and are **not** unit-tested by design.

## Installation

```bash
cd ~
sudo apt-get install binutils make m4 perl flex bison python3 tar bc gcc g++ ca-certificates libbz2-dev bzip2 xz-utils libffi-dev
git clone git@github.com:PatrickLperso/crypto.git
cd ~/crypto
python3 -m venv crypto_venv
source crypto_venv/bin/activate
export SAGE_CONF_FILE=/dev/null
pip install -r requirements.txt
```

> **Note on SageMath:** `SAGE_CONF_FILE=/dev/null` tells `passagemath-conf` to skip building a SageMath tree from source and use the prebuilt wheels instead. Without it, the install tries to compile SageMath locally (which takes hours and needs many `-dev` system libraries).


## Continuous Integration

Tests run automatically on every push and pull request via GitHub Actions. NOte