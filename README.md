# Cryptography & PKI
This repository is the the work of Patrick L. to advance his skills in cryptography thanks to crytopals and cryptohack.

You can read some write-ups about it on his [blog medium](https://medium.com/@patrickl.publique) :
 - [Attacks against ellitpic curves, from ECDH to ECDSA](https://medium.com/@patrickl.publique/attacks-on-elliptic-curves-pollard-polhig-invalid-curve-twist-lattice-18ac1abfb6c8)
 - [AES-GCM implementation and attacks](https://medium.com/@patrickl.publique/aes-gcm-nonce-reuse-attack-515f7acec3f7)

![screenshot](other/image.png)

# Installation
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