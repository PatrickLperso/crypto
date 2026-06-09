import pytest
from Crypto.Util.number import bytes_to_long, long_to_bytes

from crypto_core.repeated_nonce_gcm import (
    decrypt,
    encrypt,
    xor,
    incr_counter,
    to_gcm_poly,
    zero_pad,
    gcm,
    recover,
    challenge,
    IV, 
    KEY, 
    FLAG,
)

class TestGCMAttackNonceForgery:
    @pytest.fixture
    def mod(self):
        # polynome AES GCM x^128 + x^7 + x^2 + x + 1
        return 0x100000000000000000000000000000087
    
    def test_tag_generation(self, mod):
        # note le cas ici necessite un ad, un nonce et du plaintext
        # les cas spéciaux, un item manquant 
        # ou le clé AES qui ne fait pas 96 bits ne sont pas testés

        # ====================================================================
        # ========================= GCM Test Vectors =========================
        # ====================================================================
        
        # Test Case 4 page 29, nonce == 96 bits
        # https://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf
        
        aes_key = long_to_bytes(0xfeffe9928665731c6d6a8f9467308308)
        ad = long_to_bytes(0xfeedfacedeadbeeffeedfacedeadbeefabaddad2)
        nonce = long_to_bytes(0xcafebabefacedbaddecaf888)
        plaintext = long_to_bytes(0xd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39)

        nonce1, ad1, cipher1, tag1 = gcm(ad, nonce, plaintext, mod, aes_key)

        assert nonce1 == "cafebabefacedbaddecaf888"
        assert ad1 == "feedfacedeadbeeffeedfacedeadbeefabaddad2"
        assert cipher1 == "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
        assert tag1 == "5bc94fbc3221a5db94fae95ae7121a47"

    def test_tag_encryption(self, mod):
        # ====================================================================
        # ================== GCM Test Vectors Python lib======================
        # ====================================================================

        # on compare notre implémentation à celle de Python
        plaintext1 = long_to_bytes(0xd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39)

        res = encrypt(plaintext1.hex())
        custom_gcm = gcm(b"CryptoHack", IV, plaintext1, mod, KEY)
        assert res["nonce"] == custom_gcm[0]
        assert res["associated_data"] == custom_gcm[1]
        assert res["ciphertext"] == custom_gcm[2]
        assert res["tag"] == custom_gcm[3]

    def test_aes_gcm_nonce_forgery_attack(self, mod):
        # =======================================================================
        # ======================= GCM nonce reuse attack test ===================
        # =======================================================================

        aes_key = os.urandom(16)
        nonce = os.urandom(12)

        ad1 = b"This is a masterpiece, ip_dest=192.168.1.1 ip_origin=192.168.1.2"
        plaintext1 = b"Take on me ... Take on me ... take me on ... take me on "

        ad2 = b"I don't like this song"
        plaintext2 = b"Take on me ... T"

        nonce1, ad1, cipher1, tag1, poly1_ref, h1_ref = gcm(ad1, nonce, plaintext1, mod, aes_key, test=True)
        nonce2, ad2, cipher2, tag2, poly2_ref, h2_ref = gcm(ad2, nonce, plaintext2, mod, aes_key, test=True)
        
        assert h1_ref == h2_ref

        cipher1 = bytes.fromhex(cipher1)
        cipher2 = bytes.fromhex(cipher2)
        tag1 = bytes.fromhex(tag1)
        tag2 = bytes.fromhex(tag2)
        ad1 = bytes.fromhex(ad1)
        ad2 = bytes.fromhex(ad2)
        key_possibles = recover(ad1, cipher1, tag1, ad2, cipher2, tag2, mod, poly1_ref, poly2_ref, h1_ref)

        # a-t'on trouvé la valeur h qui permet de forger de nouveaux tags ?
        assert h1_ref in key_possibles

    def test_aes_gcm_nonce_forgery_attack(self, mod):
        # ===================================================================================
        # ======================= GCM nonce reuse attack Cryptohack local ===================
        # ===================================================================================
        interface_encrypt = encrypt
        interface_decrypt = decrypt

        flag = challenge(interface_encrypt, interface_decrypt, mod)
        assert flag == FLAG.encode()