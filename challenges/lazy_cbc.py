from Crypto.Cipher import AES
import os 
from Crypto.Util.number import bytes_to_long, long_to_bytes
import requests

KEY = b"1245154287591245"
FLAG = "crytpo{ecb}" 

def encrypt(plaintext):
    plaintext = bytes.fromhex(plaintext)
    if len(plaintext) % 16 != 0:
        return {"error": "Data length must be multiple of 16"}

    # réutilisation de l'iv en utilisant la KEY
    cipher = AES.new(KEY, AES.MODE_CBC, KEY)
    encrypted = cipher.encrypt(plaintext)

    if plaintext == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
        cipher_ecb = AES.new(KEY, AES.MODE_ECB)
        encrypted_ecb = cipher_ecb.encrypt(KEY)

        assert encrypted_ecb==encrypted

    return {"ciphertext": encrypted.hex()}

def get_flag(key):
    key = bytes.fromhex(key)

    if key == KEY:
        return {"plaintext": FLAG.encode().hex()}
    else:
        return {"error": "invalid key"}

def receive(ciphertext):
    ciphertext = bytes.fromhex(ciphertext)
    if len(ciphertext) % 16 != 0:
        return {"error": "Data length must be multiple of 16"}

    cipher = AES.new(KEY, AES.MODE_CBC, KEY)
    decrypted = cipher.decrypt(ciphertext)

    try:
        decrypted.decode() # ensure plaintext is valid ascii
    except UnicodeDecodeError:
        return {"error": "Invalid plaintext: " + decrypted.hex()}

    return {"success": "Your message has been received"}

def test(ciphertext):
    ciphertext=bytes.fromhex(ciphertext)
    cipher = AES.new(KEY, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    return decrypted

def challenge(interface_encrypt, interface_receive, interface_get_flag):

    # on fait l'equivalent de cipher_ecb.encrypt(iv)
    payload =  bytes([0x0] * 16).hex()
    cipher_iv = interface_encrypt(payload)["ciphertext"]

    # on initialise un C1 random 
    cipher_iv_1 = "00000000000000000000000000000000"
    cipher_iv_2 = cipher_iv

    found = b""

    for i in range(1,17):
        print(i)
        for k in range(256):
            # interface_receive(cipher_iv_1)
            # interface_receive(cipher_iv_1 + cipher_iv_2)
            bytes_test = hex(k)[2:].zfill(2)
            cipher = bytes.fromhex(cipher_iv_1)[:16-i].hex() + bytes_test + found.hex() + cipher_iv_2

            res = interface_receive(cipher)
            # if res == {"success": "Your message has been received"}:
            #     # ce qui veut dire que la padding PKCS est correct
            #     found += bytes([k ^ i])
            # else:
            bytes_fin = bytes.fromhex(res["error"].split(": ")[1])[16:][16-i:]
            # print(k, bytes_fin)

            if bytes_fin == bytes([i] * i):

                if i!=16:
                    found = long_to_bytes(bytes_to_long(bytes.fromhex(bytes_test)+found) ^ bytes_to_long(bytes([i] * i)) ^ bytes_to_long(bytes([i+1] * i)))
                else:
                    found = bytes.fromhex(bytes_test)+found
                break
            else:
                continue

    iv = long_to_bytes(bytes_to_long(found) ^ bytes_to_long( bytes([0x10] * 16)))

    flag = bytes.fromhex(interface_get_flag(iv.hex())["plaintext"]).decode()
    return flag



def encrypt_request(plaintext):
    return requests.get(f"https://aes.cryptohack.org/lazy_cbc/encrypt/{plaintext}").json()

def get_flag_request(key):
    return requests.get(f"https://aes.cryptohack.org/lazy_cbc/get_flag/{key}").json()

def receive_request(ciphertext):
    return requests.get(f"https://aes.cryptohack.org/lazy_cbc/receive/{ciphertext}").json()

if __name__ == "__main__":
    """
    un peu de doc
    - https://www.nccgroup.com/research-blog/cryptopals-exploiting-cbc-padding-oracles/
    - https://www.brunorochamoura.com/posts/cbc-padding-oracle/
    
    Il y a deux/trois failles :
        la possibilité d'avoir un oracle de padding qui nous dit si le padding est correct
        le fait que le message d'erreur nous donne la totalité decrypted.hex() dans receive() permet de parser le message d'erreur et 
        de récupérer la portion qui nous interresse (le second block voir 000000..0000 | AES(iv) ):
        # try:
        #     decrypted.decode() # ensure plaintext is valid ascii
        # except UnicodeDecodeError:
        #     return {"error": "Invalid plaintext: " + decrypted.hex()}

        La KEY est utilisé comme IV dans encrypt() et receive() :
        # cipher = AES.new(KEY, AES.MODE_CBC, KEY)

    Attaque : 
        On envoie donc une payload remplie de 0 avec payload =  bytes([0x0] * 16).hex() à  encrypt()
        On recoit donc en retour AES(iv XOR 00000 ...0000) = AES(iv)

        On a plus qu'à mettre en place une padding oracle attack avec receive()
        Cepdenant état donné qu'on ne maitrise pas l'iv, on envoie à receive : 000000..0000 | AES(iv)
        Et on joue sur 000000..0000 byte par byte pour trouver un padding correct (found) car on le contrôle
        On a plus ensuite qu'à en déduire l'iv/key en xorant found avec un bloc completement paddé :
        long_to_bytes(bytes_to_long(found) ^ bytes_to_long( bytes([0x10] * 16)))
    
    En vrai il y avait une solution bcp plus simple bref. En envoyant 000000..0000 | AES(iv), on obtenait de base le bon resultat déchiffré
    ds le message d'erreur
    """

    # ================ Home test ==================
    interface_encrypt = encrypt
    interface_get_flag = get_flag
    interface_receive = receive

    flag = challenge(interface_encrypt, interface_receive, interface_get_flag)
    assert flag == FLAG

    # ================ Cryptohack (attention long) ==================
    interface_encrypt = encrypt_request
    interface_get_flag = get_flag_request
    interface_receive = receive_request

    flag = challenge(interface_encrypt, interface_receive, interface_get_flag)
    assert flag == 'crypto{50m3_p30pl3_d0n7_7h1nk_IV_15_1mp0r74n7_?}'
 