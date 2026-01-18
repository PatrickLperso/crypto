from Crypto.Util.number import bytes_to_long, long_to_bytes
import requests
import os
from tqdm import tqdm 
import gmpy2
import base64
import jwt
from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

FLAG = "crypto{flag}"

# Private key generated using: openssl genrsa -out rsa-or-hmac-2-private.pem 2048
path_private_key = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ressources/rsa-or-hmac-2-private.pem')
with open(path_private_key, 'rb') as f:
   PRIVATE_KEY = f.read()

# Public key generated using: openssl rsa -RSAPublicKey_out -in rsa-or-hmac-2-private.pem -out rsa-or-hmac-2-public.pem
path_public_key = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ressources/rsa-or-hmac-2-public.pem')
with open(path_public_key, 'rb') as f:
   PUBLIC_KEY = f.read()

def authorise(token):
    try:
        decoded = jwt.decode(token, PUBLIC_KEY, algorithms=['HS256', 'RS256'])
    except Exception as e:
        return {"error": str(e)}

    if "admin" in decoded and decoded["admin"]:
        return {"response": f"Welcome admin, here is your flag: {FLAG}"}
    elif "username" in decoded:
        return {"response": f"Welcome {decoded['username']}"}
    else:
        return {"error": "There is something wrong with your session, goodbye"}

def create_session(username):
    encoded = jwt.encode({'username': username, 'admin': False}, PRIVATE_KEY, algorithm='RS256')
    return {"session": encoded}

def create_session_request(username):
    return requests.get(f"https://web.cryptohack.org/rsa-or-hmac-2/create_session/{username}/").json()

def authorise_request(token):
    return requests.get(f"https://web.cryptohack.org/rsa-or-hmac-2/authorise/{token}/").json()

def pkcs1_v1_5_em(hash_bytes: bytes, key_size_bytes: int) -> bytes:
    # Merci chatgpt pour le padding pkcs1_v5

    # 2️⃣ Préfixe DER fixe pour SHA-256 (DigestInfo)
    SHA256_DER_PREFIX = bytes.fromhex(
        "3031300d060960864801650304020105000420"
    )
    T = SHA256_DER_PREFIX + hash_bytes  # 51 octets

    # 3️⃣ Calculer la longueur du padding PS
    ps_length = key_size_bytes - len(T) - 3
    if ps_length < 8:
        raise ValueError("Clé RSA trop courte pour PKCS#1 v1.5")

    # 4️⃣ Construire PS = FF...FF
    PS = b'\xff' * ps_length

    # 5️⃣ Construire EM = 00 || 01 || PS || 00 || T
    res = b'\x00\x01' + PS + b'\x00' + T
    return res

def test_signing(message, jwt):
    private_key = serialization.load_pem_private_key(PRIVATE_KEY, password=None)
    public_key = private_key.public_key()

    private_numbers = private_key.private_numbers()
    public_numbers = public_key.public_numbers()

    d = private_numbers.d

    sign1 = int.from_bytes(base64.urlsafe_b64decode(jwt.split(".")[2] + '=='), 'big')

    assert pow( int.from_bytes(m1_pad, 'big'),d,n) == sign1

def challenge(interface_session, interface_authorise):

    username1 = "toto"
    username2 = "pepe"

    jwt1 = interface_session(username1)["session"]
    jwt2 = interface_session(username2)["session"]

    m1 = sha256(".".join(jwt1.split(".")[:2]).encode()).digest()  # base64.urlsafe_b64encode(json.dumps({'username': username1, 'admin': False}).encode())
    m2 = sha256(".".join(jwt2.split(".")[:2]).encode()).digest()

    m1_pad = gmpy2.mpz(int.from_bytes(pkcs1_v1_5_em(m1, 256), 'big'))
    m2_pad = gmpy2.mpz(int.from_bytes(pkcs1_v1_5_em(m2, 256), 'big'))

    # on peut tester que la signature RSA est bien absolument identique à celle calculé par RS256
    # test_signing(m1_pad, jwt1)

    # Nécessaire d'utiliser gmpy2 pour obtenir un résultat
    sign1 = gmpy2.mpz(int.from_bytes(base64.urlsafe_b64decode(jwt1.split(".")[2] + '=='), 'big'))
    sign2 = gmpy2.mpz(int.from_bytes(base64.urlsafe_b64decode(jwt2.split(".")[2] + '=='), 'big'))

    # gcd(se1−m1,se2−m2)=gcd(k1,k2)n
    # on sait que n sera forcement egal à 2048 bit

    e = 65537 

    sign1_pow = pow(sign1,e)
    print("sign1_pow")
    sign2_pow = pow(sign2,e)
    print("sign2_pow")

    # gcd(k1,k2) va être très petit globalement egal à 1
    gcd_k1_k2_n = gmpy2.gcd( sign1_pow - m1_pad,  sign2_pow - m2_pad)
    print(f"gcd_k1_k2_n ok")
    
    # on est censé avoir un produit de grands nombres premiers pour n
    divisors = []
    for k in range(1, 100):
        if gcd_k1_k2_n%k==0:
            gcd_k1_k2_n = gcd_k1_k2_n// k

    n = int(gcd_k1_k2_n)

    
    public_numbers = rsa.RSAPublicNumbers(e, n)
    public_key = public_numbers.public_key()

    pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.PKCS1)
    public_key_text = pem.decode()

    token = jwt.encode({'username': "taratata", 'admin': True}, public_key_text, algorithm='HS256')

    res  = interface_authorise(token)["response"].split("flag: ")[1]
    return res

if __name__ == "__main__":
    # documentation sur la récupération d'une clé RSA à partir de la signature
    # https://blog.ploetzli.ch/2018/calculating-an-rsa-public-key-from-two-signatures/
    # https://crypto.stackexchange.com/questions/26188/rsa-public-key-recovery-from-signatures

    # Concrètement, on va extraire la clé publique RSA de deux signatures RSA car le padding est déterministe 
    # Ensuite quand on a la clé on doit recréer le contenu du fichier pem qui sera lu par le jwt.decode 
    # pour le réutiliser dans le jwt.encode comme clé symétrique utilisée par HS256

    interface_session = create_session
    interface_authorise = authorise

    flag = challenge(interface_session, interface_authorise)
    assert flag == FLAG

    interface_session = create_session_request
    interface_authorise = authorise_request

    flag = challenge(interface_session, interface_authorise)
    assert flag == "crypto{thanks_silentsignal_for_inspiration}"




