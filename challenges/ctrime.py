from Crypto.Cipher import AES
from Crypto.Util import Counter
import zlib

import os 
from Crypto.Util.number import bytes_to_long, long_to_bytes
import requests
from collections import Counter as Counter_items
from tqdm import tqdm
import statistics

KEY = os.urandom(16)

# le flag a été pris exprès pour qu'il n'y ait pas de répétitions
FLAG = "crypto{CAMPAGNE_ILEES_PARADIS}"

# exemple avec répétitions
# FLAG = "crypto{ANTICONSTITUTIONELLEMENT}"


def encrypt(plaintext):
    plaintext = bytes.fromhex(plaintext)

    iv = int.from_bytes(os.urandom(16), 'big')
    cipher = AES.new(KEY, AES.MODE_CTR, counter=Counter.new(128, initial_value=iv))
    encrypted = cipher.encrypt(zlib.compress(plaintext + FLAG.encode()))

    return {"ciphertext": encrypted.hex()}

def challenge(interface_encrypt):
    
    # =============== Attention je suppose que le flag commence par crypt
    found=b"crypto{"

    length = len(bytes.fromhex(interface_encrypt("00")["ciphertext"])) -1

    while bytes([found[-1]])!=b"}":
        data = []

        # supposons on a trouve ca commence par c
        for k in tqdm(range(256)):
            if len(found)<=2:
                # Pour les premières lettre car la compression se déclenche si une chaine de 3 octects est identique à une autre 
                size_repetition=4
            else:
                size_repetition=2
            payload = bytes((list(found)+[k])*size_repetition).hex()

            res = bytes.fromhex(interface_encrypt(payload)["ciphertext"])
            # print(len(res), k, bytes([k]))
            data.append([k,len(res)])

        median_number_bytes = int(statistics.median(list(map(lambda x:x[1], data))))
        filtre = list(filter(lambda x:x[1]<median_number_bytes, data))

        if len(filtre)==1:
            # s'il y a une seule lettre qui fait réduire la taille de la réponse, c'est probablement la bonne
            found+=bytes([filtre[0][0]])
        else:
            # S'il y a des répétitions ce genre de trucs on peut avoir des faux positifs et plusieurs letres réduisent la taille de la réponse
            # Dans ce cas on laisse l'attaquant choisir (demande un pattern prédicitif évidemment )
            # Techniquement on pourrait faire du try sur les candidats jusqu'au prochain caractère mais bon ....
            # ex dans "crypto{ANTICONSTITUTIONELLEMENT}"
            # A l'étape "crypto{ANTI", on nous demande si on choisit :
                # "crypto{ANTIC"
                # "crypto{ANTIU"
                # "crypto{ANTIT
            # car TIC TIU et TIT sont tous les 3 des motifs qui existent dans AN TIC ONS TIT U TIO NELLEMENT
            # et donc de fait les 3 motifs permettent de réduire la taille de la requête.

            print(filtre)
            print([ bytes([k[0]]) for k in filtre ])
            indice = int(input("Prendre l'indice du caractère le plus probable:"))
            found+=bytes([filtre[indice][0]])

        print(found)
    return found


def encrypt_request(plaintext):
    return requests.get(f"https://aes.cryptohack.org/ctrime/encrypt/{plaintext}").json()

if __name__ == "__main__":
    # === Documentation ===
    # https://shainer.github.io/crypto/2017/01/02/crime-attack.html
    # https://docs.google.com/presentation/d/11eBmGiHbYcHR9gL5nDyZChu_-lCa2GizeuOfaLU2HOU/edit?slide=id.g1e3070b2_2_1#slide=id.g1e3070b2_2_1
    # https://sancy.iut.uca.fr/~lafourcade/2021PreZSecu/TLS_attacks_Benloulou_Deschamps_Ouahrani_Rodet_Lagier_Bensaber.pdf
    # https://security.stackexchange.com/questions/19911/crime-how-to-beat-the-beast-successor

    # L'idée de l'attaque est assez simple mais sa mise en place complète plus difficile
    # On peut injecter des données dans plaintext avec :
    # encrypted = cipher.encrypt(zlib.compress(plaintext + FLAG.encode()))

    # Or la fonction de compression va forcement compresser les patterns répétables 
    # on peut ainsi tenter :
    # - crypt + a + crypto{secret}
    # - crypt + b + crypto{secret}
    # - crypt + c + crypto{secret}
    # - [...]
    # - crypt + o + crypto{secret}
    # et voir la réponse la plus courte ( ex : crypt + o + crypto{secret}), et ainsi en déduire que le caractère o fait parti du secret
    # et ainsi de suite jusqu'à atteindre le caractère de terminaison }
    # Ce qui peut être source de faux positifs : les chaines de caracères qui se répètent 
    # l'algo de compression identifie les patterns identique dans une fenetre (de 32KB selon chatgpt et 256/512 selon d'autres sources)
    # mais je suis plutôt tenter de croire après plusieurs essais ce que dis ChatGpt 
    # dès qu'il a un pattern qui se reproduit il remplace celui-ci par une référence au pattern précédenent indiquant le nombre d'octet de décalage + la longueuer du pattern 
    # On doit donc faire une attaque en O(n) n le nombre d'octets possibles
    # en tout cas pour l'algo deflate LZ77 (voir slide 9 de https://docs.google.com/presentation/d/11eBmGiHbYcHR9gL5nDyZChu_-lCa2GizeuOfaLU2HOU/edit?slide=id.g1d134dff_1_30#slide=id.g1d134dff_1_30)
    # L'attaque peut meme passer en O(log n) https://x.com/julianor/status/245943430570704896

    print("Attention On suppose que le flag commence par crypt")

    # ====== Local test (demande une interaction humaine pour enlever certains faux positifs ======
    print(FLAG.encode()[0])
    interface_encrypt = encrypt
    flag = challenge(interface_encrypt)
    assert flag == FLAG.encode()

    # ====== online test ======
    # ======= Marche parfaitement contrairement au test offline =========
    # interface_encrypt = encrypt_request
    # flag = challenge(interface_encrypt)
    # assert flag == b"crypto{CRIME_571ll_p4y5}"