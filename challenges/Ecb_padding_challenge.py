import sys 
import os 

# Ajout du répertoire eliptic curve
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "general_crypto"))

from Ecb_padding_attack import Ecb_padding_attack

if __name__ == "__main__":
    # ======= ECB padding oracle attack on cryptohack ==========
    # Le paramètre nb_letters_batch est important si envoie trop de lettre à tester au serveur en meme temps ca fait crasher le serveur
    ecb = Ecb_padding_attack()

    BASE_URL = 'https://web.cryptohack.org/'
    letters="abcdefghijklmnopqrstuvwxyz0123456789_{}"


    length_flag = ecb.length_flag(url=BASE_URL)
    letters_found = ecb.request_oracle(length_flag, letters, url=BASE_URL, nb_letters_batch=27)
    assert letters_found.startswith("crypto")

    # ======= ECB padding oracle attack slower on "cryptohack ==========
    # ecb = Ecb_padding_attack()

    # BASE_URL = 'https://web.cryptohack.org/'
    # letters="abcdefghijklmnopqrstuvwxyz0123456789_{}"

    # length_flag = ecb.length_flag(url=BASE_URL)
    # letters_found = ecb.request_oracle_stupid(length_flag, letters, url=BASE_URL)
    # assert letters_found.startswith("crypto")