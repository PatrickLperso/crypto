import hashlib
import json
import string
from ecdsa import SigningKey
import Crypto
from Crypto.Util.number import *
import requests

# En gros on utilise NIST192p, et la fonction de hash est 
# pétée donc au dela de 192 bits le message est pas pris en compte 
# Donc on signe un message classique puis on rajoute ce qu'veut

if __name__ == "__main__":
    BASE_URL = 'https://web.cryptohack.org/digestive/'

    username="blablatruc"
    assert len(str({"admin": False, "username": username}))*8 > 192
    #on se rend ompte que tout ce qu'on envoie est de base au debla de 192 bits
    # a partir de {"admin": false, "usern on est à 192 bits

    response = requests.get(f'{BASE_URL}/sign/{username}').json()

    # on rajoute ce qu'on veut tout en format un json correcte, on est au dela de 192 bits de toute manière
    msg = response['msg'][:-1]+', "admin": true}'
    signature=response["signature"]

    response = requests.get(f'{BASE_URL}/verify/{msg}/{signature}/').json()
    print(f"flag : {response["flag"]}")