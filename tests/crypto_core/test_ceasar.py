
from crypto_core.caesar import encrypt, decrypt, bruteforce

def test_encrypt():
    # Paramètres 
    #Attention n'utiliser que des minuscules 

    key_=15
    message_="tu quoque mi fili"
    offset_=97 # indexes of ASCII carcaters don't start at 0
    nb_lettres_=26 # for modulo operations

    # Encryption
    cipher_ = encrypt(key_, message_, offset_, nb_lettres_)
    assert cipher_ == "ij fjdfjt bx uxax"

def test_decrypt():
    key_=15
    message_="tu quoque mi fili"
    offset_=97 # indexes of ASCII carcaters don't start at 0
    nb_lettres_=26 # for modulo operations

    cipher_ = "ij fjdfjt bx uxax"
    assert message_==decrypt(key_, cipher_, offset_, nb_lettres_)

def test_bruteforce():
    key_=15
    message_="tu quoque mi fili"
    offset_=97 # indexes of ASCII carcaters don't start at 0
    nb_lettres_=26 # for modulo operations
    cipher_ = "ij fjdfjt bx uxax"

    possiblities=bruteforce(cipher_, offset_, nb_lettres_)
    key_crack = possiblities.index(message_)

    assert key_==key_crack