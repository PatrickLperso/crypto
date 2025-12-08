
def encrypt(key:int, message:str, offset:int, nb_lettres:int):
    return " ".join(["".join([chr((ord(letter)-offset+key)%nb_lettres+offset) for letter in word]) for word in message.split(" ")])

def decrypt(key:int, cipher:str, offset:int, nb_lettres:int):
    return " ".join(["".join([chr((ord(letter)-offset-key)%nb_lettres+offset) for letter in word]) for word in cipher.split(" ")])

def bruteforce(cipher:str, offset:int, nb_lettres:int):
    return [decrypt(key, cipher, offset, nb_lettres) for key in range(nb_lettres_)]

if __name__ == "__main__":
    # Paramètres 
    #Attention n'utiliser que des minuscules 

    key_=15
    message_="tu quoque mi fili"
    offset_=97 # indexes of ASCII carcaters don't start at 0
    nb_lettres_=26 # for modulo operations

    # Encryption
    cipher_ = encrypt(key_, message_, offset_, nb_lettres_)
    assert cipher_ == "ij fjdfjt bx uxax"

    #Decryption
    assert message_==decrypt(key_, cipher_, offset_, nb_lettres_)

    #Bruteforce
    possiblities=bruteforce(cipher_, offset_, nb_lettres_)
    key_crack = possiblities.index(message_)
    assert message_ in possiblities
    assert key_==key_crack

    print("\n".join(possiblities))
