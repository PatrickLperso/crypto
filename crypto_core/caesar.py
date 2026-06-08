
def encrypt(key:int, message:str, offset:int, nb_lettres:int):
    return " ".join(["".join([chr((ord(letter)-offset+key)%nb_lettres+offset) for letter in word]) for word in message.split(" ")])

def decrypt(key:int, cipher:str, offset:int, nb_lettres:int):
    return " ".join(["".join([chr((ord(letter)-offset-key)%nb_lettres+offset) for letter in word]) for word in cipher.split(" ")])

def bruteforce(cipher:str, offset:int, nb_lettres:int):
    return [decrypt(key, cipher, offset, nb_lettres) for key in range(nb_lettres)]