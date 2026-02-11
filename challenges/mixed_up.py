from hashlib import sha256
import os

from pwn import *
import json

r = remote('socket.cryptohack.org', 13402)

def interface(data:dict):
    # on envoie la requete 
    request = json.dumps(data).encode()
    r.sendline(request)
    # on renvoie la réponse
    line = r.readline()
    return json.loads(line.decode())

FLAG = b"crypto{flag??????????gg????????????????}"


def _xor(a, b):
    return bytes([_a ^ _b for _a, _b in zip(a, b)])

def _and(a, b):
    return bytes([_a & _b for _a, _b in zip(a, b)])

def shuffle(mixed_and, mixed_xor):
    # super important
    return bytes([mixed_xor[i%len(mixed_xor)] for i in mixed_and])


class Challenge():
    def __init__(self):
        self.before_input = "Oh no, how are you going to unmix this?\n"

    def challenge(self, msg):
        if "option" not in msg:
            return {"error": "You must send an option to this server."}

        elif msg["option"] == "mix":
            if not "data" in msg:
                return {"error": "Please send hex-encoded data"}

            data = bytes.fromhex(msg["data"])
            if len(data) < len(FLAG):
                data += os.urandom(len(FLAG) - len(data))

            # ici on contrôle bien 
            mixed_and = _and(FLAG, data)

            # pas la main ici ca renvoie un truc imprévisible car xor avec os.urandom(len(FLAG)
            mixed_xor = _xor(_xor(FLAG, data), os.urandom(len(FLAG)))

            very_mixed = shuffle(mixed_and, mixed_xor)
            super_mixed = sha256(very_mixed).hexdigest()

            return {"mixed": super_mixed}

        else:
            return {"error": "Invalid option"}

def resolve_challenge(interface):
    # data1 = bytes([97]*39).hex()
    # res1 = interface({"option":"mix", "data":data1})

    # data2 = (bytes([97]*38) + bytes([0])).hex()
    # res2 = interface({"option":"mix", "data":data2})
    # print(res1)
    # print(res2)
    # print("toto")

    flag_length_min = 10
    flag_length_max = 100

    hash_list = []
    for size_flag in range(flag_length_min, flag_length_max):
        for byte_index in range(256):
            data_test = bytes([byte_index]*size_flag)
            hash_list.append(sha256(data_test).hexdigest())

    flag = b""
    for i in range(flag_length_max):
        ord_caracter = 0

        # on itère sur les puissance de 2 : 1,2,4,8,16,32,64,128
        for j in range(8):
            
            bytes_ = [0]*flag_length_max
            bytes_[i] = 2**j
            data = bytes(bytes_)
            
            # il y a une chance non négligeable (1/256) d'avoir un faux négatif 
            # Pour négliger ce risque, on fait 3 requêtes 
            # Dès qu'il y a un positif on break
            for request in range(3):
                # on check si le hash obtenu est dans la table précompute 
                # des hashs de chaines de bytes identiques, si non présent, alors le byte contient 2**j
                # sinon on retente car il y a un risque de faux négatif avec une proba de 1/256 (pas de faux positif par contre)
                hash_inter = interface({"option":"mix", "data":data.hex()})["mixed"]
                if hash_inter not in hash_list:
                    ord_caracter += 2**j
                    break
        
        flag += bytes([ord_caracter])
        print(flag)

        if flag[-1]==125:
            break

    return flag
    

if __name__ == "__main__":
    # L'attaque consite à se rendre compte que l'on peut leaker bit par bit le Flag
    # car si on envoie 
    # [2**i,0,0,0,..................., 0]
    # le résultat de :
    """
    mixed_and = _and(FLAG, data)
    """
    # sera 
    # [1,0,0,0,..................., 0] si et seulement si FLAG[0] (1er byte du flag) contient 2**i 
    # [0,0,0,0,..................., 0] sinon 
    # de fait en sortie de :
    """
    shuffle(mixed_and, mixed_xor)
    """
    # on aura soit 
    # [rd(1),rd(0),rd(0),rd(0),..................., rd(0)], le premier byte change 
    # ou bien :
    # [rd(0),rd(0),rd(0),rd(0),..................., rd(0)], tous les bytes sont identiques
    # On va donc bruteforcer la décomposition binaire du flag grâce à cette bijection

    # rd fait référence à un vecteur de valeur aléatoire inconnu (rd(0) au premier byte )
    # rd est ce qui est sort de mixed :
    """
    mixed_xor = _xor(_xor(FLAG, data), os.urandom(len(FLAG)))
    very_mixed = shuffle(mixed_and, mixed_xor)
    """
    # puis l'oracle nous renvoie soit :
    # SHA256([rd(1),rd(0),rd(0),rd(0),..................., rd(0)]) => SHA256(Y, X, X, X .........., X)
    # SHA256([rd(0),rd(0),rd(0),rd(0),..................., rd(0)]) => SHA256(X, X, X, X .........., X)
    # On va donc précalculer une table de tous les hashs possibles de type :
    # SHA256([X,X,X,X,...................,X])
    # si le hash recupéré auprès de l'oracle n'est pas dans cette table précalculée, on est assuré d'avoir un hash de type :
    # [rd(1),rd(0),rd(0),rd(0),..................., rd(0)], et donc que data[0] contient 2**i 
    """
    hash_inter = interface({"option":"mix", "data":data.hex()})["mixed"]
    if hash_inter not in hash_list:
        ord_caracter += 2**j
        break
    """
    # sinon on retente auprès de l'oracle car il y a une risque de faux négatif (mais pas de faux positifs) car 
    # on ne maitrise pas os.urandom(len(FLAG) dans 
    """
    mixed_xor = _xor(_xor(FLAG, data), os.urandom(len(FLAG)))
    """
    # et donc que rd(0) peut être égal à rd(1) avec 1/256 ce qui est indistinguable de [rd(0),rd(0),rd(0),rd(0),..................., rd(0)]

    # La longueur du flag n'est pas un problème car le challenge utilise des zip donc on peut juste envoyer 
    # de longues chaînes de bytes sans influer sur le résultat et on peut 
    # précompute une table des hashs dont tous les bytes sont identiques en faisant varier 
    # la longueur des chaines de bytes identiques entre une longueur minimum et maximum
    """
    flag_length_min = 10
    flag_length_max = 100

    hash_list = []
    for size_flag in range(flag_length_min, flag_length_max):
        for byte_index in range(256):
            data_test = bytes([byte_index]*size_flag)
            hash_list.append(sha256(data_test).hexdigest())
    """

    #============= Local ============
    challenge_ = Challenge()
    interface_ = challenge_.challenge

    flag = resolve_challenge(interface_)
    assert flag == FLAG

    #============= Cryptohack ============

    r.readline()
    interface_ = interface
    flag = resolve_challenge(interface_)
    assert flag == b'crypto{y0u_c4n7_m1x_3v3ry7h1n6_1n_l1f3}'
