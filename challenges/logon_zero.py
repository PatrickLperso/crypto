#!/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long
from os import urandom

FLAG = "crypto{???????????????????????????????}"


import os 
from Crypto.Util.number import bytes_to_long, long_to_bytes
from pwn import *
import json

r = remote('socket.cryptohack.org', 13399)


class CFB8:
    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        IV = urandom(16)
        cipher = AES.new(self.key, AES.MODE_ECB)
        ct = b''
        state = IV
        for i in range(len(plaintext)):
            b = cipher.encrypt(state)[0]
            c = b ^ plaintext[i]
            ct += bytes([c])
            state = state[1:] + bytes([c])
        return IV + ct

    def decrypt(self, ciphertext):

        # le chiffrement réalise 
        # bytes([cipher.encrypt(ciphertext[i:i+16])[0] ^ ciphertext[16:][i] for i in range(len(ciphertext[16:]))])
        # bytes([cipher.encrypt(ciphertext[i:i+16])[0] ^ ct[i] for i in range(len(ct))])
        # bytes([cipher.encrypt((IV + ct)[i:i+16])[0] ^ ct[i] for i in range(len(ct))])

        # moi je veux que bytes([cipher.encrypt((IV + ct)[i:i+16])[0] ^ ct[i] for i in range(len(ct)-4, len(ct))]) == b'\x00\x00\x00\x00'
        # impossible ?

        IV = ciphertext[:16]
        ct = ciphertext[16:]
        cipher = AES.new(self.key, AES.MODE_ECB)
        pt = b''
        state = IV
        for i in range(len(ct)):
            b = cipher.encrypt(state)[0] # on prend le premier byte ??????????????????????????
            c = b ^ ct[i] # on xor b avec le ième bytes de ciphertext[16:]
            pt += bytes([c]) # on transforme ca sous forme de byte
            state = state[1:] + bytes([ct[i]]) # fenetre glissante ciphertext[i:i+16]

        return pt

class Challenge():
    def __init__(self):
        self.before_input = "Please authenticate to this Domain Controller to proceed\n"
        self.password = urandom(20)
        self.password_length = len(self.password)
        self.cipher = CFB8(urandom(16))

    def challenge(self, your_input):
        if your_input['option'] == 'authenticate':
            if 'password' not in your_input:
                return {'msg': 'No password provided.'}
            your_password = your_input['password']
            if your_password.encode() == self.password:
                self.exit = True
                return {'msg': 'Welcome admin, flag: ' + FLAG}
            else:
                return {'msg': 'Wrong password.'}

        if your_input['option'] == 'reset_connection':
            self.cipher = CFB8(urandom(16))
            return {'msg': 'Connection has been reset.'}

        if your_input['option'] == 'reset_password':
            if 'token' not in your_input:
                return {'msg': 'No token provided.'}
            token_ct = bytes.fromhex(your_input['token'])
            if len(token_ct) < 28:
                return {'msg': 'New password should be at least 8-characters long.'}

            token = self.cipher.decrypt(token_ct)
            new_password = token[:-4]
            self.password_length = bytes_to_long(token[-4:])
            self.password = new_password[:self.password_length]

            if self.password== b"":
                print(self.password, len(self.password))

            return {'msg': 'Password has been correctly reset.'}

def resolve_challenge(interface_challenge):


    # challenge un peu pourri mais en gros 
    # on envoie un iv + ct dans 
    # token = bytes([cipher.encrypt((IV + ct)[i:i+16])[0] ^ ct[i] for i in range(len(ct)-4, len(ct))]) 
    # sauf que c'est du ECB donc on peut envoyer le même bit iv + ct = "00000000000000000000000000"
    # donc on aura toujours un résultalt en sportie qui sera indéterminé mais ce sera toujours les même bits
    # on pourrait tester tous les bits sauf que dans challenge() notre mot de passe va dans encode:
    # your_password.encode() == self.password 
    # Pour dépaser ça on remarque que :
    # le password = token[:-4][:bytes_to_long(token[-4:])]
    # donc si token = "0000000000000000" qui arrive si AES(byte) ^ byte = 0
    # alors password = token[:-4][:0] = b''
    # on peut donc envoyer challenge("") car "".encode() == b"" est vrai
    # on tente donc tous les bytes possibles d'envoyer "00000000000" puis "111111111111111":
    # en éspérant tomber sur AES(byte) ^ byte = 0 (car AES(byte) nous donne un résultalt imprévisible)
    # et on se logger avec interface_challenge({'option' : "authenticate", "password" : ""})
    # on répète jusqu'à être loggué 
    # si on a épuise tous les bytes, on demande interface_challenge({'option' : "reset_connection"})
    # pour générer une nouvelle clé pour AES t à nouveau on teste toutes les combinaisons pour espérer tomber sur 
    # AES(byte) ^ byte = 0 

    # Note : on pouvait faire mieux et tenter tous les passwords donc l'écriture était possible avec des caractères valides:
    # b'CCCCCCCC' 8
    # b'>>>>>>>>' 8
    # b'LLLLLLLL' 8
    # b'SSSSSSSS' 8
    # b'TTTTTTTT' 8
    # b'WWWWWWWW' 8
    # b'jjjjjjjj' 8
    # b'22222222' 8
    # b'\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f' 8
    # b'::::::::' 8
    # b'&&&&&&&&' 8
    # b'CCCCCCCC' 8
    # b'KKKKKKKK' 8
    # b'hhhhhhhh' 8
    # b'########' 8
    # b'^^^^^^^^' 8
    # b'IIIIIIII' 8
    # b'++++++++' 8
    # b'zzzzzzzz' 8
    # b'^^^^^^^^' 8
    # b'UUUUUUUU' 8
    # b'||||||||' 8

    # En l'occurence cela veut dire qu'il y a 50% de casser le password peut importe celui ci car s'il se trouve dans la moitie des bytes sont des caractères UTF8 valides alors on 
    # bytes([k]*28).decode() est une opération valide et on peut envoyer une chaine de caractère valide pour 
    # if your_password.encode() == self.password:

    # for k in range(128): # la liste des chaines de caractères possibles à envoyer
    #    print(k, 28*chr(k), bytes([k]*28).decode(), bytes([k]*28), bytes([k]*28).decode().encode()== bytes([k]*28))

    # bytes([127]*28).decode() # résultalt valide
    # '\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f'

    # bytes([128]*28).decode() # résultalt invalide
    # Traceback (most recent call last):
    # File "<stdin>", line 1, in <module>
    # UnicodeDecodeError: 'utf-8' codec can't decode byte 0x80 in position 0: invalid start byte

    # dans mon cas je me suis concentré sur b'' == b''


    compteur = 1

    flag =""
    while flag =="":
        print(compteur)

        # on a aucune garante que Aes(byte) ^ bytes = 0
        # on réinitalise la clé tant que ca marche pas  
        interface_challenge({'option' : "reset_connection"})
        for k in range(256):
            interface_challenge({'option' : "reset_password", "token" : bytes([k]*28).hex()})

            res = interface_challenge({'option' : "authenticate", "password" : ""})
            if res == {'msg': 'Wrong password.'}:
                continue
            else:
                flag = res["msg"].split(", flag: ")[1]
                break
        compteur+=1
    return flag

def interface(data:dict):
    # on envoie la requete 
    request = json.dumps(data).encode()
    r.sendline(request)
    # on renvoie la réponse
    line = r.readline()
    return json.loads(line.decode())


if __name__ == "__main__":

    # ========= challenge offline ==========
    challenge = Challenge()
    interface_challenge = challenge.challenge

    flag = resolve_challenge(interface_challenge)
    assert flag == FLAG

    # ========= challenge cryptohack ==========
    print(r.readline())
    interface_challenge = interface
    flag = resolve_challenge(interface_challenge)
    assert flag == "crypto{Zerologon_Windows_CVE-2020-1472}"

