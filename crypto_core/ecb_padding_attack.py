import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import random
import json
import string
import requests
from tqdm import tqdm

class Ecb_padding_attack():
    def __init__(self):
        self.FLAG="il_etait_UneFOIS12viela8be"
        self.KEY=os.urandom(16)
        self.nb_request=0

    def encrypt(self, plaintext):
        plaintext = bytes.fromhex(plaintext)

        padded = pad(plaintext + self.FLAG.encode(), 16)
        cipher = AES.new(self.KEY, AES.MODE_ECB)
        try:
            encrypted = cipher.encrypt(padded)
        except ValueError as e:
            return {"error": str(e)}

        return encrypted.hex()

    def request_url(self, url, payload):
        self.nb_request+=1

        request = requests.get(f'{url}/ecb_oracle/encrypt/{payload}')
        if not request.ok:
            text = "Request to the server wasn't succesful, it's likely because"
            text += f"\n the nb_letters_batch is to high. Try reducing it. Especially, if your length_flag is big enough."
            raise Exception(text)

        return bytes.fromhex(request.json()["ciphertext"])

    def length_flag(self, url=''):

        plaintext="0".encode().hex()
        payload = "".join(plaintext)

        if url:
            cipher = self.request_url(url, payload)
        else:
            cipher = bytes.fromhex(self.encrypt(payload))
        
        inital_length_cipher=len(cipher)
        
        # We can't send a payload empty so we can't compare k=0 and k=1 
        for k in range(2,17):
            plaintext=(k*"0").encode().hex()
            payload = "".join(plaintext)
            if url:
                cipher = self.request_url(url, payload)
            else:
                cipher = bytes.fromhex(self.encrypt(payload))
            if len(cipher)!=inital_length_cipher:
                length_flag = inital_length_cipher-k
                break
        return length_flag

    def optimized(self, letters:str, letters_found:str, size_buffer:int, url:str, key, nb_letters_batch=16):

        letters_list=list(letters)

        #========= a bit of optimization here is still possible but overall performance are great ===========
        # we build 00000000000000a + 00000000000000b + 00000000000000c + ... 00000000000000i
        # we build 0000000000000ia + 0000000000000ib + 0000000000000ic + ... 0000000000000il
        # we build 000000000000ila + 000000000000ilb + 000000000000ilc + ... 000000000000il_

        # if length_flag >16, we build padded blocks of 0 until their sizes if over the length of the flag
        # if the flag is "il_etait_UneFOIS12vielabe"
        # we build 00000000000000000000000000000a + 00000000000000000000000000000b + 00000000000000000000000000000c
        # we build 0000000000000000000000000000ia + 0000000000000000000000000000ib + 0000000000000000000000000000ic
        # (...)
        # we build 000000000il_etait_UneFOIS12via + 000000000il_etait_UneFOIS12vib + 000000000il_etait_UneFOIS12vic + 000000000il_etait_UneFOIS12vie
        
        mapping_dict={}
        res=""
        if url:
            nb_iterations = len(letters)//nb_letters_batch+1

            # we will construct a dictionnary mapping the ciphertexts to letter in letters 

            #               we build the dictionnary
            # b'\xac\x17\xd4\xd8\x04\xef\x17\xae!\x04\xc0\x8aT\xeb\xbbC':'a', 
            # b'\x02#\x12\x07j 22\xdf\xab\xe9E\x95\xc4\xacZ'            :'b'
            # b'\x...'                                                  :'c'

            for k in range(nb_iterations):

                # we take the letters in batches of length nb_letters_batch
                list_letter_batch = list(letters_list[k*nb_letters_batch:min((k+1)*nb_letters_batch, len(letters_list))])

                # we build the plaintext & the payload
                plaintext=list(map(lambda letter:((size_buffer-1-len(letters_found))*"0"+f"{letters_found}{letter}").encode().hex(),list_letter_batch ))
                payload = "".join(plaintext)

                # we send the request and recieve the cipher
                cipher = self.request_url(url, payload)

                # we build the dictionnary
                mapping_dict_inter = dict(zip([cipher[k*size_buffer:(k+1)*size_buffer] for k in range(len(cipher)//size_buffer)], list_letter_batch))
                mapping_dict.update(mapping_dict_inter)

                # if the key is in the mapping dictionnary keys we can stop constructing the dictionnary, we have our letter
                if key in mapping_dict.keys():
                    break

        else: # local version (in reality we can suppress the if else but for readability it's here)
            plaintext=list(map(lambda letter:((size_buffer-1-len(letters_found))*"0"+f"{letters_found}{letter}").encode().hex(), list(letters_list)))
            payload = "".join(plaintext)
            cipher = bytes.fromhex(self.encrypt(payload))
            mapping_dict = dict(zip([cipher[k*size_buffer:(k+1)*size_buffer] for k in range(len(cipher)//size_buffer)], letters_list))

        if key in mapping_dict.keys():
            res=mapping_dict[key]
        else:
            raise Exception("The letter wasn't found")

        # we send the letter found
        return res

    def request_oracle(self, length_flag, letters, url='', nb_letters_batch=16):
        size_buffer = (length_flag//16+1)*16
        letters_found=""

        for k in range(length_flag):

            payload=((size_buffer-1-k)*"0").encode().hex()
            if url:
                cipher1 = self.request_url(url, payload)
            else:
                cipher1 = bytes.fromhex(self.encrypt(payload))
            key=cipher1[:size_buffer]
            letters_found += self.optimized(letters, letters_found, size_buffer, url, key, nb_letters_batch)

            print(letters_found)
        if url:
            print(f"nb_request:{self.nb_request}")
        return letters_found

    def request_oracle_stupid(self, length_flag, letters, url=""):
        # This is not optimized, because thanks to ECB, we can"t the ecryption scheme of multiple letters in a single request
        # Here we are trying one letter wih one request

        letters_found = ""
        for k in range(length_flag):
            for letter in letters:

                payload=(((length_flag//16+1)*16-1-k)*"0").encode().hex()
                if url:
                    cipher1 = self.request_url(url, payload)
                else:
                    cipher1 = bytes.fromhex(self.encrypt(payload))

                payload=(((length_flag//16+1)*16-1-k)*"0"+letters_found+f"{letter}").encode().hex()
                if url:
                    cipher2 = self.request_url(url, payload)
                else:
                    cipher2 = bytes.fromhex(self.encrypt(payload))

                if cipher1[:(16*length_flag//16+1)]==cipher2[:(16*length_flag//16+1)]:
                    letters_found+=letter
                    print(letters_found)
                    break
        if url:
            print(f"nb_request:{self.nb_request}")
        return letters_found

    


