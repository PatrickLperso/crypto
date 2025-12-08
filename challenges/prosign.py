from pwn import *
import json
import codecs
import base64
 
import Crypto
from Crypto.Util.number import *

import hashlib
from Crypto.Util.number import bytes_to_long, long_to_bytes
from ecdsa.ecdsa import Public_key, Private_key, Signature, generator_192
from datetime import datetime
from random import randrange
import time 

g = generator_192
n = g.order()


r = remote('socket.cryptohack.org', 13381, level = 'debug')

def json_recv():
    line = r.readline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    r.sendline(request)

def sha1(data):
    sha1_hash = hashlib.sha1()
    sha1_hash.update(data)
    return sha1_hash.digest()
    

def get_private_key(g, n):
    request = {
                    'option':'sign_time',
                }

    print(r.readline())
    json_send(request)
    sign_message=json.loads(r.readline())

    signature=Crypto.Util.number.bytes_to_long(bytes.fromhex(sign_message["s"][2:]))
    x=Crypto.Util.number.bytes_to_long(bytes.fromhex(sign_message["r"][2:]))

    sha1_hash = hashlib.sha1()
    sha1_hash.update(sign_message["msg"].encode())
    h=Crypto.Util.number.bytes_to_long(sha1_hash.digest())

    max_value_r=int(sign_message['msg'].split(":")[-1])

    # on brutefroce k car il y a confusion variable locale&global pour le nonce
    # le nonce est compris entre 1 et la seconde du timestamp (autrement dit au 1<nonce<59) 

    for r_bruteforce in range(1,max_value_r):
        pubkey = Public_key(g, r_bruteforce*g)
        x_brutefroce=pubkey.point.x()
        if x_brutefroce==x:
            print(r_bruteforce)
            private_key=(pow(x,-1,n)*(r_bruteforce*signature-h))%n
            assert signature==(pow(r_bruteforce, -1, n)*(h+x*private_key))%n
    return private_key

def get_flag(g, private_key, n):

    pubkey = Public_key(g, g * private_key)
    privkey = Private_key(pubkey, private_key)

    msg='unlock'
    hsh = sha1(msg.encode())
    sig = privkey.sign(bytes_to_long(hsh), randrange(1, n))

    request = {
                'option':'verify',
                'msg':msg,
                'r':hex(sig.r),
                's':hex(sig.s)
            }

    json_send(request)
    flag=json.loads(r.readline())
    return flag

if __name__ == "__main__":
    private_key=get_private_key(g, n)
    flag=get_flag(g, private_key, n)
    print(flag["flag"])


