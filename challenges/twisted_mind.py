import os,sys
import hashlib
import random
import json
import string
import requests
from pwn import *

#sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "general_crypto"))

from crypto_core.Twisted_curve_attack import break_twist, break_curve,crt_system_equation_solution

r = remote('socket.cryptohack.org', 13416, level = 'debug')

def json_recv():
    line = r.readline()
    return json.loads(line.decode())

def json_send(data):
    request = json.dumps(data).encode()
    r.sendline(request)

def request_cryptohack(x:int):
    request = {
                'option':'get_pubkey',
                'x0':x,
            }
    
    json_send(request)
    pubkey_x=int(json.loads(r.readline())["pubkey"])
    return pubkey_x

def get_flag(private_key:int):
    request = {
                'option':'get_flag',
                'privkey':str(private_key),
            }
    
    json_send(request)
    flag=json.loads(r.readline())["flag"]
    return flag


if __name__ == "__main__":
    p = 2**192 - 237
    a = -3
    b = 1379137549983732744405137513333094987949371790433997718123
    order = 6277101735386680763835789423072729104060819681027498877478

    # Mesage de bienvenue
    print(r.readline())
    print(r.readline())
    print(r.readline())

    interface = request_cryptohack

    G_weirstrass, x_scalar_weirstrass, crt_system_equations1  = break_curve(a,b,p,interface)
    G_twist_weirstrass, x_scalar_twist, crt_system_equations2 = break_twist(a,b,p,interface)

    # ========== Avant polhig Hellman on fait un choix car quand on nous renvoie l coordonée x on peut choisir P(x, +/y) avec tonneli
    # ==========   on doit donc rendre coherent le système d'équation pour CRT ==========  

    private_key = crt_system_equation_solution(crt_system_equations1, crt_system_equations2, order, G_weirstrass, x_scalar_weirstrass)
    
    assert "crypto{tw1st_s3curity_of_x_0nly_ladder}" == get_flag(private_key)


