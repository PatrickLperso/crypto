

# Ajout du répertoire eliptic curve
from Eliptic_curve import WeierStrass, PointWeirstrass
from Modular_arithmetic import ChineseRemainder, pgcd
import logging
from typing import List, Tuple
from tqdm import tqdm
import random as rd
import psutil, os
import pandas as pd

from pwn import *
import json
import codecs
import base64

sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "general_crypto"))


r = remote('socket.cryptohack.org', 13419, level = 'debug')

def json_recv():
    line = r.readline()
    return json.loads(line.decode())

def json_send(json_dict:dict):
    request = json.dumps(json_dict).encode()
    r.sendline(request)

def parse_data(initial_data, curve):
    get_lines = initial_data.decode().split("\n")[2:-1]
    Point_client_server_x, Point_client_server_y = tuple(map(lambda x:int(x), get_lines[0].split(" : ")[1].strip('Point(x=').strip(")").split(", y=")))
    Point_client_server = PointWeirstrass(curve, Point_client_server_x, Point_client_server_y)

    Point_server_client_x, Point_server_client_y = tuple(map(lambda x:int(x), get_lines[1].split(" : ")[1].strip('Point(x=').strip(")").split(", y=")))
    Point_server_client = PointWeirstrass(curve, Point_server_client_x, Point_server_client_y)

    flag_AES = initial_data.decode().split("\n")[2:-1][2].split(" : ")[1].encode()
    return Point_client_server, Point_server_client, flag_AES


if __name__ == "__main__":
    # NIST P-256
    p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
    b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

    curve = WeierStrass(a, b, p)

    G = PointWeirstrass(
        curve,
        0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    )

    evil_curve = WeierStrass(a, 0, p)

    request = {
                'option':'start_key_exchange',
                'ciphersuite':'ECDHE_P256_WITH_AES_128',
                'Qx':'',
                'Qy':'',
            }

    initial_data = r.recv(timeout=0.5)

    Point_client_server, Point_server_client, flag_AES = parse_data(initial_data, curve)
    print("toto")

    json_send(request)
    response = r.recv(timeout=0.5)