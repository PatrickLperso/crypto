from Eliptic_curve import WeierStrass, PointWeirstrass
from Modular_arithmetic import ChineseRemainder, pgcd
import logging
from typing import List, Tuple
from tqdm import tqdm
import random as rd
import psutil, os
import pandas as pd

from os import urandom
from collections import namedtuple
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import inverse
from hashlib import sha256

# Pour générer des courbes vulnérables
from sage.all import EllipticCurve, GF

FLAG = b"This is a very secret flag"

class Server:
    def __init__(self, curve, generator):
        self.curve = curve
        self.generator = generator
        self.secret = int.from_bytes(urandom(32), byteorder="little")
        self.public_key = self.secret*self.generator

    def ecdh_kex(self, Q):
        shared_point =  self.secret * Q
        self.shared_key = sha256(str(shared_point.x).encode()).digest()[:16]

    def send_msg(self, message):
        iv = urandom(16)
        cipher = AES.new(self.shared_key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(pad(message, 16))


class Challenge:
    def __init__(self, server):
        self.server = server
        client_secret_key = int.from_bytes(urandom(32), byteorder="little")
        client_public_key = client_secret_key * self.server.generator

        self.server.ecdh_kex(client_public_key)

        self.before_input = {
            "client_server" : client_public_key,
            "server_client" : self.server.public_key,
            "server_client_msg" : self.server.send_msg(FLAG).hex(),
        }

    def challenge(self, your_input):
        if your_input["option"] == "start_key_exchange":
            if "Qx" not in your_input or "Qy" not in your_input:
                return {"msg": "No public key provided."}
            try:
                Q = Point(int(your_input["Qx"], 16), int(your_input["Qy"], 16))
                self.server.ecdh_kex(Q)
            except:
                return {"msg": "An error occured, please provide valid inputs."}
            return {"msg": "Key exchange proceeded successfully."}

        if your_input["option"] == "get_test_message":
            # this is where I can break the server secret key
            return {"msg": self.server.send_msg(b"SERVER_TEST_MESSAGE").hex()}


if __name__ == "__main__":
    # Dummy elitpic curve
    # sage: EllipticCurve(GF(101141), [1,5]).order().factor(algorithm='ecm')
    # 101089
    #sage: P = E(83423,72213)
    # sage: P.order()
    # 101089

    curve = WeierStrass(1,5,101141)

    # On autorise les additions avec des points sur d'autres courbes
    G = PointWeirstrass(curve, 83423,72213, secure=False)
    server = Server(curve, G)

    challenge = Challenge(server)
    challenge_client_flag = challenge.before_input

    for k in vulnerable_elitpic_curves:
        # on va mettre à jour la self.server.shared_key en envoyant Q de faible order
        challenge.challenge({"option" : "start_key_exchange", "Qx" : , "Qy":})

        response = bytes.fromhex(challenge.challenge({"option" : "get_test_message"}))
        iv = response[:16]
        cipher = response[16:]

        # On casse par bruteforce le shared secret en iterant sur tous les Q de faible order possible 
        # on bruteforce private de cette manière 
        if cipher == encrypt_AES("SERVER_TEST_MESSAGE", self.server.public_key*private)

        x = private mod prime order
    
    x = CRT([[private1, order1], [private2, order2]])
    self.secret = x % order_curve_server

    shared_secret = client_public_key * self.secret
    On peut casser ca mtn :
    self.server.send_msg(FLAG).hex()


    """
    on va attaquer avec :
    sage: EllipticCurve(GF(101141), [1,7]).order().factor(algorithm='ecm')
    3 * 5 * 6709
    sage: EllipticCurve(GF(101141), [1,1]).order().factor(algorithm='ecm')
    3 * 13 * 2609
    """

    # =>
    # <= point d'ordre faible
    # <= point d'ordre faible
    # <= point d'ordre faible
    # <= point d'ordre faible
    # => message chiffrée avec une clé d'ordre faible que je vais casser