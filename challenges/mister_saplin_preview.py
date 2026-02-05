from hashlib import sha256
from threading import Thread

import random
from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes
import json
import os
import timeit

FLAG = b"crypto{??????????????????????????????????????????????????????????????????}"

def hash256(data):
    return sha256(data).digest()

def merge_nodes(a, b):
    return hash256(a+b)

def interface(data:dict, socket):
    # on envoie la requete 
    request = json.dumps(data).encode()
    socket.sendline(request)
    # on renvoie la réponse
    line = socket.readline()
    return json.loads(line.decode())

class Challenge:
    def __init__(self):
        self.before_input = "Welcome to the saplins previews system implementation!\n"
        self.datas = os.urandom(64)
        self.balance = 99
        self.nodes = []
        self.build_saplin()
        self.balance_validated = False
        self.layer_price = {0:20, 1:50, 2:110}

    def build_saplin(self):
        self.nodes.append([hash256(self.datas[i:i+8]) for i in range(0,64,8)])
        self.nodes.append([merge_nodes(*self.nodes[0][i:i+2]) for i in range(0,8,2)])
        self.nodes.append([merge_nodes(*self.nodes[1][i:i+2]) for i in range(0,4,2)])
        self.nodes.append([merge_nodes(*self.nodes[2][0:2])])

    def request_checker(self, wanted_nodes):
        # just checking if the balance has enough credits
        credits_needed = 0
        for layer in wanted_nodes.keys():
            for _ in range(wanted_nodes[layer]):
                credits_needed += self.layer_price[layer]

        if credits_needed > self.balance:
            self.balance_validated = False
        else:
            self.balance_validated = True
            self.balance -= credits_needed

    def balance_check(self, wanted_nodes):
        layers = wanted_nodes.keys()
        # dealing with trivials cases
        for layer in layers:
            if layer >= 3 or layer < 0:
                self.balance_validated = False
                return
        if 2 in layers and wanted_nodes[2] >= 1:
            # too high node even with the starting balance
            self.balance_validated = False
            return
        # dealing with common cases
        t = Thread(target=self.request_checker, args=[wanted_nodes])
        t.start()

    def saplin_proof(self, user_input):
        return user_input == self.nodes[-1][0]

    def challenge(self, your_input):
        if not "option" in your_input:
            return {"error": "You must send an option to this server"}

        if your_input["option"] == "get_nodes":
            self.balance_validated = None
            try:
                raw_wanted_nodes = your_input["nodes"].split(";")
                wanted_nodes = {int(layer.split(",")[0]): int(layer.split(",")[1]) for layer in raw_wanted_nodes}
                self.balance_check(wanted_nodes)
                if self.balance_validated != False:
                    print(self.balance_validated)
                    nodes = []
                    for layer in wanted_nodes:
                        nodes.append(list(map(bytes.hex, self.nodes[layer][:wanted_nodes[layer]])))
                    return {"msg": str(nodes)}
                else:
                    return {"error": "You don't have enough credits!"}
            except Exception as e:
                return {"error": str(e)}

        elif your_input["option"] == "do_proof":
            try:
                hsh =  bytes.fromhex(your_input["root"])
                if self.saplin_proof(hsh):
                    return {"msg": FLAG.decode()}
                else:
                    return {"msg": "you failed!"}
            except Exception as e:
                return {"error": str(e)}
        else:
            return {"error": "Invalid option"}




def resolve_challenge(interface, local=True):


    results = []

    def worker(payload,socket=None):
        #start.wait()
        if socket is None:
            res = interface(payload)
        else:
            res = interface(payload, socket)
        print(res)
        results.append((time.time(), threading.current_thread().name, res))
    
    if local:
        T1 = Thread(target=worker, args=({"option":"get_nodes", "nodes":"0,100000"},), name="RC1")
    else:
        socket = remote('socket.cryptohack.org', 13414, level = 'info')
        socket.readline()
        T1 = Thread(target=worker, args=({"option":"get_nodes", "nodes":"0,100000"},socket), name="RC1")        

    T1.start()

    T1.join()

    if "error" not in list(map(lambda x:list(x[2].keys())[0],results)):
        # LETS Go BAbY Race COndiTion
        results = sorted(results, key= lambda x:x[1])
        nodes = list(map(lambda x:bytes.fromhex(x), eval(results[0][2]["msg"])[0]))
        
        for k in reversed(range(1,4)):
            merkel_inter=[]
            merkel_inter = [merge_nodes(*nodes[i:i+2]) for i in range(0,2**k,2)]
            nodes = merkel_inter
        
        if local:
            flag = interface({"option":"do_proof", "root":nodes[0].hex()})["msg"]
        else:
            flag = interface({"option":"do_proof", "root":nodes[0].hex()}, socket)["msg"]
        
    return flag


if __name__ == "__main__":
    # Race condition au niveau de 
    # if self.balance_validated != False:
    # car la variable est calculé dans un thread
    # t = Thread(target=self.request_checker, args=[wanted_nodes])
    # il suffit de rendre long ce thread grâce à une longue boucle :
    # for layer in wanted_nodes.keys():
    #     for _ in range(wanted_nodes[layer]):
    #         credits_needed += self.layer_price[layer]
    # ainsi le fil d'execution parent continue avant que le resultat du thread soit renvoyé 
    # autremen dit la valeur self.balance_validated est tjs à sa valeur d'initalisation qui était :
    # self.balance_validated = None et donc le test 
    # if self.balance_validated != False: est valide

    # ainsi on recupère tous les noeuds de l'arbre de Merkle et on envoie le root de l'arbre que 'on peut calcuer
    # pour obtenir le flag


    # ========== local challenge ==========
    challenge_ = Challenge()
    interface_ = challenge_.challenge
    flag = resolve_challenge(interface_)
    print(flag)
    assert flag == FLAG.decode()

    # ========== Cryptohack challenge ==========
    interface_ = interface
    flag = resolve_challenge(interface_, local=False)
    assert flag == "crypto{M3rkle_tree_AND_race_condition_AND_replay_attack___that's_too_much}"

    