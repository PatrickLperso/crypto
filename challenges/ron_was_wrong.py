from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
import random
import math
from tqdm import tqdm
import os, sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

#sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "general_crypto"))
from crypto_core.common_modulus import factor


def charger_cles_pem_cipher(dossier_path):
    cles_chargees = []
    
    # On liste tous les fichiers du dossier
    id_fichier = sorted(list(set(list(map(lambda x:x.split(".")[0], os.listdir(dossier_path))))))

    for id_ in id_fichier:
            chemin_pem    = os.path.join(dossier_path, id_ + ".pem")
            chemin_cipher = os.path.join(dossier_path, id_ + ".ciphertext")
            
            try:
                with open(chemin_pem, "rb") as f:
                    donnees_pem = f.read()
                    
                    # On tente de charger la clé (Publique ou Privée)
                    # Note: On charge souvent la publique pour l'attaque
                    try:
                        cle = serialization.load_pem_public_key(donnees_pem)
                    except:
                        # Si c'est une clé privée, on en extrait la publique
                        cle_privee = serialization.load_pem_private_key(donnees_pem, password=None)
                        cle = cle_privee.public_key()
                    
                    # On récupère N et e
                    n = cle.public_numbers().n
                    e = cle.public_numbers().e
                
                    with open(chemin_cipher, "r") as f:
                        cipher = f.read()
                    
                    cles_chargees.append({
                        "fichier": id_,
                        "n": n,
                        "e": e,
                        "c": cipher,
                    })
                    
            except Exception as err:
                print(f"[ERREUR] Impossible de lire {id_}: {err}")
                
    return cles_chargees

def challenge(directory):
    keys_cipher = charger_cles_pem_cipher(directory)
    
    # on factorise les modules qui ont des facteurs premiers communs
    factorization = factor(list(map(lambda x:x["n"], keys_cipher)))

    flag = b""
    for index, keys in enumerate(factorization):
        if keys[0]!=1:
            p = int(keys[0])
            q = int(keys[1])
            n = keys_cipher[index]["n"]
            e = keys_cipher[index]["e"]
            ciphertext = bytes.fromhex(keys_cipher[index]["c"])

            # --- RECONSTRUCTION DE LA CLÉ AVEC CRYPTOGRAPHY ---
            # On calcule d et les paramètres CRT nécessaires pour l'objet
            phi = (p - 1) * (q - 1)
            d = pow(e, -1, phi)
            
            # Reconstruction de l'objet de clé privée
            pn = rsa.RSAPrivateNumbers(
                p=int(p),
                q=int(q),
                d=int(d),
                dmp1=int(d % (p - 1)),
                dmq1=int(d % (q - 1)),
                iqmp=int(pow(q, -1, p)),
                public_numbers=rsa.RSAPublicNumbers(e, n)
            )

            private_key = pn.private_key()

            decrypted_part = private_key.decrypt(
                    ciphertext,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA1()), # Modifier en SHA1 si besoin
                        algorithm=hashes.SHA1(),                   # Modifier en SHA1 si besoin
                        label=None
                    )
                )
            flag += decrypted_part

    return flag[:flag.find(b"} ")+1]


if __name__ == "__main__":
    directory = os.path.join(os.path.join(os.path.dirname(os.path.abspath(__file__)), "ressources"), "keys_and_messages")
    flag = challenge(directory)
    assert flag == b"crypto{3ucl1d_w0uld_b3_pr0ud}"

