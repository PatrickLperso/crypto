import pytest
from crypto_core.Ecb_padding_attack import Ecb_padding_attack

# Liste des caractères autorisés partagée par tous les tests
LETTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!*-+_"

@pytest.mark.parametrize("custom_flag, method_type", [
    (None, "fast"), 
    ("il_etait_UneFOIS12viela8be74125e", "fast"), 
    (None, "slow")
])
def test_ecb_padding_oracle_attack(custom_flag, method_type):
    ecb = Ecb_padding_attack()
    
    # si flag est perso
    if custom_flag is not None:
        ecb.FLAG = custom_flag
        
    # test de la longeueur du flag
    length_flag = ecb.length_flag()
    assert length_flag == len(ecb.FLAG)

    # test padding ecb parrélélié versus simple onee
    if method_type == "fast":
        letters_found = ecb.request_oracle(length_flag, LETTERS, url=False)
    elif method_type == "slow":
        letters_found = ecb.request_oracle_stupid(length_flag, LETTERS)
        
    # assert finale
    assert letters_found == ecb.FLAG