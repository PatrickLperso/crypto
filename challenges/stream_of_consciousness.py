from Crypto.Cipher import AES
from Crypto.Util import Counter
import random

from Crypto.Util.number import bytes_to_long, long_to_bytes
import requests
import os
from tqdm import tqdm 

def encrypt_request():
    return requests.get("https://aes.cryptohack.org/stream_consciousness/encrypt").json()

def recover_bytes(infos, guess, cipher):
    #AES_stream = [a^b for a,b in zip(b"ppy", [147, 59, 79])] #happy
    AES_stream = [a^b for a,b in zip(guess, cipher)]
    length = len(infos[0][0])
    
    res = []
    for k in range(len(infos)):
        res.append([infos[k][0]+bytes([ a^b for a,b in zip(infos[k][1][length:length+len(AES_stream)], AES_stream)]), infos[k][1]])
    return res 

def challenge(interface_encrypt):
    cipher_list = []
    for k in tqdm(range(100)):
        res = bytes.fromhex(interface_encrypt()["ciphertext"])
        if res not in cipher_list:
            cipher_list.append(res)
        if len(cipher_list)==22:
            break
    print(cipher_list)

    start_messages = [b'And I s', b'As if I', b'But I w', b'Dolly w', b'Dress-m', b'How pro', b'I shall', b'I shall', b"I'm unh", b"It can'", b'Love, p', b"No, I'l", b'Our? Wh', b'Perhaps', b'The ter', b'These h', b'Three b', b'What a ', b'What a ', b'Why do ', b'Would I', b'crypto{']
    # on va tente de guesser celui qui est "crypto{.......}" 
    message = b"crypto{"
    for index, cipher_crypto in enumerate(cipher_list):
        message_start_possibles_inter=[bytes([a ^ b ^ c for a,b,c in zip(cipher_crypto[:7], message, cipher_no_crypto[:7])]) for cipher_no_crypto in cipher_list]
        if sorted(message_start_possibles_inter) == start_messages:
            index_flag = index
            break
    
    infos = [[message_start_possibles_inter[k], cipher_list[k], len(cipher_list[k])] for k in range(len(cipher_list))]

    # on recober les bytes à la main petit à petit
    infos=recover_bytes(infos, b" ", [47])# [7]
    infos=recover_bytes(infos, b"ppy", [135, 122, 41]) #[8:11]
    infos=recover_bytes(infos, b"e", [30]) #[11]
    infos = recover_bytes(infos, b" ", [191]) #[12]
    infos = recover_bytes(infos, b"y", [147]) #[13]
    infos = recover_bytes(infos, b" ", [148]) #[14]
    infos = recover_bytes(infos, b"ing", [99, 57, 104]) #[15:18]
    infos = recover_bytes(infos, b"ve", [101, 193]) #[18:20]
    infos = recover_bytes(infos, b"d ", [101, 211]) #[20:22]
    infos = recover_bytes(infos, b" ", [217]) #[22]
    infos = recover_bytes(infos, b"hat ", [89, 184, 112, 197]) #[23:27]
    infos = recover_bytes(infos, b"nt ", [136, 118, 218]) #[27:30]
    infos = recover_bytes(infos, b"n ", [28, 240]) #[30:32]

    return infos[index_flag][0]

if __name__ == "__main__":
    interface_encrypt = encrypt_request
    flag = challenge(interface_encrypt)
    assert flag == b'crypto{k3y57r34m_r3u53_15_f474l}'

    # baisquement le truc c'est qu'on utilise le même nonce + counter pour plusieurs message différents 
    # cipher = AES.new(KEY, AES.MODE_CTR, counter=Counter.new(128))
    # Donc :
    # C1 = M1 XOR AES_CTR(Nonce + counter)
    # C2 = M2 XOR AES_CTR(Nonce + counter)
    # en particulier parmi les 22 messages recus, on sait qu'il en existe un qui commence par crypto{
    # Donc en tesant l'hypothèse M1[0:7] == "crypto{", M2[0:7] == "crypto{"
    # on peut tenter de déduire les 7 premiers octets de M2[0:7], M3[0:7], ... M22[0:7] avec l'hypothèse M1[0:7] =  == "crypto{"
    # ou M1[0:7], M3[0:7], ... M22[0:7] avec l'hypothèse M2[0:7] =  == "crypto{"
    # et ainsi de suite 
    # On tombe alors sur une hypothèse ou tous les débuts de messages sont cohérents 
    #  start_messages = [b'And I s', b'As if I', b'But I w', b'Dolly w', b'Dress-m', b'How pro', b'I shall', b'I shall', b"I'm unh", b"It can'", b'Love, p', b"No, I'l", b'Our? Wh', b'Perhaps', b'The ter', b'These h', b'Three b', b'What a ', b'What a ', b'Why do ', b'Would I', b'crypto{']
    # ensuite on peut tenter petit à petit de déterminer le contenu des phrases lettre par lettre le flux du stream 

    # infos=recover_bytes(infos, b" ", [47])# [7]
    # infos=recover_bytes(infos, b"ppy", [135, 122, 41]) #[8:11]
    # infos=recover_bytes(infos, b"e", [30]) #[11]
    # infos = recover_bytes(infos, b" ", [191]) #[12]
    # infos = recover_bytes(infos, b"y", [147]) #[13]
    # infos = recover_bytes(infos, b" ", [148]) #[14]
    # infos = recover_bytes(infos, b"ing", [99, 57, 104]) #[15:18]
    # infos = recover_bytes(infos, b"ve", [101, 193]) #[18:20]
    # infos = recover_bytes(infos, b"d ", [101, 211]) #[20:22]
    # infos = recover_bytes(infos, b" ", [217]) #[22]
    # infos = recover_bytes(infos, b"hat ", [89, 184, 112, 197]) #[23:27]
    # infos = recover_bytes(infos, b"nt ", [136, 118, 218]) #[27:30]
    # infos = recover_bytes(infos, b"n ", [28, 240]) #[30:32]

    # jusqu'à obtenir le flag b'crypto{k3y57r34m_r3u53_15_f474l}'
    # Il est probablement possible d'automoasiter la décoiverte du stream en tentant des caractères en s'assurant qu'aucun ngram ou caratères chelou ne soient apparus dans les autres messages 

    # on obtient au final :

    # [b'What a lot of things that then s', b'\x8dtCZ^\xdbSc\x98~p\x14\xf9\xca\xc0b>at\xd7!\x87\x91P\xad$\x91\x8eg\x94R\xa3P\xaf6J\xe2\x08\xa9\xf4k\xd3\xa0\x8a\xca\xf4T\xe8@\xde\xe6Z\xe1\xff%\x81\xeaRo\xd1\x94v\x06.g\xf6\xfe\xd1\xfc\xd1\xe4\xe8$\xa9\xb3\x80\xa1J*\xd3$&\x98\xe7\x0e...\xe1\xef\xb6\x04]\x0c\x9eS_6b\xe8\xe3\xcd\x939y;\xe8\x9f7~.\xa0\xb2I\xa3(\x83d\xf5$\x0c\xf8\xac0 \x93\x04\xdbE\xec']
    # [b'The terrible thing is that the p', b'\x8etG\x0e\n\xdf\x01}\x9eh<\x1e\xbf\x9e\xdcc9h3\xcdr\xd3\x8dY\xb8p\xc5\x92j\x9fR\xa0T\xb9/\x0f\xe5I\xb3\xbc?\x9e\xa7\xcf\x99\xef\x1b\xf7O\x8c\xffJ\xf9\xb3(\x8d\xb9\x1bz\xcc\xd0$\x1c/r\xf1\xa4']
    # [b'As if I had any wish to be in th', b'\x9bo\x02G\x18\x9a:/\x9fk4[\xfe\x84\xcd* f`\xcc!\x87\x96\x11\xbba\xc5\x8fl\xda\x06\xb8P\xea)F\xe1@\xa9\xbak\xf7\xe5\xc9\xd8\xf5S\xf1\x00']
    # [b'What a nasty smell this paint ha', b'\x8dtCZ^\xdbSa\x96y$\x02\xbf\x99\xd9o;c3\xd0i\x9a\x8a\x11\xa9e\x8c\x88v\xda\x1a\xb1Q\xe4']
    # [b"How proud and happy he'll be whe", b'\x92sU\x0e\x0e\xc8\x1cz\x93*1\x15\xfb\xca\xdck\'\x7fj\x84i\x96\xde]\xb5$\x87\x83"\x8d\x1a\xb5[\xea3J\xa6O\xb8\xef8\x9e\xa8\xd3\x99\xf5\x1b\xf1D\x8d']
    # [b'I shall lose everything and not ', b'\x93<QF\x1f\xd6\x1f/\x9be#\x1e\xbf\x8f\xc2o%vg\xcch\x9d\x9e\x11\xb8j\x81\xc6l\x95\x06\xf0R\xaf/\x0f\xeeA\xb0\xbb)\xdf\xa6\xc1\x97']
    # [b"Love, probably? They don't know ", b'\x96sTKR\x9a\x03}\x98h1\x19\xf3\x93\x8b*\x03gv\xdd!\x97\x96_\xfep\xc5\x8dl\x95\x05\xf0]\xa5,\x0f\xe2Z\xb8\xfa9\xc7\xe5\xc3\xcd\xbb\x1d\xf6\r\x8c\xf8P\xfa\xb3"\x81\xf4\x1bb\xd6\x91"\x1a.a\xac\xa4\x9e\xb5\xcb\xed\xefh\x8d\xe9\xc5\xa7^9\x96e*\x99\xa4\x02\xaew8Dc\x17\xab\x8c']
    # [b"I shall, I'll lose everything if", b'\x93<QF\x1f\xd6\x1f#\xd7Cw\x17\xf3\xca\xd8e$j3\xc1w\x96\x8bH\xadl\x8c\x88e\xda\x1b\xb6\x15\xa2>\x0f\xe2G\xb8\xe8%\x99\xb1\x8a\xda\xf4\x19\xe0\x01\xce\xf1\\\xe6\xbd']
    # [b'But I will show him.', b'\x98iV\x0e7\x9a\x04f\x9bfp\x08\xf7\x85\xc3*?f~\x8a']
    # [b"Dolly will think that I'm leavin", b'\x9esNB\x07\x9a\x04f\x9bfp\x0f\xf7\x83\xdaaw{{\xc5u\xd3\xb0\x16\xb4$\x89\x83c\x8c\x1b\xbeR\xea:\x0f\xf5M\xbe\xf4%\xda\xe5\xc2\xcc\xe8\x16\xe4O\xc8\xb0^\xe3\xf7j\x80\xf1\x13z\x9f\x84>\x162c\xe4\xe5\xc2\xf0\x9f\xcc\xaa%\xb9\xec\xd4\xe9X)\xc4a(\x84\xa4\x03\xa3>=N1\x06\xad\xc7*1F~\xd6\xc6V']
    # [b"No, I'll go in to Dolly and tell", b'\x94s\x0e\x0e7\x9d\x1fc\xd7m?[\xf6\x84\x94~8/W\xcbm\x9f\x80\x11\xb8j\x81\xc6v\x9f\x1e\xbc\x15\xa2>]\xa6[\xa9\xe9*\xd7\xa2\xc2\xcd\xbb\x1b\xf0U']
    
    # [b'crypto{k3y57r34m_r3u53_15_f474l}', b'\xb9n[^\n\xd5\x08d\xc4seL\xed\xd9\x80g\x08} \xd14\xc0\xa6\x00\xec[\x83\xd25\xce\x1e\xad']
   
    # [b'Perhaps he has missed the train ', b'\x8ayPF\x1f\xca\x00/\x9fop\x13\xfe\x99\x94g>|`\xc1e\xd3\x8dY\xbc$\x91\x94c\x93\x1c\xf0T\xa4?\x0f\xef[\xfd\xf9*\xdd\xae\x8a\xdb\xe2T\xebN\xdb\xbe\x1f\xda\xf2$\x80\xb9\x1fa\xcd\x95v\x1b5k\xeb\xe6\xd9\xf4\xcb\xec\xe5&\xed']
    # [b"It can't be torn out, but it can", b'\x93h\x02M\x1f\xd4T{\xd7h5[\xeb\x85\xc6dw`f\xd0-\xd3\x9bD\xad$\x8c\x92"\x99\x13\xbe\x15\xa8>\x0f\xefO\xb3\xf49\xdb\xa1\x84']
    # [b'Dress-making and Millinery', b'\x9enG]\r\x97\x1en\x9cc>\x1c\xbf\x8b\xdanwBz\xc8m\x9a\x97T\xab}']
    # [b'Would I have believed then that ', b'\x8dsWB\x1a\x9a:/\x9fk&\x1e\xbf\x88\xd1f>je\xc1e\xd3\x8dY\xbcj\xc5\x92j\x9b\x06\xf0|\xea8@\xf3D\xb9\xbb9\xdb\xa4\xc9\xd1\xbb\x07\xf0B\xc4\xb0[\xe8\xe3>\x9c\xeaRa\xd9\xd0>\x06-o\xee\xe3\xd1\xe1\xd6\xea\xe4w']
    # [b'Three boys running, playing at h', b'\x8etPK\x1b\x9a\x11`\x8eyp\t\xea\x84\xdac9h?\x84q\x9f\x98H\xb0j\x82\xc6c\x8eR\xb8Z\xb8(J\xf5\x04\xfd\xc8.\xcc\xbc\xc5\xc3\xf3\x15\xa4']
    # [b'These horses, this carriage - ho', b'\x8etG]\x1b\x9a\x1b`\x85y5\x08\xb3\xca\xc0b>|3\xc7`\x81\x8bX\xb8c\x80\xc6/\xda\x1a\xbfB\xea\x12\x0f\xeaG\xbc\xef#\xdb\xe5\xc7\xc0\xe8\x11\xe9G\x8c\xf9Q\xad\xe7"\x9d\xeaRm\xde\x82$\x1a!a\xe7\xaa\x9d\xb5\xcb\xed\xef1\xeb\xed\xc5\xe9J0\xda$,\x94\xf7Z\xe6|!T1;\xe5\xd1b\'X}\x98\xcf\x1d\xef\xf8\x97\xd2\xe6K\x18\xef\r\x83\xfc\x04s)\n\x12]\xaf\x88']
    # [b'Our? Why our?', b'\x95iP\x11^\xed\x1bv\xd7e%\t\xa0']
    # [b'And I shall ignore it.', b'\x9brF\x0e7\x9a\x00g\x96f<[\xf6\x8d\xdae%j3\xcdu\xdd']
    # [b'Why do they go on painting and b', b'\x8dt[\x0e\x1a\xd5S{\x9fo)[\xf8\x85\x94e9/c\xc5h\x9d\x8dX\xb7c\xc5\x87l\x9eR\xb2@\xa37K\xefF\xba\xbb*\xd2\xa9\x8a\xcd\xf3\x11\xa5U\xc5\xfdZ\xb2']
    # [b"I'm unhappy, I deserve it, the f", b'\x93;O\x0e\x0b\xd4\x1bn\x87z)W\xbf\xa3\x94n2|v\xd6w\x96\xd9X\xad(\xc5\x92j\x9fR\xb6T\xbf7[\xa1[\xfd\xf6"\xd0\xa0\x86\x99\xf9\x01\xf1\x01\xe5\xb7R\xad\xe6$\x9c\xf8\x02~\xc6\xd07\x1f,&\xf6\xe2\xd5\xb5\xcc\xe4\xe7-\xe0\xbf\xc8\xacG,\x96i!\xd3']