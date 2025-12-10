from itertools import combinations
from functools import reduce
from typing import List, Tuple


# Donne la solution à un système d'équations avec diffèrents modulo si les modulos ont coprimes entre eux

def extended_euclidian(a:int,b:int):
    #Documentation
    #https://www.youtube.com/watch?v=AA4TBClsjFY

    # Initialisation des poids
    a0,a1=1,0 
    b0,b1=0,1

    # Pour conserver les valeures de a et b
    c,d=a,b
    while (b>0):
        
        q=a//b
        a,b=b,a%b

        c0,c1=b0,b1 # on stocke temporairement b0,b1
        b0,b1=a0-q*b0,a1-q*b1 #on met en jour les coefficients en utilisant le quotient entre a et b
        a0,a1=c0,c1 #on converse uniquement la ligne précédente 

    #print(f"{a}={a0}*{c}+{a1}*{d}")
    return a,a0,a1

def inverse_modulaire(a:int,modulo:int):
    #Caclul de l'inverse de a modulo n
    #ax+modulo*y=1 => ax = 1 % modulo
    # Donc x est l'inverse de a % modulo
 
    pgcd,x,y = extended_euclidian(a,modulo)
    if (pgcd!=1):
        raise Exception("{a} et {n} ne sont pas premier entre eux")
    else:
        return x

def pgcd(a,b):
    return extended_euclidian(a,b)[0]

def legendre(a,p):
    return pow(a,(p-1)//2,p)

def ChineseRemainder(system_equations:List[tuple[int,int]], fast:bool=False):
    # https://fr.wikipedia.org/wiki/Th%C3%A9or%C3%A8me_des_restes_chinois 

    modulos = list(map(lambda x:x[1], system_equations))
    
    combinaisons = list(combinations(modulos, r=2))
    for combi in combinaisons:
        if pgcd(combi[0],combi[1])!=1:
            raise Exception(f"Modulos {combi} aren't coprimed ")
    

    # product modulos 
    n = reduce(lambda x, y: x * y, modulos) 
    
    res=0
    for equation in system_equations:
        n_i = equation[1]
        n_divide_by_ni = n // n_i

        # On récupère l'inverse modulaire (v_i) de n_divide_by_ni modulo n_i
        if fast:
            v_i=pow(n_divide_by_ni,-1,n_i)
        else:
            v_i = inverse_modulaire(n_divide_by_ni,n_i)
        e_i = v_i * n_divide_by_ni

        res += equation[0] * e_i
    return res%n,n


if __name__ == "__main__":
    system_equations=[(2,5),(3,11),(5,17)]
    solution1 = ChineseRemainder(system_equations)
    solution2 = ChineseRemainder(system_equations, fast=True)
    assert solution1==(872,935)
    assert solution2==(872,935)