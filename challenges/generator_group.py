
from sage.all import Integer

if __name__ == "__main__":
    p = 28151
    order = p-1

    factors = Integer(p-1).factor(algorithm="ecm")
    prime_factor_decompo = [(int(k[0]),int(k[1])) for k in list(factors)]

    for g_candidate in range(1,order):
        print(g_candidate)
        if (all([pow(g_candidate, (order)//prime_factor[0],p)!=1 for prime_factor in prime_factor_decompo])):
            break
            
    print(f"g_candidate :{g_candidate}")
        