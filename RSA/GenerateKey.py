import math
import random
import time


def exponentiate_modular(base, x, modulus):
    out = base
    values = {0 : out}
    logged = int(math.log2(x))
    for i in range(logged):
        out *= out
        out %= modulus
        values[i+1] = out
    difference = x - (2**logged)
    logged_two = int(math.log2(difference)) if difference > 0 else -1
    while logged_two >= 0:
        out *= values[logged_two]
        out %= modulus
        difference = difference - 2**logged_two
        logged_two = int(math.log2(difference)) if difference > 0 else -1
    return out

#Uses Fermat's little theorem to validate number as prime
def generate_prime(n):
    lower = 2**(n-1)+1
    upper = 2 ** n
    while True:
        p = random.randrange(lower, upper, 2)
        if exponentiate_modular(2, p-1, p) == 1:
            break
    return p

#extended euclidean algorithm (modified for optimization)
def find_inverse(a, n):
    r = a 
    oldr = n 
    t = 1
    oldt = 0
    while r > 1: 
        q = oldr // r 
        temp = r 
        r = oldr % r 
        oldr = temp 
        temp = t 
        t = oldt - q * t 
        oldt = temp  
    return t % n
    


if __name__ == "__main__":
    # p = generate_prime(1024)
    # print(p)
    # print()
    # q = generate_prime(1024)
    # print(q)
    # print()
    # N = p*q 
    # phi_N = (p-1)*(q-1)
    # e = 65537 
    # d = find_inverse(e, phi_N)
    # print(f"modulus: {N}\n")
    # print(f"public key: {e, hex(e)}\n")
    # print(f"private key: {bytes.fromhex(hex(d)[2:])}\n")
    a = generate_prime(1024)
    b = generate_prime(1024)
    c = generate_prime(1024)
    start = time.time()
    print(exponentiate_modular(a, b, c))
    end = time.time()
    print(f"\n {end - start}")
