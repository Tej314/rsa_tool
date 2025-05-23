import random
from sympy import isprime, mod_inverse

def generate_prime(bits):
    while True:
        num = random.getrandbits(bits)
        if isprime(num):
            return num

def generate_keypair(bits=512):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    while q == p:
        q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if phi % e == 0:
        return generate_keypair(bits)
    d = mod_inverse(e, phi)
    return (e, n), (d, n)

def encrypt(message: int, public_key):
    e, n = public_key
    return pow(message, e, n)

def decrypt(ciphertext: int, private_key):
    d, n = private_key
    return pow(ciphertext, d, n)
