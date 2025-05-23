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

def encrypt_string(message: str, public_key):
    message_bytes = message.encode('utf-8')
    message_int = int.from_bytes(message_bytes, byteorder='big')
    cipher_int = encrypt(message_int, public_key)
    return cipher_int

def decrypt_string(cipher_int: int, private_key):
    message_int = decrypt(cipher_int, private_key)
    message_length = (message_int.bit_length() + 7) // 8
    message_bytes = message_int.to_bytes(message_length, byteorder='big')
    return message_bytes.decode('utf-8')

def save_key_to_file(key, filename):
    with open(filename, 'w') as f:
        f.write(f"{key[0]}\n{key[1]}")  # e or d on line 1, n on line 2

def load_key_from_file(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()
        part1 = int(lines[0].strip())
        part2 = int(lines[1].strip())
        return (part1, part2)
