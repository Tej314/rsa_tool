from rsa import generate_keypair, encrypt, decrypt

def main():
    print("Generating RSA keypair...")
    public_key, private_key = generate_keypair(512)
    print("Public Key (e, n):", public_key)
    print("Private Key (d, n):", private_key)

    message = int(input("Enter a number to encrypt (as plaintext integer): "))
    ciphertext = encrypt(message, public_key)
    print("Encrypted message:", ciphertext)

    decrypted = decrypt(ciphertext, private_key)
    print("Decrypted message:", decrypted)

if __name__ == "__main__":
    main()
