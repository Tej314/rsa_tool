from rsa import generate_keypair, encrypt_string, decrypt_string, save_key_to_file, load_key_from_file

def main():
    print("Generating RSA keypair...")
    public_key, private_key = generate_keypair(512)
    save_key_to_file(public_key, "public_key.txt")
    save_key_to_file(private_key, "private_key.txt")
    print("Keys saved to public_key.txt and private_key.txt")

    print("\nReloading keys from file...")
    public_key = load_key_from_file("public_key.txt")
    private_key = load_key_from_file("private_key.txt")

    message = input("\nEnter a message to encrypt: ")
    ciphertext = encrypt_string(message, public_key)
    print("Encrypted (as integer):", ciphertext)

    decrypted = decrypt_string(ciphertext, private_key)
    print("Decrypted message:", decrypted)

if __name__ == "__main__":
    main()
