# AES_keygen.py

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def generate_aes_key():
    # Generate a random 256-bit AES key
    key = os.urandom(32)  # 32 bytes = 256 bits
    return key

def save_key_to_file(key, filename):
    """ Save the AES key to a file in binary format. """
    with open(filename, 'wb') as f:
        f.write(key)
    print(f"AES key saved to {filename}")

def main():
    # Prompt the user for the key file name
    file_name = input("Enter the file name to save the AES key (with .bin extension): ")

    # Generate the AES key
    aes_key = generate_aes_key()

    # Save the key to the file
    save_key_to_file(aes_key, file_name)

if __name__ == "__main__":
    main()
