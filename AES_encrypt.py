# AES_encrypt.py

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def load_aes_key(key_file):
    """Load the AES key from a file."""
    with open(key_file, 'rb') as f:
        key = f.read()
    if len(key) != 32:
        raise ValueError("The AES key must be 256 bits (32 bytes).")
    return key

def encrypt_file(input_file, output_file, key):
    """Encrypt a file with AES-256 encryption."""
    # Read the input file data
    with open(input_file, 'rb') as f:
        data = f.read()

    # Create an AES cipher in CBC mode
    iv = os.urandom(16)  # AES block size is 16 bytes for CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad data to be multiple of block size (AES block size is 16 bytes)
    padder = padding.PKCS7(128).padder()  # 128 bits = 16 bytes block size
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt the data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Write the IV and encrypted data to the output file
    with open(output_file, 'wb') as f:
        f.write(iv)  # Write the IV at the beginning of the file
        f.write(encrypted_data)

def main():
    # Prompt user for AES key file and file to encrypt
    key_file = input("Enter the AES key file name (with .bin extension): ")
    input_file = input("Enter the file name to encrypt: ")

    # Check if the input file exists
    if not os.path.exists(input_file):
        print(f"Error: The file '{input_file}' does not exist.")
        return

    # Load the AES key
    try:
        aes_key = load_aes_key(key_file)
    except ValueError as e:
        print(f"Error: {e}")
        return

    # Generate the output encrypted file name
    output_file = input_file + ".BIJI"

    # Encrypt the file
    encrypt_file(input_file, output_file, aes_key)

    # Remove the original plaintext file
    os.remove(input_file)
    print(f"File encrypted successfully. Encrypted file saved as '{output_file}' and original file '{input_file}' removed.")

if __name__ == "__main__":
    main()
