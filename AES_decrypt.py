# AES_decrypt.py

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

def decrypt_file(input_file, output_file, key):
    """Decrypt an AES-256 encrypted file."""
    # Read the encrypted file data
    with open(input_file, 'rb') as f:
        iv = f.read(16)  # Read the first 16 bytes as the IV
        encrypted_data = f.read()

    # Create an AES cipher in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the data
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()  # 128 bits = 16 bytes block size
    data = unpadder.update(decrypted_data) + unpadder.finalize()

    # Write the decrypted data to the output file
    with open(output_file, 'wb') as f:
        f.write(data)

def main():
    # Prompt user for AES key file and encrypted file to decrypt
    key_file = input("Enter the AES key file name (with .bin extension): ")
    encrypted_file = input("Enter the file name to decrypt (with .BIJI extension): ")

    # Check if the encrypted file exists
    if not os.path.exists(encrypted_file):
        print(f"Error: The file '{encrypted_file}' does not exist.")
        return

    # Load the AES key
    try:
        aes_key = load_aes_key(key_file)
    except ValueError as e:
        print(f"Error: {e}")
        return

    # Generate the output decrypted file name by removing the ".BIJI" extension
    if not encrypted_file.endswith('.BIJI'):
        print(f"Error: The file '{encrypted_file}' does not have the expected '.BIJI' extension.")
        return
    output_file = encrypted_file[:-5]  # Remove ".BIJI" from the file name

    # Decrypt the file
    decrypt_file(encrypted_file, output_file, aes_key)

    # Remove the original encrypted file
    os.remove(encrypted_file)
    print(f"File decrypted successfully. Decrypted file saved as '{output_file}' and encrypted file '{encrypted_file}' removed.")

if __name__ == "__main__":
    main()
