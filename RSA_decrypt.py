# RSA_decrypt.py

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os

def load_private_key(priv_key_file):
    """Load the RSA private key from a PEM file."""
    with open(priv_key_file, 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    return private_key

def decrypt_file(input_file, output_file, private_key):
    """Decrypt a file using the RSA private key."""
    # Read the encrypted file data
    with open(input_file, 'rb') as f:
        encrypted_data = f.read()

    # RSA decryption can only decrypt small pieces of data at a time
    decrypted_data = b""

    # Decrypt the data in chunks
    chunk_size = private_key.key_size // 8  # Maximum size per encrypted chunk
    for i in range(0, len(encrypted_data), chunk_size):
        chunk = encrypted_data[i:i + chunk_size]
        decrypted_chunk = private_key.decrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted_data += decrypted_chunk

    # Write the decrypted data to the output file
    with open(output_file, 'wb') as f:
        f.write(decrypted_data)

def main():
    # Prompt user for RSA private key file and encrypted file to decrypt
    priv_key_file = input("Enter the RSA private key file name (with .pem extension): ")
    encrypted_file = input("Enter the encrypted file name (with .BIJI extension): ")

    # Check if the encrypted file exists
    if not os.path.exists(encrypted_file):
        print(f"Error: The file '{encrypted_file}' does not exist.")
        return

    # Load the RSA private key
    try:
        private_key = load_private_key(priv_key_file)
    except Exception as e:
        print(f"Error loading private key: {e}")
        return

    # Ensure the file has the ".BIJI" extension
    if not encrypted_file.endswith('.BIJI'):
        print(f"Error: The file '{encrypted_file}' does not have the expected '.BIJI' extension.")
        return

    # Generate the output decrypted file name by removing the ".BIJI" extension
    output_file = encrypted_file[:-5]  # Remove ".BIJI" from the file name (5 characters)

    # Decrypt the file
    decrypt_file(encrypted_file, output_file, private_key)

    # Remove the original encrypted file
    os.remove(encrypted_file)
    print(f"File decrypted successfully. Decrypted file saved as '{output_file}' and encrypted file '{encrypted_file}' removed.")

if __name__ == "__main__":
    main()
