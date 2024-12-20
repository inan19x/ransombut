# RSA_encrypt.py

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os

def load_public_key(pub_key_file):
    """Load the RSA public key from a PEM file."""
    with open(pub_key_file, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read())
    return public_key

def encrypt_file(input_file, output_file, public_key):
    """Encrypt a file using the RSA public key."""
    # Read the input file data
    with open(input_file, 'rb') as f:
        data = f.read()

    # RSA encryption can only encrypt small pieces of data at a time (less than key size)
    # So, we'll split the data into chunks to encrypt
    max_chunk_size = public_key.key_size // 8 - 42  # RSA encryption max data size (based on padding)
    encrypted_data = b""

    # Split data into chunks and encrypt each chunk
    for i in range(0, len(data), max_chunk_size):
        chunk = data[i:i + max_chunk_size]
        encrypted_chunk = public_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_data += encrypted_chunk

    # Write the encrypted data to the output file
    with open(output_file, 'wb') as f:
        f.write(encrypted_data)

def main():
    # Prompt user for RSA public key file and file to encrypt
    pub_key_file = input("Enter the RSA public key file name (with .pem extension): ")
    input_file = input("Enter the file name to encrypt: ")

    # Check if the input file exists
    if not os.path.exists(input_file):
        print(f"Error: The file '{input_file}' does not exist.")
        return

    # Load the RSA public key
    try:
        public_key = load_public_key(pub_key_file)
    except Exception as e:
        print(f"Error loading public key: {e}")
        return

    # Generate the output encrypted file name by adding ".BIJI" extension
    output_file = input_file + ".BIJI"

    # Encrypt the file
    encrypt_file(input_file, output_file, public_key)

    # Remove the original plaintext file
    os.remove(input_file)
    print(f"File encrypted successfully. Encrypted file saved as '{output_file}' and original file '{input_file}' removed.")

if __name__ == "__main__":
    main()
