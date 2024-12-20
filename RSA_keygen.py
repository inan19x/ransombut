# RSA_keygen.py

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_keypair():
    # Generate RSA key pair (private and public keys)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Generate the corresponding public key
    public_key = private_key.public_key()

    return private_key, public_key

def save_key_to_file(key, filename, key_type):
    """ Save the RSA key to a file in PEM format. """
    if key_type == 'private':
        with open(filename, 'wb') as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
        print(f"Private key saved to {filename}")
    elif key_type == 'public':
        with open(filename, 'wb') as f:
            f.write(
                key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )
        print(f"Public key saved to {filename}")

def main():
    # Prompt the user for the key pair file name
    file_name = input("Enter the base file name for the RSA key pair (without extension): ")

    # Generate the RSA key pair
    private_key, public_key = generate_rsa_keypair()

    # Save the private and public keys to separate files
    save_key_to_file(private_key, f"{file_name}_private.pem", "private")
    save_key_to_file(public_key, f"{file_name}_public.pem", "public")

if __name__ == "__main__":
    main()
