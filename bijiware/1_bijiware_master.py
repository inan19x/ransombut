from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Function to generate RSA key pair
def generate_keys():
    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Generate the corresponding public key
    public_key = private_key.public_key()

    # Save the private key to a file
    with open("MASTER_private_key.pem", "wb") as private_key_file:
        private_key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Save the public key to a file
    with open("MASTER_public_key.pem", "wb") as public_key_file:
        public_key_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print(">> RSA key pair generated and saved as 'MASTER_private_key.pem' and 'MASTER_public_key.pem'.")
    print(">> WARNING!! DO NOT LOOSE YOUR MASTER KEY!!")

# Call the function to generate keys
if __name__ == "__main__":
    generate_keys()
