# ransombut
Python scripts to simulate ransomware methodologies to encrypt a file leveraging RSA and AES crypto algorithm.

The tools that demonstrate a fundamental aspect of information security: encryption. Leveraging both RSA and AES encryption algorithms, these tools simulate encryption and decryption processes often used in ransomware attacks, offering a practical introduction to how ransomware works. RSA is used for asymmetric encryption, ideal for securely sharing public keys, while AES is employed for efficient, symmetric encryption of larger files.  In a typical ransomware attack, cybercriminals encrypt a victim's files using strong encryption algorithms like AES, making them inaccessible until a ransom is paid. The attacker usually demands payment in cryptocurrency for the decryption key, which is often an RSA private key. By simulating this process, learners can understand how ransomware takes advantage on the strong cryptographic model to hold data hostage. These tools hopefully can provide insights into the importance of key management, backup strategies, and cybersecurity defenses in mitigating the impact of such attacks.

Encryption flows:
![ransombut-encrypt](https://github.com/user-attachments/assets/066ea62d-e800-4777-acf2-a4f573f17a96)

Decryption flows:
![ransombut-decrypt](https://github.com/user-attachments/assets/8f03968e-baf1-4e8f-9d15-828796968689)
