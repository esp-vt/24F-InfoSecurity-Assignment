from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def generate_keys(key_size=4096):
    """
    Generate RSA key pair.
    """
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_message(message, public_key):
    """
    Encrypt a message using the public key.
    """
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    ciphertext = cipher.encrypt(message)
    return ciphertext

def decrypt_message(ciphertext, private_key):
    """
    Decrypt a message using the private key.
    """
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

# Generate keys
private_key, public_key = generate_keys()

# Print the keys
print("Private Key:")
print(private_key.decode())
print("\nPublic Key:")
print(public_key.decode())

# Message to encrypt
message = b"This is my first RSA encrypted message!"

# Encrypt the message
ciphertext = encrypt_message(message, public_key)
print("\nEncrypted Message:")
print(ciphertext)

# Decrypt the message
decrypted_message = decrypt_message(ciphertext, private_key)
print("\nDecrypted Message:")
print(decrypted_message.decode())

