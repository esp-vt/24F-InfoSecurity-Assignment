from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from time import time

def generate_keys(key_size=2048):
    """
    Generate RSA key pair.
    """
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def sign_message(message, private_key):
    """
    Sign a message using the private key.
    """
    rsa_key = RSA.import_key(private_key)
    hash_message = SHA256.new(message.encode())  # Create a hash of the message
    signature = pkcs1_15.new(rsa_key).sign(hash_message)  # Generate signature
    return signature

def verify_signature(message, signature, public_key):
    """
    Verify the message's signature using the public key.
    """
    rsa_key = RSA.import_key(public_key)
    hash_message = SHA256.new(message.encode())
    try:
        pkcs1_15.new(rsa_key).verify(hash_message, signature)
        return True
    except (ValueError, TypeError):
        return False

# Generate keys
private_key, public_key = generate_keys()

# Message to sign and verify
message = "This is my own message for RSA signing and verification!"

# Sign the message
signature = sign_message(message, private_key)
print("Message:", message)
print("Signature:", signature.hex())

# Verify the signature
is_valid = verify_signature(message, signature, public_key)
print("Signature Valid:", is_valid)

