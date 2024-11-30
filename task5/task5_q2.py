import os
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
# Generate large files for testing
def generate_file(size_kb, filename):
    with open(filename, 'wb') as f:
        f.write(os.urandom(size_kb * 1024))  # Write random data of specified size

# Measure signing time for a file
def measure_signing_time(filename, private_key):
    with open(filename, 'rb') as f:
        message = f.read()
    start_time = time()
    rsa_key = RSA.import_key(private_key)
    hash_message = SHA256.new(message)
    pkcs1_15.new(rsa_key).sign(hash_message)
    end_time = time()
    return end_time - start_time

# Generate keys
private_key, public_key = generate_keys()

# Test for different file sizes
file_sizes = [1, 100, 1024, 10240]  # Sizes in KB: 1KB, 100KB, 1MB, 10MB
for size in file_sizes:
    filename = f"test_{size}KB.txt"
    generate_file(size, filename)
    signing_time = measure_signing_time(filename, private_key)
    print(f"File Size: {size} KB | Signing Time: {signing_time:.6f} seconds")

    # Clean up test files
    os.remove(filename)

