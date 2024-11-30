# Task 3: Decrypting a Message
from binascii import unhexlify

# Given private key and modulus
N = int("BDDD9F7CF8B69B24810B0A0F02CE69549F5E94BAD865100F60698C13A5E190F24D8900B8E9126461110D51FA7D5C7B1E0F2DA28568D36D96BE65D9062DD2EE89", 16)
d = int("6D7690B4E44FA332709384C112C51E45037CEC12AD1FD71A866353B72033E3F44FE76BCC343CB4319CCD5049AE3B52CB65102249BAF44AB834311CC908E17461", 16)

# Given ciphertext
C = int("35B8BC929DD26C75A17CDA4772FB9E6A0682ED019EE806D1507AFC064D4955BE031EACE40DD3B9F9421511EC0AF6600510E93E0C3D6F2270FF9A879C132476C", 16)

# Step 1: Decrypt the ciphertext
M = pow(C, d, N)  # M = C^d mod N

# Step 2: Convert the integer M back to hexadecimal
M_hex = hex(M)[2:]  # Convert to hex and remove the "0x" prefix if present
if len(M_hex) % 2 != 0:  # Ensure even-length hex string
    M_hex = "0" + M_hex

# Step 3: Convert hex to ASCII
plaintext = unhexlify(M_hex).decode('utf-8')

print(f"Decrypted Message: {plaintext}")

