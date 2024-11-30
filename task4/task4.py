from binascii import hexlify

# Given private key and modulus
N = int("BDDD9F7CF8B69B24810B0A0F02CE69549F5E94BAD865100F60698C13A5E190F24D8900B8E9126461110D51FA7D5C7B1E0F2DA28568D36D96BE65D9062DD2EE89", 16)
d = int("6D7690B4E44FA332709384C112C51E45037CEC12AD1FD71A866353B72033E3F44FE76BCC343CB4319CCD5049AE3B52CB65102249BAF44AB834311CC908E17461", 16)

# Step 1: Define the message
message = "This is a contract for $20,000"
message_modified = "This is a contract for ₩20,000"  # Slightly modified message

# Step 2: Convert the message to a hexadecimal integer
def message_to_int(msg):
    return int(hexlify(msg.encode()).decode(), 16)

M_original = message_to_int(message)
M_modified = message_to_int(message_modified)

# Step 3: Generate the signature using the private key
def sign_message(M, d, N):
    return pow(M, d, N)  # S = M^d mod N

S_original = sign_message(M_original, d, N)
S_modified = sign_message(M_modified, d, N)

# Step 4: Print the results
print(f"Original Message: {message}")
print(f"Original Signature: {hex(S_original)}\n")

print(f"Modified Message: {message_modified}")
print(f"Modified Signature: {hex(S_modified)}\n")

# Observe the difference
if S_original != S_modified:
    print("The signatures are different, indicating the change in the message!")
else:
    print("The signatures are the same, which shouldn't happen for RSA.")

