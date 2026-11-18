TEXT = "CryptoNoobs"

import hashlib


message = TEXT.encode()
length_in_bits = len(message) * 8

zeros = 0
while (len(message) + 1 + zeros) % 64 != 56:
    zeros = zeros + 1

length_field = length_in_bits.to_bytes(8, "big")
padded = message + b"\x80" + bytes(zeros) + length_field

print("For learning only, not financial advice.")
print("Guide: https://cryptonoobs.tech/knowledges/what-is-a-hash")
print("Try it in your browser: https://cryptonoobs.tech/practice/hash")
print(f"Text:          {TEXT}")
print(f"Message:       {message.hex()} ({len(message)} bytes)")
print("One byte:      80")
print(f"Zero bytes:    {zeros}")
print(f"Length field:  {length_field.hex()} ({length_in_bits} bits)")
print(f"Total length:  {len(padded)} bytes, {len(padded) // 64} block(s) of 64 bytes")

for i in range(0, len(padded), 64):
    print(f"Block {i // 64 + 1}:       {padded[i:i + 64].hex()}")

print(f"SHA-256:       {hashlib.sha256(message).hexdigest()}")
print("SHA-256 works on these blocks, so the hash above belongs to the same message.")
