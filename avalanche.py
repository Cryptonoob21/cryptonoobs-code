TEXT = "CryptoNoobs"
BIT = 0

import hashlib


def to_binary(number):
    return format(number, "08b")


def count_different_bits(first, second):
    count = 0
    for i in range(len(first)):
        different = first[i] ^ second[i]
        for bit in range(8):
            if different & (1 << bit):
                count = count + 1
    return count


original = TEXT.encode()
changed = bytes([original[0] ^ (0x80 >> BIT)]) + original[1:]

original_hash = hashlib.sha256(original).digest()
changed_hash = hashlib.sha256(changed).digest()
distance = count_different_bits(original_hash, changed_hash)

print("For learning only, not financial advice.")
print("Guide: https://cryptonoobs.tech/knowledges/what-is-a-hash")
print("Try it in your browser: https://cryptonoobs.tech/practice/hash")
print(f"Flipping bit {BIT} of the first byte (0 is the leftmost)")
print(f"Original first byte: {to_binary(original[0])}")
print(f"Changed first byte:  {to_binary(changed[0])}")
print(f"Original SHA-256:    {original_hash.hex()}")
print(f"Changed SHA-256:     {changed_hash.hex()}")
print(f"Different bits:      {distance} of 256")
print("One small change flips about half of the bits, so the count stays near 128.")
