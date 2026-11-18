BITS = 24
TEXT = "CryptoNoobs"

import hashlib
import time


def first_bits(data):
    number = int.from_bytes(hashlib.sha256(data).digest(), "big")
    return number >> (256 - BITS)


print("For learning only, not financial advice.")
print("Guide: https://cryptonoobs.tech/knowledges/what-is-a-hash")
print("Try it in your browser: https://cryptonoobs.tech/practice/hash")
print(f"Looking for two messages whose SHA-256 starts with the same {BITS} bits...")

seen = {}
n = 0
started = time.time()

while True:
    message = f"{TEXT} {n}"
    value = first_bits(message.encode())
    if value in seen:
        other = seen[value]
        break
    seen[value] = message
    n = n + 1

seconds = time.time() - started
tries = n + 1
expected = 1.18 * 2 ** (BITS / 2)
prefix = format(value, "0" + str(BITS) + "b")

print(f"Message 1:      {other}")
print(f"Message 2:      {message}")
print(f"SHA-256 1:      {hashlib.sha256(other.encode()).hexdigest()}")
print(f"SHA-256 2:      {hashlib.sha256(message.encode()).hexdigest()}")
print(f"Shared bits:    {prefix}")
print(f"Tries:          {tries:,} ({seconds:.2f} seconds)")
print(f"Expected tries: about {expected:,.0f}")
print("For the full 256-bit hash you would need about 2 ** 128 tries, so you will almost certainly not find one.")
