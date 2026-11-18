TEXT = "CryptoNoobs"
FILE = ""
ALGORITHMS = ["sha256", "double-sha256", "sha1", "ripemd160", "hash160", "sha512"]

import hashlib

from ripemd160 import ripemd160


def read_file(path):
    chunks = []
    with open(path, "rb") as file:
        while True:
            chunk = file.read(256 * 1024)
            if len(chunk) == 0:
                break
            chunks.append(chunk)
    return b"".join(chunks)


def make_hash(name, data):
    if name == "sha256":
        return hashlib.sha256(data).digest()
    if name == "double-sha256":
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()
    if name == "sha1":
        return hashlib.sha1(data).digest()
    if name == "ripemd160":
        return ripemd160(data)
    if name == "hash160":
        return ripemd160(hashlib.sha256(data).digest())
    if name == "sha512":
        return hashlib.sha512(data).digest()
    return None


print("For learning only, not financial advice.")
print("Guide: https://cryptonoobs.tech/knowledges/what-is-a-hash")
print("Try it in your browser: https://cryptonoobs.tech/practice/hash")

if FILE != "":
    data = read_file(FILE)
    print(f"File: {FILE} ({len(data):,} bytes)")
else:
    data = TEXT.encode()
    print(f"Text: {TEXT}")

for name in ALGORITHMS:
    result = make_hash(name, data)
    if result is None:
        print(f"{name:<14} unknown algorithm")
        continue
    bits = str(len(result) * 8) + " bits"
    line = f"{name:<14} {bits:<9} {result.hex()}"
    if name == "sha1":
        line = line + " (broken)"
    print(line)
