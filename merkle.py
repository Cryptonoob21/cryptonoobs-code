TXIDS = [
    "8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87",
    "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4",
    "6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4",
    "e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d",
]

import hashlib


def double_sha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def read_txid(text):
    return bytes.fromhex(text)[::-1]


def show(hash_bytes):
    return hash_bytes[::-1].hex()


print("For learning only, not financial advice.")
print("Guide: https://cryptonoobs.tech/knowledges/what-really-means-mining-a-btc")
print("Try it in your browser: https://cryptonoobs.tech/practice/merkle")
print()

row = []
for txid in TXIDS:
    row.append(read_txid(txid))

number = 0
while True:
    if len(row) == 1:
        print(f"Row {number} (1 hash)")
    else:
        print(f"Row {number} ({len(row)} hashes)")
    for hash_bytes in row:
        print("  " + show(hash_bytes))

    if len(row) == 1:
        break

    if len(row) % 2 == 1:
        print("  (odd count: the last hash is paired with a copy of itself)")
        row = row + [row[-1]]

    next_row = []
    for i in range(0, len(row), 2):
        next_row.append(double_sha256(row[i] + row[i + 1]))
    row = next_row
    number = number + 1

print()
print("Merkle root: " + show(row[0]))
