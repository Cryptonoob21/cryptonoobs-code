TXIDS = [
    "8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87",
    "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4",
    "6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4",
    "e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d",
]
INDEX = 2
ROOT = "f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766"
CHANGE_ONE_LETTER = False

import hashlib


def double_sha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def read_txid(text):
    return bytes.fromhex(text)[::-1]


def show(hash_bytes):
    return hash_bytes[::-1].hex()


def make_proof(txids, index):
    row = []
    for txid in txids:
        row.append(read_txid(txid))

    proof = []
    while len(row) > 1:
        if len(row) % 2 == 1:
            row = row + [row[-1]]
        if index % 2 == 0:
            proof.append(("right", row[index + 1]))
        else:
            proof.append(("left", row[index - 1]))

        next_row = []
        for i in range(0, len(row), 2):
            next_row.append(double_sha256(row[i] + row[i + 1]))
        row = next_row
        index = index // 2
    return proof


print("For learning only, not financial advice.")
print("Guide: https://cryptonoobs.tech/knowledges/what-really-means-mining-a-btc")
print("Try it in your browser: https://cryptonoobs.tech/practice/merkle")
print()

proof = make_proof(TXIDS, INDEX)

leaf = TXIDS[INDEX]
if CHANGE_ONE_LETTER:
    if leaf[0] == "0":
        leaf = "1" + leaf[1:]
    else:
        leaf = "0" + leaf[1:]

print(f"Transaction at position {INDEX} (counting from 0): {leaf}")
print(f"The proof is {len(proof)} hashes, not all {len(TXIDS)} transactions:")
for side, hash_bytes in proof:
    print(f"  {side:5} {show(hash_bytes)}")
print()

node = read_txid(leaf)
for side, hash_bytes in proof:
    if side == "right":
        node = double_sha256(node + hash_bytes)
    else:
        node = double_sha256(hash_bytes + node)
    print("Up one row: " + show(node))

print()
print("Root from the proof:  " + show(node))
print("Root in the header:   " + ROOT)
if show(node) == ROOT:
    print("The proof checks: this transaction is in the block.")
else:
    print("The proof fails: this transaction is not the one in the block.")
