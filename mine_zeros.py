ZEROS = 5
VERSION = 0x20000000
PREVIOUS_BLOCK = "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"
TIME = 1735689600
PAYMENTS = [
    "Alice pays Bob 0.5 coins",
    "Bob pays Carol 0.2 coins",
    "Carol pays Dan 0.1 coins",
]

import hashlib
import time


def double_sha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def merkle_root(txids):
    level = txids
    while len(level) > 1:
        if len(level) % 2 == 1:
            level = level + [level[-1]]
        next_level = []
        for i in range(0, len(level), 2):
            next_level.append(double_sha256(level[i] + level[i + 1]))
        level = next_level
    return level[0]


def compact_bits(number):
    size = (number.bit_length() + 7) // 8
    mantissa = number >> (8 * (size - 3))
    if mantissa >= 0x800000:
        mantissa = mantissa >> 8
        size = size + 1
    return size * 0x1000000 + mantissa


def header_without_nonce(extra_nonce, bits):
    transactions = ["New coins for the miner, extra nonce " + str(extra_nonce)] + PAYMENTS
    txids = []
    for text in transactions:
        txids.append(double_sha256(text.encode()))
    root = merkle_root(txids)
    return (
        VERSION.to_bytes(4, "little")
        + bytes.fromhex(PREVIOUS_BLOCK)[::-1]
        + root
        + TIME.to_bytes(4, "little")
        + bits.to_bytes(4, "little")
    )


target = 0xFFFF * 2 ** (4 * (64 - ZEROS) - 16)
bits = compact_bits(target)
expected_tries = 2**256 // (target + 1)

print("For learning only, not financial advice.")
print("Guide: https://cryptonoobs.tech/knowledges/bitcoin-block-time-and-difficulty")
print("Try it in your browser: https://cryptonoobs.tech/practice/mining")
print(f"Zeros:          {ZEROS}")
print(f"Target:         {target:064x}")
print(f"Bits:           {bits:08x}")
print(f"Expected tries: about {expected_tries:,}")
print("Searching...")

extra_nonce = 0
nonce = 0
tries = 0
header_start = header_without_nonce(extra_nonce, bits)
started = time.time()

while True:
    header = header_start + nonce.to_bytes(4, "little")
    block_hash = double_sha256(header)[::-1]
    tries = tries + 1
    if int.from_bytes(block_hash, "big") <= target:
        break
    nonce = nonce + 1
    if nonce == 2**32:
        nonce = 0
        extra_nonce = extra_nonce + 1
        header_start = header_without_nonce(extra_nonce, bits)

seconds = time.time() - started

print(f"Found after:    {tries:,} tries ({seconds:.1f} seconds, about {tries / max(seconds, 0.001):,.0f} tries a second)")
print(f"Extra nonce:    {extra_nonce}")
print(f"Nonce:          {nonce}")
print(f"Header:         {header.hex()}")
print(f"Hash:           {block_hash.hex()}")
