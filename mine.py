BLOCK_HEIGHT = 840000
SEARCH_FROM_ZERO = False
WINDOW = 1000000

import ctypes
import hashlib
import json
import subprocess
import time
import urllib.request


def get(url):
    request = urllib.request.Request(url, headers={"User-Agent": "cryptonoobs-code"})
    return urllib.request.urlopen(request).read().decode()


block_hash = get(f"https://mempool.space/api/block-height/{BLOCK_HEIGHT}")
block = json.loads(get(f"https://mempool.space/api/block/{block_hash}"))

header = (
    block["version"].to_bytes(4, "little")
    + bytes.fromhex(block["previousblockhash"])[::-1]
    + bytes.fromhex(block["merkle_root"])[::-1]
    + block["timestamp"].to_bytes(4, "little")
    + block["bits"].to_bytes(4, "little")
)

exponent = block["bits"] >> 24
mantissa = block["bits"] & 0xFFFFFF
target = mantissa * 256 ** (exponent - 3)

print(f"Block:          {BLOCK_HEIGHT}")
print(f"Previous block: {block['previousblockhash']}")
print(f"Merkle root:    {block['merkle_root']}")
print(f"Target:         {target:064x}")

if SEARCH_FROM_ZERO:
    start = 0
    end = 2**32 - 1
else:
    start = max(0, block["nonce"] - WINDOW)
    end = min(2**32 - 1, block["nonce"] + WINDOW)

print(f"Searching nonces from {start} to {end}...")

subprocess.run(["cc", "-O2", "-shared", "-fPIC", "-o", "mine.so", "mine.c"], check=True)
mine = ctypes.CDLL("./mine.so")
mine.find_nonce.restype = ctypes.c_longlong
mine.find_nonce.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_longlong, ctypes.c_longlong]

started = time.time()
nonce = mine.find_nonce(header, target.to_bytes(32, "big"), start, end)
seconds = time.time() - started

if nonce == -1:
    print("No valid nonce in this range.")
else:
    full_header = header + nonce.to_bytes(4, "little")
    found_hash = hashlib.sha256(hashlib.sha256(full_header).digest()).digest()[::-1].hex()
    print(f"Nonce found:    {nonce} ({seconds:.1f} seconds)")
    print(f"Block hash:     {found_hash}")
    print(f"Same as block:  {found_hash == block['id']}")
