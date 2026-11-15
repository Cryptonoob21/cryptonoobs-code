"""mine.py: mine a real Bitcoin block again, with the nonce search in C.

Python does the bookkeeping: it fetches a block from the mempool.space API,
builds the first 76 bytes of its header and turns "bits" into the target.
C does the heavy part: mine.c tries nonces with double SHA-256 (sha256.c).

Use:
    python3 mine.py              block 840000 (the 2024 halving)
    python3 mine.py 170          any block height
    python3 mine.py 840000 --full  search from nonce 0 (can take up to an hour)

A real miner does not know the answer, so it scans all 4.3 billion nonces
(and then changes the time or the coinbase and scans again). To finish in
seconds, the default search starts 1,000,000 nonces before the real one.
Needs Python 3 and a C compiler (cc, gcc or clang). Educational only.
"""

import json
import os
import subprocess
import sys
import urllib.request

API = "https://mempool.space/api"
HERE = os.path.dirname(os.path.abspath(__file__))
WINDOW = 1_000_000


def get(path):
    request = urllib.request.Request(API + path, headers={"User-Agent": "cryptonoobs-code"})
    with urllib.request.urlopen(request, timeout=20) as response:
        return response.read().decode()


def fetch_block(height):
    block_hash = get(f"/block-height/{height}").strip()
    return json.loads(get(f"/block/{block_hash}"))


def header_without_nonce(block):
    """The first 76 bytes of the header, in the order Bitcoin hashes them.

    Numbers are little-endian. Hashes are stored reversed compared with how
    explorers print them, so we reverse them back with [::-1].
    """
    return (
        block["version"].to_bytes(4, "little")
        + bytes.fromhex(block["previousblockhash"])[::-1]
        + bytes.fromhex(block["merkle_root"])[::-1]
        + block["timestamp"].to_bytes(4, "little")
        + block["bits"].to_bytes(4, "little")
    )


def target_from_bits(bits):
    """'bits' packs the target: 1 byte of exponent, 3 bytes of mantissa.

    target = mantissa * 256 ** (exponent - 3)
    """
    exponent = bits >> 24
    mantissa = bits & 0xFFFFFF
    return mantissa * 256 ** (exponent - 3)


def compile_miner():
    """Build ./mine from mine.c if it is missing or older than the C files."""
    binary = os.path.join(HERE, "mine")
    sources = [os.path.join(HERE, name) for name in ("mine.c", "sha256.c")]
    if os.path.exists(binary) and all(os.path.getmtime(binary) > os.path.getmtime(s) for s in sources):
        return binary
    compiler = os.environ.get("CC", "cc")
    print(f"compiling mine.c with {compiler} ...")
    subprocess.run([compiler, "-O2", "-o", binary, sources[0]], check=True)
    return binary


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    full = "--full" in sys.argv
    height = int(args[0]) if args else 840000

    block = fetch_block(height)
    header = header_without_nonce(block)
    target = target_from_bits(block["bits"])
    real_nonce = block["nonce"]

    print(f"block {height}")
    print(f"  previous block  {block['previousblockhash']}")
    print(f"  merkle root     {block['merkle_root']}")
    print(f"  time            {block['timestamp']}")
    print(f"  bits            {block['bits']:#010x}")
    print(f"  target          {target:064x}")

    if full:
        first, last = 0, 2**32 - 1
    else:
        first = max(0, real_nonce - WINDOW)
        last = min(2**32 - 1, real_nonce + WINDOW)
    miner = compile_miner()
    print(f"searching nonces {first:,} to {last:,} in C ...")
    result = subprocess.run(
        [miner, header.hex(), f"{target:064x}", str(first), str(last)],
        capture_output=True, text=True,
    )
    print(result.stderr.strip())

    words = result.stdout.split()
    if not words or words[0] != "found":
        print("no valid nonce in this range")
        return 1

    nonce, block_hash = int(words[1]), words[2]
    print(f"nonce found     {nonce}")
    print(f"block hash      {block_hash}")
    print(f"matches block   {'yes' if nonce == real_nonce and block_hash == block['id'] else 'no'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
