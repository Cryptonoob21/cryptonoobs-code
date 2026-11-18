# CryptoNoobs code

Small, simple programs that show how Bitcoin works under the hood. They go with the guides on [cryptonoobs.tech](https://cryptonoobs.tech). For learning only, not financial advice. To change what a program does, edit the values at the top of the file.

| File | What it does |
|------|--------------|
| `sha256.h` | The SHA-256 hash function, written from scratch. The C programs below use it. |
| `sha256.c` | Prints the SHA-256 (or double SHA-256) of a text. |
| `merkle.c` | Builds the Merkle tree of a block from its transaction ids and prints every level up to the Merkle root. |
| `merkle.py` | The same tree in Python: prints every row of block 100,000's transaction ids up to the Merkle root. |
| `merkle_proof.py` | Proves one transaction is in a block with only a few hashes, and shows the proof fail after one letter changes. |
| `mine.c` | Tries nonces until the hash of a block header is below the target, the work miners do. |
| `mine.py` | Gets a real block from mempool.space, builds its header and target, and uses `mine.c` to find the block's nonce again. |
| `mine_zeros.py` | Builds a made-up block and tries nonces until its hash starts with `ZEROS` zeros, the same block as the mining page on the site. |
| `hash.py` | Prints the hash of a text or a file with several algorithms side by side: SHA-256, double SHA-256, SHA-1, RIPEMD-160, HASH160 and SHA-512. |
| `ripemd160.py` | The RIPEMD-160 hash function, written from scratch. `hash.py` uses it. |
| `padding.py` | Shows how SHA-256 pads a message into 64-byte blocks before hashing it. |
| `avalanche.py` | Flips one bit of a text and counts how many bits of the SHA-256 hash change. |
| `collision.py` | Looks for two messages whose SHA-256 starts with the same `BITS` bits, the birthday search. |

```sh
cc -o sha256 sha256.c && ./sha256
cc -o merkle merkle.c && ./merkle
python3 merkle.py
python3 merkle_proof.py
python3 mine.py
python3 mine_zeros.py
python3 hash.py
python3 padding.py
python3 avalanche.py
python3 collision.py
```

MIT license, see `LICENSE`.
