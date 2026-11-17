# CryptoNoobs code

Small, simple programs that show how Bitcoin works under the hood. They go with the guides on [cryptonoobs.tech](https://cryptonoobs.tech). For learning only, not financial advice. To change what a program does, edit the values at the top of the file.

| File | What it does |
|------|--------------|
| `sha256.h` | The SHA-256 hash function, written from scratch. The C programs below use it. |
| `sha256.c` | Prints the SHA-256 (or double SHA-256) of a text. |
| `merkle.c` | Builds the Merkle tree of a block from its transaction ids and prints every level up to the Merkle root. |
| `mine.c` | Tries nonces until the hash of a block header is below the target, the work miners do. |
| `mine.py` | Gets a real block from mempool.space, builds its header and target, and uses `mine.c` to find the block's nonce again. |
| `mine_zeros.py` | Builds a made-up block and tries nonces until its hash starts with `ZEROS` zeros, the same block as the mining page on the site. |

```sh
cc -o sha256 sha256.c && ./sha256
cc -o merkle merkle.c && ./merkle
python3 mine.py
python3 mine_zeros.py
```

MIT license, see `LICENSE`.
