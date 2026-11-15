# CryptoNoobs code

Small, readable programs that show how Bitcoin works under the hood. They go with the guides on [cryptonoobs.tech](https://cryptonoobs.tech). No external libraries; for learning only, not financial advice.

| File | What it does |
|------|--------------|
| `sha256.c` | SHA-256 from scratch, step by step. Hashes a text, does Bitcoin's double SHA-256 (`-d`), prints the 64 rounds (`-v`) and runs the official tests (`-t`). |
| `merkle.c` | Builds the Merkle root of a block from its transaction ids, the same root stored in the block header (`-v` prints every level of the tree). |
| `mine.c` | Tries nonces until the double SHA-256 of a block header is below the target: the work miners do. |
| `mine.py` | Fetches a real block, builds its header and target, and runs `mine.c` to find the block's nonce again. |

```sh
cc -O2 -o sha256 sha256.c && ./sha256 "hello"
cc -O2 -o merkle merkle.c && ./merkle -t
python3 mine.py 840000
```
