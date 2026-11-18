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
| `keys.py` | Follows test words to a seed, keys and addresses (Legacy, Nested SegWit, Native SegWit, Taproot). Only the public example words get main network addresses; any other words get test format only. |
| `english.txt` | The 2,048 BIP39 English words, copied unchanged from [bitcoin/bips](https://github.com/bitcoin/bips/blob/a7f91321f25b5be8d93e901775621c21519e80b7/bip-0039/english.txt) (SHA-256 `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`). `keys.py` reads it. |
| `secp256k1.py` | The secp256k1 curve: adding points and turning a private key into a public key. `keys.py` uses it. |
| `base58.py` | Base58 and Base58Check, used for Legacy and Nested SegWit addresses and WIF keys. |
| `bech32.py` | Bech32 and Bech32m, used for `bc1` and `tb1` addresses. |

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
python3 keys.py
```

The key files are for learning with test keys only. They are not constant-time, have not been reviewed, and are not safe for real funds: never put real words in them. `keys.py` was checked against the official BIP39 (Trezor), BIP32, BIP49, BIP84 and BIP86 vectors and the SLIP-132 vectors, and `bech32.py` against the BIP173 and BIP350 lists.

MIT license, see `LICENSE`.
