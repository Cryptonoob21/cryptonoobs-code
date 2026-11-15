# CryptoNoobs code

Small, readable programs in C and Python that go with the guides on [cryptonoobs.tech](https://cryptonoobs.tech).

Each program is written to be studied: no external libraries, comments that follow the math step by step, and a self-test against official test vectors. They are educational code, not production code; for real systems, use a reviewed library.

## Contents

| Folder | Language | What it shows | Guide |
|--------|----------|---------------|-------|
| [`c/sha256`](c/sha256) | C | SHA-256 from scratch, Bitcoin's double SHA-256, and every one of the 64 rounds | [What is a HASH](https://cryptonoobs.tech/knowledges/what-is-a-hash) |

## Run

You need a C compiler (`cc`, `gcc` or `clang`) and `make`.

```sh
cd c/sha256
make test          # official test vectors
./sha256 "hello"   # 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
```

## Notes

Everything here is for learning. Nothing in this repository is financial advice.

## License

[MIT](LICENSE)
