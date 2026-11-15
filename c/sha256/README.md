# SHA-256 in C

A from-scratch implementation of SHA-256 (FIPS 180-4) in one file, [`sha256.c`](sha256.c), written to be read alongside the guide [What is a HASH](https://cryptonoobs.tech/knowledges/what-is-a-hash).

## Build and test

```sh
make          # or: cc -std=c99 -O2 -Wall -Wextra -o sha256 sha256.c
make test     # checks "", "abc", a 448-bit message and one million "a"
```

## Use

```sh
./sha256 "hello"            # hash a text
echo -n "hello" | ./sha256  # hash standard input (files work too: ./sha256 < file)
./sha256 -d "hello"         # double SHA-256, sha256(sha256(x)), as Bitcoin does
./sha256 -v "abc"           # print the working variables after each of the 64 rounds
```

Compare with your system: `echo -n "hello" | shasum -a 256` (macOS) or `sha256sum` (Linux).

## How the file is organized

1. **Constants.** The initial hash value (square roots of the first 8 primes) and the 64 round constants (cube roots of the first 64 primes).
2. **Bit functions.** Rotate right, Choose, Majority and the four mixing functions.
3. **State.** The 8 words of the hash value plus a buffer for the current 512-bit block.
4. **Compression.** Expands one block into 64 words and runs 64 rounds over the working variables `a` to `h`.
5. **Padding.** Appends a `1` bit, zeros, and the message length, so every message becomes whole 512-bit blocks.
6. **Command line.** Hex output, the `-d`, `-v` and `-t` options.

## Try this

- Hash `hello` and `Hello`. One letter changes the whole output: the avalanche effect from the guide.
- Run `./sha256 -v "abc"` and watch how fast the words stop looking like the input.
- Hash an empty message and a book: the output is always 64 hex characters (256 bits).
