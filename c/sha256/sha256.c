/*
 * sha256.c: SHA-256 from scratch, written to be read.
 *
 * Companion code for the CryptoNoobs guide "What is a HASH":
 * https://cryptonoobs.tech/knowledges/what-is-a-hash
 *
 * SHA-256 is the hash function Bitcoin uses for mining and for transaction
 * and block ids. This file follows the official specification (FIPS 180-4)
 * step by step, with no external libraries, so you can see every operation.
 *
 * Build:  make            (or: cc -std=c99 -O2 -Wall -Wextra -o sha256 sha256.c)
 * Use:    ./sha256 "hello"           hash a text
 *         echo -n "hello" | ./sha256  hash standard input
 *         ./sha256 -d "hello"        double SHA-256, as Bitcoin does
 *         ./sha256 -v "abc"          show the 64 rounds of each block
 *         ./sha256 -t                run the official test vectors
 *
 * Educational code: it is correct, but it is not hardened or optimized.
 * For real systems use a reviewed library (OpenSSL, libsodium, ...).
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------ */
/* 1) Constants                                                              */
/* ------------------------------------------------------------------------ */

/*
 * Initial hash value H(0): the first 32 bits of the fractional parts of the
 * square roots of the first 8 prime numbers (2, 3, 5, 7, 11, 13, 17, 19).
 * Using "nothing up my sleeve" numbers shows nobody picked them to hide a
 * backdoor.
 */
static const uint32_t H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

/*
 * Round constants K[0..63]: the first 32 bits of the fractional parts of the
 * cube roots of the first 64 prime numbers. One constant per round.
 */
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

/* ------------------------------------------------------------------------ */
/* 2) The six bit functions                                                  */
/* ------------------------------------------------------------------------ */

/* Rotate right: bits that fall off the right end come back on the left. */
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

/* Choose: for each bit, if x is 1 take y, else take z. */
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))

/* Majority: for each bit, the value that appears at least twice in x, y, z. */
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

/* Mixing functions used on the working variables a and e. */
#define BSIG0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define BSIG1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))

/* Mixing functions used to expand the message schedule. */
#define SSIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SSIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

/* ------------------------------------------------------------------------ */
/* 3) Hashing state                                                          */
/* ------------------------------------------------------------------------ */

typedef struct {
    uint32_t h[8];        /* current hash value, updated after every block */
    uint8_t block[64];    /* bytes waiting to fill a 512-bit block */
    size_t block_len;     /* how many bytes are in block[] */
    uint64_t total_len;   /* total message length in bytes */
    int verbose;          /* print every round when set */
    unsigned block_count; /* blocks processed so far (for verbose output) */
} sha256_ctx;

static void sha256_init(sha256_ctx *ctx, int verbose)
{
    memcpy(ctx->h, H0, sizeof H0);
    ctx->block_len = 0;
    ctx->total_len = 0;
    ctx->verbose = verbose;
    ctx->block_count = 0;
}

/* ------------------------------------------------------------------------ */
/* 4) The compression function: one 512-bit block, 64 rounds                 */
/* ------------------------------------------------------------------------ */

static void sha256_compress(sha256_ctx *ctx, const uint8_t block[64])
{
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    int t;

    /*
     * Message schedule. The first 16 words are the block itself, read as
     * big-endian 32-bit numbers. The other 48 are mixed from earlier words,
     * so every input bit ends up influencing many rounds.
     */
    for (t = 0; t < 16; t++) {
        w[t] = ((uint32_t)block[4 * t] << 24) | ((uint32_t)block[4 * t + 1] << 16) |
               ((uint32_t)block[4 * t + 2] << 8) | (uint32_t)block[4 * t + 3];
    }
    for (t = 16; t < 64; t++) {
        w[t] = SSIG1(w[t - 2]) + w[t - 7] + SSIG0(w[t - 15]) + w[t - 16];
    }

    /* Working variables start from the current hash value. */
    a = ctx->h[0]; b = ctx->h[1]; c = ctx->h[2]; d = ctx->h[3];
    e = ctx->h[4]; f = ctx->h[5]; g = ctx->h[6]; h = ctx->h[7];

    ctx->block_count++;
    if (ctx->verbose) {
        printf("\nBlock %u\n", ctx->block_count);
        printf(" t   a        b        c        d        e        f        g        h\n");
    }

    /* 64 rounds. Additions wrap around modulo 2^32 (uint32_t does that). */
    for (t = 0; t < 64; t++) {
        uint32_t t1 = h + BSIG1(e) + CH(e, f, g) + K[t] + w[t];
        uint32_t t2 = BSIG0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
        if (ctx->verbose) {
            printf("%2d   %08x %08x %08x %08x %08x %08x %08x %08x\n", t, a, b, c, d, e, f, g, h);
        }
    }

    /* Add the result to the previous hash value. */
    ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c; ctx->h[3] += d;
    ctx->h[4] += e; ctx->h[5] += f; ctx->h[6] += g; ctx->h[7] += h;
}

/* ------------------------------------------------------------------------ */
/* 5) Feeding data and padding                                               */
/* ------------------------------------------------------------------------ */

static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        ctx->block[ctx->block_len++] = data[i];
        if (ctx->block_len == 64) {
            sha256_compress(ctx, ctx->block);
            ctx->block_len = 0;
        }
    }
    ctx->total_len += len;
}

/*
 * Padding makes the message a multiple of 512 bits:
 *   1. append one "1" bit (the byte 0x80),
 *   2. append "0" bits until 64 bits are left in the last block,
 *   3. append the original length in bits as a 64-bit big-endian number.
 * This is why the output never depends on how the data was split.
 */
static void sha256_final(sha256_ctx *ctx, uint8_t out[32])
{
    uint64_t bit_len = ctx->total_len * 8;
    int i;

    ctx->block[ctx->block_len++] = 0x80;
    if (ctx->block_len > 56) {
        /* No room for the length: fill this block with zeros and start another. */
        while (ctx->block_len < 64) ctx->block[ctx->block_len++] = 0x00;
        sha256_compress(ctx, ctx->block);
        ctx->block_len = 0;
    }
    while (ctx->block_len < 56) ctx->block[ctx->block_len++] = 0x00;
    for (i = 7; i >= 0; i--) {
        ctx->block[ctx->block_len++] = (uint8_t)(bit_len >> (8 * i));
    }
    sha256_compress(ctx, ctx->block);

    /* The digest is the 8 words of the hash value, written big-endian. */
    for (i = 0; i < 8; i++) {
        out[4 * i]     = (uint8_t)(ctx->h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(ctx->h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(ctx->h[i] >> 8);
        out[4 * i + 3] = (uint8_t)(ctx->h[i]);
    }
}

/* One-shot helper. */
static void sha256(const uint8_t *data, size_t len, uint8_t out[32], int verbose)
{
    sha256_ctx ctx;
    sha256_init(&ctx, verbose);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
}

/* ------------------------------------------------------------------------ */
/* 6) Command line                                                           */
/* ------------------------------------------------------------------------ */

static void to_hex(const uint8_t digest[32], char hex[65])
{
    static const char digits[] = "0123456789abcdef";
    int i;
    for (i = 0; i < 32; i++) {
        hex[2 * i] = digits[digest[i] >> 4];
        hex[2 * i + 1] = digits[digest[i] & 0x0f];
    }
    hex[64] = '\0';
}

/* Known answers from FIPS 180-4 and NIST examples. */
static int run_tests(void)
{
    static const struct { const char *input; const char *expected; } cases[] = {
        { "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
        { "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
        { "hello", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" },
    };
    uint8_t digest[32];
    char hex[65];
    size_t i;
    int failures = 0;

    for (i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        sha256((const uint8_t *)cases[i].input, strlen(cases[i].input), digest, 0);
        to_hex(digest, hex);
        int ok = strcmp(hex, cases[i].expected) == 0;
        printf("%s  sha256(\"%s\")\n", ok ? "ok  " : "FAIL", cases[i].input);
        failures += !ok;
    }

    /* One million "a": many blocks, fed in uneven pieces. */
    {
        sha256_ctx ctx;
        uint8_t chunk[997];
        size_t left = 1000000;
        memset(chunk, 'a', sizeof chunk);
        sha256_init(&ctx, 0);
        while (left > 0) {
            size_t n = left < sizeof chunk ? left : sizeof chunk;
            sha256_update(&ctx, chunk, n);
            left -= n;
        }
        sha256_final(&ctx, digest);
        to_hex(digest, hex);
        int ok = strcmp(hex, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") == 0;
        printf("%s  sha256(one million \"a\")\n", ok ? "ok  " : "FAIL");
        failures += !ok;
    }

    printf(failures ? "\n%d test(s) failed\n" : "\nall tests passed\n", failures);
    return failures ? 1 : 0;
}

/* Read all of standard input into memory. */
static uint8_t *read_stdin(size_t *len)
{
    size_t cap = 4096, n = 0, got;
    uint8_t *buf = malloc(cap);
    if (!buf) return NULL;
    while ((got = fread(buf + n, 1, cap - n, stdin)) > 0) {
        n += got;
        if (n == cap) {
            uint8_t *bigger = realloc(buf, cap * 2);
            if (!bigger) { free(buf); return NULL; }
            buf = bigger;
            cap *= 2;
        }
    }
    *len = n;
    return buf;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s [-d] [-v] [text]\n"
            "       %s -t\n"
            "  text  the message to hash; without it, standard input is read\n"
            "  -d    double SHA-256: sha256(sha256(x)), as Bitcoin does\n"
            "  -v    print the 64 rounds of every block\n"
            "  -t    run the official test vectors\n",
            prog, prog);
}

int main(int argc, char **argv)
{
    int double_hash = 0, verbose = 0, i;
    const char *text = NULL;
    uint8_t *data;
    size_t len;
    uint8_t digest[32];
    char hex[65];

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0) return run_tests();
        else if (strcmp(argv[i], "-d") == 0) double_hash = 1;
        else if (strcmp(argv[i], "-v") == 0) verbose = 1;
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) { usage(argv[0]); return 0; }
        else if (argv[i][0] == '-' && argv[i][1] != '\0') { usage(argv[0]); return 2; }
        else if (text == NULL) text = argv[i];
        else { usage(argv[0]); return 2; }
    }

    if (text != NULL) {
        data = (uint8_t *)text;
        len = strlen(text);
    } else {
        data = read_stdin(&len);
        if (data == NULL) { fprintf(stderr, "out of memory\n"); return 1; }
    }

    sha256(data, len, digest, verbose);
    if (double_hash) {
        /* Bitcoin hashes the 32-byte digest again (the bytes, not the hex text). */
        uint8_t first[32];
        memcpy(first, digest, sizeof first);
        sha256(first, sizeof first, digest, verbose);
    }

    to_hex(digest, hex);
    if (verbose) printf("\n");
    printf("%s\n", hex);

    if (text == NULL) free(data);
    return 0;
}
