/*
 * merkle.c: the Merkle root of a Bitcoin block, from its transaction ids.
 *
 * Every block header carries one 32-byte "Merkle root" that commits to all
 * the transactions in the block. It is built like a tournament:
 *   1. start with the list of transaction ids (txids),
 *   2. pair them up and hash each pair: double SHA-256 of left || right,
 *   3. if a level has an odd count, the last hash is paired with itself,
 *   4. repeat on the new, shorter list until one hash is left: the root.
 * Change any transaction and its txid changes, which changes every hash on
 * its path up to the root, so the header (and the block hash) changes too.
 *
 * Build:  cc -O2 -o merkle merkle.c        (needs sha256.c in the same folder)
 * Use:    ./merkle -t                      test with block 100000
 *         ./merkle < txids.txt             txids in any text: one per line,
 *                                          a JSON list, anything with 64-hex ids
 *         curl -s https://mempool.space/api/block/<block hash>/txids | ./merkle
 *         ./merkle -v < txids.txt          also print every level of the tree
 *
 * Byte order: block explorers show txids and the root reversed (the bytes of
 * the hash read backwards). The tree is computed on the real bytes, so this
 * program reverses each txid on the way in and the root on the way out.
 */

#define SHA256_LIB
#include "sha256.c"

#include <ctype.h>

/* Double SHA-256, the hash Bitcoin uses for txids, the tree and blocks. */
static void hash256(const uint8_t *data, size_t len, uint8_t out[32])
{
    uint8_t first[32];
    sha256(data, len, first, 0);
    sha256(first, sizeof first, out, 0);
}

/* Print a hash the way explorers show it: bytes reversed, in hex. */
static void print_reversed(const uint8_t h[32])
{
    uint8_t rev[32];
    char hex[65];
    int i;
    for (i = 0; i < 32; i++) rev[i] = h[31 - i];
    to_hex(rev, hex);
    printf("%s", hex);
}

static int hex_value(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    c = tolower(c);
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

/*
 * Compute and print the root of n hashes (internal byte order).
 * The array is overwritten level by level: each level is half the size.
 */
static void merkle_root(uint8_t (*level)[32], size_t n, int verbose, uint8_t root[32])
{
    size_t depth = 0, i;

    while (1) {
        if (verbose) {
            printf("level %zu: %zu hash%s\n", depth, n, n == 1 ? "" : "es");
            for (i = 0; i < n; i++) {
                printf("  ");
                print_reversed(level[i]);
                printf("\n");
            }
        }
        if (n == 1) break;

        for (i = 0; i < n; i += 2) {
            uint8_t pair[64];
            memcpy(pair, level[i], 32);
            /* Odd count: the last hash is paired with a copy of itself. */
            memcpy(pair + 32, level[i + 1 < n ? i + 1 : i], 32);
            hash256(pair, sizeof pair, level[i / 2]);
        }
        n = (n + 1) / 2;
        depth++;
    }
    memcpy(root, level[0], 32);
}

/* Read every run of exactly 64 hex characters in a file as a txid. */
static uint8_t (*read_txids(FILE *in, size_t *count))[32]
{
    size_t cap = 1024, n = 0, run = 0;
    uint8_t (*ids)[32] = malloc(cap * 32);
    char buf[64];
    int c;

    if (!ids) return NULL;
    while (1) {
        c = getc(in);
        if (c != EOF && hex_value(c) >= 0) {
            if (run < 64) buf[run] = (char)c;
            run++;
            continue;
        }
        if (run == 64) {
            int i;
            if (n == cap) {
                uint8_t (*bigger)[32] = realloc(ids, cap * 2 * 32);
                if (!bigger) { free(ids); return NULL; }
                ids = bigger;
                cap *= 2;
            }
            /* Text byte i is hash byte 31 - i: reverse while decoding. */
            for (i = 0; i < 32; i++) {
                ids[n][31 - i] = (uint8_t)(hex_value(buf[2 * i]) << 4 | hex_value(buf[2 * i + 1]));
            }
            n++;
        }
        run = 0;
        if (c == EOF) break;
    }
    *count = n;
    return ids;
}

/* Block 100000: 4 transactions and the Merkle root in its header. */
static int run_test(void)
{
    static const char *txids =
        "8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87\n"
        "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4\n"
        "6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4\n"
        "e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d\n";
    static const char *expected = "f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766";
    FILE *in = tmpfile();
    size_t n;
    uint8_t (*ids)[32];
    uint8_t root[32], rev[32];
    char hex[65];
    int i, ok;

    if (!in) { perror("tmpfile"); return 1; }
    fputs(txids, in);
    rewind(in);
    ids = read_txids(in, &n);
    fclose(in);
    if (!ids) { fprintf(stderr, "out of memory\n"); return 1; }

    merkle_root(ids, n, 1, root);
    for (i = 0; i < 32; i++) rev[i] = root[31 - i];
    to_hex(rev, hex);
    ok = strcmp(hex, expected) == 0;
    printf("\n%s  Merkle root of block 100000\n", ok ? "ok  " : "FAIL");
    free(ids);
    return ok ? 0 : 1;
}

int main(int argc, char **argv)
{
    int verbose = 0;
    size_t n;
    uint8_t (*ids)[32];
    uint8_t root[32];

    if (argc > 1 && strcmp(argv[1], "-t") == 0) return run_test();
    if (argc > 1 && strcmp(argv[1], "-v") == 0) verbose = 1;
    else if (argc > 1) {
        fprintf(stderr, "usage: %s [-v] < txids    or    %s -t\n", argv[0], argv[0]);
        return 2;
    }

    ids = read_txids(stdin, &n);
    if (!ids) { fprintf(stderr, "out of memory\n"); return 1; }
    if (n == 0) { fprintf(stderr, "no txids found on standard input\n"); free(ids); return 1; }

    merkle_root(ids, n, verbose, root);
    if (verbose) printf("\n");
    printf("transactions: %zu\nmerkle root:  ", n);
    print_reversed(root);
    printf("\n");
    free(ids);
    return 0;
}
