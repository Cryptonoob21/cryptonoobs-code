/*
 * mine.c: search for the nonce that makes a Bitcoin block header valid.
 *
 * A block header is 80 bytes:
 *   version (4) | previous block hash (32) | Merkle root (32) | time (4) | bits (4) | nonce (4)
 * Mining means trying nonces until double SHA-256 of the header, read as a
 * 256-bit number, is at or below the target. The first 76 bytes are fixed,
 * only the last 4 change, so this program takes those 76 bytes and the target
 * and tries every nonce in a range.
 *
 * mine.py fetches a real block, builds the 76 bytes and runs this program.
 *
 * Build:  cc -O2 -o mine mine.c        (needs sha256.c in the same folder)
 * Use:    ./mine <header 76 bytes hex> <target 64 hex> <first nonce> <last nonce>
 * Output: "found <nonce> <block hash>" or "not found", plus speed on stderr.
 */

#define SHA256_LIB
#include "sha256.c"

#include <time.h>

static int parse_hex(const char *hex, uint8_t *out, size_t len)
{
    size_t i;
    if (strlen(hex) != 2 * len) return 0;
    for (i = 0; i < len; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1) return 0;
        out[i] = (uint8_t)byte;
    }
    return 1;
}

int main(int argc, char **argv)
{
    uint8_t header[80], target[32], hash[32], first[32], display[32];
    sha256_ctx midstate, ctx;
    unsigned long long nonce, start, end, tried = 0;
    char hex[65];
    clock_t t0;
    double seconds;
    int i, found = 0;

    if (argc != 5 || !parse_hex(argv[1], header, 76) || !parse_hex(argv[2], target, 32)) {
        fprintf(stderr, "usage: %s <header 76 bytes hex> <target 64 hex> <first nonce> <last nonce>\n", argv[0]);
        return 2;
    }
    start = strtoull(argv[3], NULL, 10);
    end = strtoull(argv[4], NULL, 10);
    if (end > 0xffffffffULL) end = 0xffffffffULL;

    /*
     * Midstate: SHA-256 eats 64 bytes at a time, and the first 64 bytes of
     * the header never change while we try nonces. Hash them once and reuse
     * that state; each try only hashes the last 16 bytes. Real miners do this.
     */
    sha256_init(&midstate, 0);
    sha256_update(&midstate, header, 64);

    t0 = clock();
    for (nonce = start; nonce <= end; nonce++) {
        /* The nonce goes in the last 4 bytes, little-endian. */
        header[76] = (uint8_t)nonce;
        header[77] = (uint8_t)(nonce >> 8);
        header[78] = (uint8_t)(nonce >> 16);
        header[79] = (uint8_t)(nonce >> 24);

        ctx = midstate;
        sha256_update(&ctx, header + 64, 16);
        sha256_final(&ctx, first);
        sha256(first, sizeof first, hash, 0); /* second SHA-256 */
        tried++;

        /*
         * The hash is a little-endian number: its last byte is the most
         * significant. Reverse it to compare with the big-endian target.
         * This reversed form is also the block hash explorers show.
         */
        for (i = 0; i < 32; i++) display[i] = hash[31 - i];
        if (memcmp(display, target, 32) <= 0) {
            found = 1;
            break;
        }
    }
    seconds = (double)(clock() - t0) / CLOCKS_PER_SEC;

    if (found) {
        to_hex(display, hex);
        printf("found %llu %s\n", nonce, hex);
    } else {
        printf("not found\n");
    }
    fprintf(stderr, "tried %llu nonces in %.2f s (%.0f hashes per second)\n",
            tried, seconds, seconds > 0 ? tried / seconds : 0.0);
    return found ? 0 : 1;
}
