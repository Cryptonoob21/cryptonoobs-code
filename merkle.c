const char *TXIDS[] = {
    "8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87",
    "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4",
    "6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4",
    "e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d"
};

#include "sha256.h"

#define COUNT (sizeof(TXIDS) / sizeof(TXIDS[0]))

void read_txid(const char *text, unsigned char txid[32])
{
    for (int i = 0; i < 32; i++) {
        unsigned int byte;
        sscanf(text + 2 * i, "%2x", &byte);
        txid[31 - i] = byte;
    }
}

void print_hash(unsigned char hash[32])
{
    for (int i = 31; i >= 0; i--) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

int main(void)
{
    unsigned char level[COUNT][32];
    int count = COUNT;

    for (int i = 0; i < count; i++) {
        read_txid(TXIDS[i], level[i]);
    }

    int depth = 0;
    while (1) {
        printf("Level %d (%d hashes)\n", depth, count);
        for (int i = 0; i < count; i++) {
            printf("  ");
            print_hash(level[i]);
        }

        if (count == 1) {
            break;
        }

        for (int i = 0; i < count; i += 2) {
            unsigned char pair[64];
            memcpy(pair, level[i], 32);
            if (i + 1 < count) {
                memcpy(pair + 32, level[i + 1], 32);
            } else {
                memcpy(pair + 32, level[i], 32);
            }
            double_sha256(pair, 64, level[i / 2]);
        }

        count = (count + 1) / 2;
        depth++;
    }

    printf("\nMerkle root: ");
    print_hash(level[0]);

    return 0;
}
