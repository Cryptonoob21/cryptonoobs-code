#include "sha256.h"

int is_below_target(unsigned char hash[32], const unsigned char *target)
{
    for (int i = 0; i < 32; i++) {
        if (hash[31 - i] < target[i]) {
            return 1;
        }
        if (hash[31 - i] > target[i]) {
            return 0;
        }
    }
    return 1;
}

long long find_nonce(const unsigned char *header76, const unsigned char *target, long long start, long long end)
{
    unsigned char header[80];
    unsigned char hash[32];

    memcpy(header, header76, 76);

    for (long long nonce = start; nonce <= end; nonce++) {
        header[76] = nonce & 0xff;
        header[77] = (nonce >> 8) & 0xff;
        header[78] = (nonce >> 16) & 0xff;
        header[79] = (nonce >> 24) & 0xff;

        double_sha256(header, 80, hash);

        if (is_below_target(hash, target)) {
            return nonce;
        }
    }

    return -1;
}
