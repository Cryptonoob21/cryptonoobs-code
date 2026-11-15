#define TEXT "hello"
#define DOUBLE_HASH 0

#include "sha256.h"

int main(void)
{
    unsigned char hash[32];

    if (DOUBLE_HASH) {
        double_sha256((const unsigned char *)TEXT, strlen(TEXT), hash);
    } else {
        sha256((const unsigned char *)TEXT, strlen(TEXT), hash);
    }

    printf("Text:   %s\n", TEXT);
    printf("Hash:   ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    return 0;
}
