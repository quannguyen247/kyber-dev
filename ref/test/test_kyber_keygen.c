#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../randombytes.h"
#include "../kem.h"

#define CLIENT_SK_PATH "client_sk.bin"
#define CLIENT_PK_PATH "client_pk.bin"
#define SERVER_SK_PATH "server_sk.bin"
#define SERVER_PK_PATH "server_pk.bin"

static int write_file(const char *path, const uint8_t *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "Failed to open %s for writing\n", path);
        return -1;
    }
    if (fwrite(buf, 1, len, f) != len) {
        fprintf(stderr, "Failed to write to %s\n", path);
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

int main(void) {
    uint8_t client_pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t client_sk[CRYPTO_SECRETKEYBYTES];
    uint8_t server_pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t server_sk[CRYPTO_SECRETKEYBYTES];

    printf("[*] Generating client Kyber keypair...\n");
    if (crypto_kem_keypair(client_pk, client_sk) != 0) {
        fprintf(stderr, "Client key generation failed\n");
        return 1;
    }
    printf("[OK] Client keypair generated\n");

    printf("[*] Generating server Kyber keypair...\n");
    if (crypto_kem_keypair(server_pk, server_sk) != 0) {
        fprintf(stderr, "Server key generation failed\n");
        return 1;
    }
    printf("[OK] Server keypair generated\n");

    if (write_file(CLIENT_SK_PATH, client_sk, sizeof(client_sk)) < 0) {
        return 1;
    }
    printf("[OK] Wrote %s\n", CLIENT_SK_PATH);

    if (write_file(CLIENT_PK_PATH, client_pk, sizeof(client_pk)) < 0) {
        return 1;
    }
    printf("[OK] Wrote %s\n", CLIENT_PK_PATH);

    if (write_file(SERVER_SK_PATH, server_sk, sizeof(server_sk)) < 0) {
        return 1;
    }
    printf("[OK] Wrote %s\n", SERVER_SK_PATH);

    if (write_file(SERVER_PK_PATH, server_pk, sizeof(server_pk)) < 0) {
        return 1;
    }
    printf("[OK] Wrote %s\n", SERVER_PK_PATH);

    printf("\n[OK] All keypairs generated successfully\n");
    printf("Copy %s to the server machine before running the server.\n", CLIENT_PK_PATH);
    printf("Copy %s to the client machine before running the client.\n", SERVER_PK_PATH);
    
    return 0;
}
