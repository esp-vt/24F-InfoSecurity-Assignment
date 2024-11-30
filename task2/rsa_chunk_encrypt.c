#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <stdlib.h>

#define KEY_SIZE 2048  // Key size in bits
#define CHUNK_SIZE 64  // Maximum size for a message chunk (RSA padding requires space)

void printBN(char *msg, BIGNUM *a) {
    char *number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

void encrypt_chunk(const char *chunk, BIGNUM *e, BIGNUM *N, BN_CTX *ctx, int chunk_num) {
    BIGNUM *M = BN_new();
    BIGNUM *C = BN_new();

    // Convert chunk to hex
    char chunk_hex[strlen(chunk) * 2 + 1];
    for (int i = 0; i < strlen(chunk); ++i) {
        sprintf(&chunk_hex[i * 2], "%02x", chunk[i] & 0xFF);
    }
    chunk_hex[strlen(chunk) * 2] = '\0'; // Null-terminate the string

    // Convert hex string to BIGNUM
    BN_hex2bn(&M, chunk_hex);

    // Encrypt: C = M^e mod N
    BN_mod_exp(C, M, e, N, ctx);

    // Print results
    printf("Chunk %d: %s\n", chunk_num, chunk);
    printBN("Hexadecimal Chunk: ", M);
    printBN("Ciphertext: ", C);

    // Free memory
    BN_free(M);
    BN_free(C);
}

int main() {
    // Initialize OpenSSL variables
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *N = BN_new();
    BIGNUM *e = BN_new();

    // Assign values for N and e
    BN_hex2bn(&N, "EF38064573FC9B1DF7BD8415B6BFB64402E5DB284FE8CAD9A85F0785BC3E3D07A3CFCFCEE6C8B64C37966982472C36604EF8B5A4AA5178CD2758D0E443126C19");
    BN_hex2bn(&e, "010001");

    // Message to encrypt
    char msg[] = "This is a much longer message that exceeds the block size of RSA encryption, and it must be split into chunks.";
    int msg_len = strlen(msg);

    // Encrypt message in chunks
    int chunk_num = 0;
    for (int i = 0; i < msg_len; i += CHUNK_SIZE) {
        char chunk[CHUNK_SIZE + 1];
        int chunk_length = (msg_len - i < CHUNK_SIZE) ? (msg_len - i) : CHUNK_SIZE;
        strncpy(chunk, &msg[i], chunk_length);
        chunk[chunk_length] = '\0';  // Null-terminate the chunk
        encrypt_chunk(chunk, e, N, ctx, ++chunk_num);
    }

    // Free memory
    BN_free(N);
    BN_free(e);
    BN_CTX_free(ctx);

    return 0;
}

