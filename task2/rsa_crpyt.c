#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM * a) {
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main() {
    // Initialize OpenSSL variables
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *N = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *M = BN_new();
    BIGNUM *C = BN_new();

    // Assign values for N and e
    BN_hex2bn(&N, "EF38064573FC9B1DF7BD8415B6BFB64402E5DB284FE8CAD9A85F0785BC3E3D07A3CFCFCEE6C8B64C37966982472C36604EF8B5A4AA5178CD2758D0E443126C19");
    BN_hex2bn(&e, "010001");

    // Message to encrypt
    char msg[] = "Hello, this is my first RSA message!";
    int len = strlen(msg);

    // Convert message to hexadecimal
    char msg_hex[len * 2 + 1];
    for (int i = 0; i < len; ++i) {
        sprintf(&msg_hex[i * 2], "%02x", msg[i] & 0xFF);
    }

    // Convert hex to BIGNUM
    BN_hex2bn(&M, msg_hex);

    // Encrypt: C = M^e mod N
    BN_mod_exp(C, M, e, N, ctx);

    // Print results
    printf("Original Message: %s\n", msg);
    printBN("Hexadecimal Message: ", M);
    printBN("Ciphertext: ", C);

    // Free memory
    BN_free(N); BN_free(e); BN_free(M); BN_free(C);
    BN_CTX_free(ctx);

    return 0;
}

