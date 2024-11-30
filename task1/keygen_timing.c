#include <stdio.h>
#include <openssl/bn.h>
#include <time.h>

void generate_key_pair(int bits) {
    // Initialize variables
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *N = BN_new();
    BIGNUM *phi_N = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *one = BN_new();

    BN_dec2bn(&e, "65537"); // Common public exponent
    BN_dec2bn(&one, "1");

    // Generate random primes for p and q
    clock_t start = clock();
    BN_generate_prime_ex(p, bits, 1, NULL, NULL, NULL);
    BN_generate_prime_ex(q, bits, 1, NULL, NULL, NULL);

    // Compute N = p * q
    BN_mul(N, p, q, ctx);

    // Compute phi(N) = (p-1)*(q-1)
    BIGNUM *p_minus_1 = BN_new();
    BIGNUM *q_minus_1 = BN_new();
    BN_sub(p_minus_1, p, one);
    BN_sub(q_minus_1, q, one);
    BN_mul(phi_N, p_minus_1, q_minus_1, ctx);

    // Compute d = e^(-1) mod phi(N)
    BN_mod_inverse(d, e, phi_N, ctx);
    clock_t end = clock();

    // Print results
    printf("Key Size: %d bits\n", bits);
    printf("Public Key: (e=%s, N=<%d bits>)\n", BN_bn2dec(e), BN_num_bits(N));
    printf("Private Key: d=<%d bits>\n", BN_num_bits(d));
    printf("Time taken: %.6f seconds\n\n", (double)(end - start) / CLOCKS_PER_SEC);

    // Free memory
    BN_free(p); BN_free(q); BN_free(N); BN_free(phi_N); BN_free(e); BN_free(d);
    BN_free(one); BN_free(p_minus_1); BN_free(q_minus_1);
    BN_CTX_free(ctx);
}

int main() {
    // Key sizes to test
    int key_sizes[] = {256, 512, 1024, 2048, 4096, 8192};
    int num_sizes = sizeof(key_sizes) / sizeof(key_sizes[0]);

    for (int i = 0; i < num_sizes; i++) {
        generate_key_pair(key_sizes[i]);
    }

    return 0;
}

