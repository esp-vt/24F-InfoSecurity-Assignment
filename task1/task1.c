#include <stdio.h>
#include <openssl/bn.h>
#include <time.h>

int main() {
    // Initialize variables
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *N = BN_new();
    BIGNUM *phi_N = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *one = BN_new();

    // Set values for p, q, and e
    BN_dec2bn(&p, "87712020782810358806012366960530480363676290880575039025592945358193408249897");
    BN_dec2bn(&q, "102835471351264451708400576484301274347085188629221996951152314010256656047547");
    BN_dec2bn(&e, "65537");
    BN_dec2bn(&one, "1");

    // Compute N = p * q
    BN_mul(N, p, q, ctx);

    // Compute phi(N) = (p-1)*(q-1)
    BIGNUM *p_minus_1 = BN_new();
    BIGNUM *q_minus_1 = BN_new();
    BN_sub(p_minus_1, p, one);
    BN_sub(q_minus_1, q, one);
    BN_mul(phi_N, p_minus_1, q_minus_1, ctx);

    // Compute d = e^(-1) mod phi(N)
    clock_t start = clock();
    BN_mod_inverse(d, e, phi_N, ctx);
    clock_t end = clock();

    // Print results
    printf("Public Key: (e=%s, N=%s)\n", BN_bn2dec(e), BN_bn2dec(N));
    printf("Private Key: d=%s\n", BN_bn2dec(d));
    printf("Time taken: %.6f seconds\n", (double)(end - start) / CLOCKS_PER_SEC);

    // Free memory
    BN_free(p); BN_free(q); BN_free(N); BN_free(phi_N); BN_free(e); BN_free(d);
    BN_free(one); BN_free(p_minus_1); BN_free(q_minus_1);
    BN_CTX_free(ctx);

    return 0;
}

