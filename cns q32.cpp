#include <stdio.h>
#include <stdlib.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/sha.h>

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

void print_signature(unsigned char* sig, unsigned int sig_len) {
    for (unsigned int i = 0; i < sig_len; i++) {
        printf("%02x", sig[i]);
    }
    printf("\n");
}

int main() {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    DSA *dsa = DSA_new();
    if (dsa == NULL) {
        handleErrors();
    }

    if (DSA_generate_parameters_ex(dsa, 1024, NULL, 0, NULL, NULL, NULL) == 0) {
        handleErrors();
    }

    if (DSA_generate_key(dsa) == 0) {
        handleErrors();
    }

    const char *message = "This is a test message";
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)message, strlen(message), hash);

    unsigned char *signature = malloc(DSA_size(dsa));
    unsigned int sig_len;

    // First signature
    if (DSA_sign(0, hash, SHA256_DIGEST_LENGTH, signature, &sig_len, dsa) == 0) {
        handleErrors();
    }
    printf("First signature: ");
    print_signature(signature, sig_len);

    // Second signature (same message, different k value)
    if (DSA_sign(0, hash, SHA256_DIGEST_LENGTH, signature, &sig_len, dsa) == 0) {
        handleErrors();
    }
    printf("Second signature: ");
    print_signature(signature, sig_len);

    // Clean up
    DSA_free(dsa);
    free(signature);
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
