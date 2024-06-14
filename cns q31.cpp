#include <stdio.h>
#include <string.h>
#include <stdint.h>

// AES block size in bytes
#define BLOCK_SIZE 16

// 128-bit and 64-bit polynomials
const uint8_t POLY_128 = 0x87;
const uint8_t POLY_64 = 0x1B;

// Dummy AES encryption function that encrypts a block of zeros
void AES_encrypt(const uint8_t *key, const uint8_t *input, uint8_t *output) {
    // In a real implementation, you would call a proper AES encryption function here.
    // For simplicity, we are just copying the input to output.
    memcpy(output, input, BLOCK_SIZE);
}

// Left shift the block by 1 bit
void left_shift(uint8_t *input, uint8_t *output, int len) {
    int i;
    uint8_t overflow = 0;

    for (i = len - 1; i >= 0; i--) {
        output[i] = (input[i] << 1) | overflow;
        overflow = (input[i] & 0x80) ? 1 : 0;
    }
}

// XOR the block with a constant
void xor_with_constant(uint8_t *input, uint8_t constant) {
    input[BLOCK_SIZE - 1] ^= constant;
}

// Generate subkeys K1 and K2
void generate_subkeys(uint8_t *key, uint8_t *K1, uint8_t *K2, int block_size) {
    uint8_t L[BLOCK_SIZE] = {0};
    uint8_t Z[BLOCK_SIZE] = {0};
    uint8_t constant = (block_size == 128) ? POLY_128 : POLY_64;

    // Encrypt the zero block
    AES_encrypt(key, Z, L);

    // Generate K1
    left_shift(L, K1, BLOCK_SIZE);
    if (L[0] & 0x80) {
        xor_with_constant(K1, constant);
    }

    // Generate K2
    left_shift(K1, K2, BLOCK_SIZE);
    if (K1[0] & 0x80) {
        xor_with_constant(K2, constant);
    }
}

int main() {
    uint8_t key[BLOCK_SIZE] = {0}; // Example key, should be set to a proper value
    uint8_t K1[BLOCK_SIZE] = {0};
    uint8_t K2[BLOCK_SIZE] = {0};

    // Generate subkeys for 128-bit block size
    generate_subkeys(key, K1, K2, 128);

    // Print the subkeys
    printf("K1: ");
    for (int i = 0; i < BLOCK_SIZE; i++) {
        printf("%02X", K1[i]);
    }
    printf("\n");

    printf("K2: ");
    for (int i = 0; i < BLOCK_SIZE; i++) {
        printf("%02X", K2[i]);
    }
    printf("\n");

    return 0;
}
