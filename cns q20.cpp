#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define BLOCK_SIZE 8  // DES block size in bytes

// XOR function
void xorBlocks(uint8_t *a, uint8_t *b, uint8_t *out, int len) {
    for (int i = 0; i < len; i++) {
        out[i] = a[i] ^ b[i];
    }
}

// Simple block encryption/decryption (stub function for demonstration purposes)
void simpleBlockEncrypt(uint8_t *input, uint8_t *output) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        output[i] = input[i] ^ 0xAA;  // XOR with 0xAA for simple encryption
    }
}

void simpleBlockDecrypt(uint8_t *input, uint8_t *output) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        output[i] = input[i] ^ 0xAA;  // XOR with 0xAA for simple decryption
    }
}

// ECB mode encryption
void ecbEncrypt(uint8_t *plaintext, uint8_t *ciphertext, int len) {
    for (int i = 0; i < len; i += BLOCK_SIZE) {
        simpleBlockEncrypt(plaintext + i, ciphertext + i);
    }
}

// ECB mode decryption
void ecbDecrypt(uint8_t *ciphertext, uint8_t *plaintext, int len) {
    for (int i = 0; i < len; i += BLOCK_SIZE) {
        simpleBlockDecrypt(ciphertext + i, plaintext + i);
    }
}

// CBC mode encryption
void cbcEncrypt(uint8_t *plaintext, uint8_t *ciphertext, uint8_t *iv, int len) {
    uint8_t prevCiphertext[BLOCK_SIZE];
    memcpy(prevCiphertext, iv, BLOCK_SIZE);
    for (int i = 0; i < len; i += BLOCK_SIZE) {
        uint8_t block[BLOCK_SIZE];
        xorBlocks(plaintext + i, prevCiphertext, block, BLOCK_SIZE);
        simpleBlockEncrypt(block, ciphertext + i);
        memcpy(prevCiphertext, ciphertext + i, BLOCK_SIZE);
    }
}

// CBC mode decryption
void cbcDecrypt(uint8_t *ciphertext, uint8_t *plaintext, uint8_t *iv, int len) {
    uint8_t prevCiphertext[BLOCK_SIZE];
    memcpy(prevCiphertext, iv, BLOCK_SIZE);
    for (int i = 0; i < len; i += BLOCK_SIZE) {
        uint8_t block[BLOCK_SIZE];
        simpleBlockDecrypt(ciphertext + i, block);
        xorBlocks(block, prevCiphertext, plaintext + i, BLOCK_SIZE);
        memcpy(prevCiphertext, ciphertext + i, BLOCK_SIZE);
    }
}

void printBlock(uint8_t *block, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02X ", block[i]);
    }
    printf("\n");
}

int main() {
    uint8_t plaintext[] = "This is a test of ECB and CBC modes.";
    uint8_t key[BLOCK_SIZE] = {0};  // Not used in the simple example
    uint8_t iv[BLOCK_SIZE] = {0};   // Initialization vector for CBC mode
    int len = sizeof(plaintext);
    
    uint8_t ecbCiphertext[len];
    uint8_t ecbDecrypted[len];
    
    uint8_t cbcCiphertext[len];
    uint8_t cbcDecrypted[len];

    // Encrypt and decrypt using ECB
    printf("ECB Mode:\n");
    ecbEncrypt(plaintext, ecbCiphertext, len);
    ecbDecrypt(ecbCiphertext, ecbDecrypted, len);
    printf("Plaintext: %s\n", plaintext);
    printf("Ciphertext: ");
    printBlock(ecbCiphertext, len);
    printf("Decrypted: %s\n", ecbDecrypted);

    // Introduce an error in ECB ciphertext
    ecbCiphertext[8] ^= 0xFF;  // Flip bits in one block of ciphertext
    ecbDecrypt(ecbCiphertext, ecbDecrypted, len);
    printf("Decrypted with error in ECB ciphertext: %s\n", ecbDecrypted);

    // Encrypt and decrypt using CBC
    printf("\nCBC Mode:\n");
    cbcEncrypt(plaintext, cbcCiphertext, iv, len);
    cbcDecrypt(cbcCiphertext, cbcDecrypted, iv, len);
    printf("Plaintext: %s\n", plaintext);
    printf("Ciphertext: ");
    printBlock(cbcCiphertext, len);
    printf("Decrypted: %s\n", cbcDecrypted);

    // Introduce an error in CBC ciphertext
    cbcCiphertext[8] ^= 0xFF;  // Flip bits in one block of ciphertext
    cbcDecrypt(cbcCiphertext, cbcDecrypted, iv, len);
    printf("Decrypted with error in CBC ciphertext: %s\n", cbcDecrypted);

    return 0;
}
