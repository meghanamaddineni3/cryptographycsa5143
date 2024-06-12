#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>

#define BLOCK_SIZE 8 // 64 bits
#define KEY_SIZE 24  // 192 bits (3 times the size of DES key)

// Encrypt plaintext using 3DES in CBC mode
void encrypt_3des_cbc(const unsigned char *plaintext, const unsigned char *key, const unsigned char *iv, unsigned char *ciphertext, int len) {
    DES_cblock des_key1, des_key2, des_key3;
    DES_key_schedule ks1, ks2, ks3;

    // Split the 24-byte key into three 8-byte keys
    memcpy(des_key1, key, 8);
    memcpy(des_key2, key + 8, 8);
    memcpy(des_key3, key + 16, 8);

    // Set up key schedules
    DES_set_key_checked(&des_key1, &ks1);
    DES_set_key_checked(&des_key2, &ks2);
    DES_set_key_checked(&des_key3, &ks3);

    // Initialize the IV
    DES_cblock ivec;
    memcpy(ivec, iv, 8);

    // Encrypt each block of plaintext using CBC mode
    int remaining = len;
    const unsigned char *input = plaintext;
    unsigned char *output = ciphertext;
    while (remaining >= BLOCK_SIZE) {
        DES_ede3_cbc_encrypt(input, output, BLOCK_SIZE, &ks1, &ks2, &ks3, &ivec, DES_ENCRYPT);
        input += BLOCK_SIZE;
        output += BLOCK_SIZE;
        remaining -= BLOCK_SIZE;
    }
}

int main() {
    // Example plaintext, key, and IV
    unsigned char plaintext[] = "Hello, CBC!";
    unsigned char key[KEY_SIZE] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                                    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                                    0x21, 0x43, 0x65, 0x87, 0xA9, 0xCB, 0xED, 0xFE};
    unsigned char iv[BLOCK_SIZE] = {0};

    // Determine the length of the plaintext
    int len = strlen((char *)plaintext);

    // Determine the length of ciphertext (must be multiple of BLOCK_SIZE)
    int cipher_len = (len % BLOCK_SIZE == 0) ? len : (len / BLOCK_SIZE + 1) * BLOCK_SIZE;

    // Allocate memory for ciphertext
    unsigned char *ciphertext = (unsigned char *)malloc(cipher_len);

    // Encrypt plaintext using 3DES in CBC mode
    encrypt_3des_cbc(plaintext, key, iv, ciphertext, len);

    // Print ciphertext
    printf("Ciphertext: ");
    for (int i = 0; i < cipher_len; ++i) {
        printf("%02X", ciphertext[i]);
    }
    printf("\n");

    // Free memory
    free(ciphertext);

    return 0;
}

