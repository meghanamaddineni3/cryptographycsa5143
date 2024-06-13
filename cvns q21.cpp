#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>

#define BLOCK_SIZE 8  // DES block size in bytes

// Function to pad the plaintext if needed
void addPadding(unsigned char *plaintext, int *length) {
    int paddingLength = BLOCK_SIZE - (*length % BLOCK_SIZE);
    if (paddingLength == BLOCK_SIZE) {
        // Add a full block of padding
        memset(plaintext + *length, BLOCK_SIZE, BLOCK_SIZE);
        *length += BLOCK_SIZE;
    } else {
        // Add partial padding
        memset(plaintext + *length, paddingLength, paddingLength);
        *length += paddingLength;
    }
}

// Function to perform DES encryption in ECB mode
void ecbEncrypt(unsigned char *plaintext, int length, unsigned char *key, unsigned char *ciphertext) {
    DES_key_schedule keySchedule;
    DES_set_key_checked((const_DES_cblock *)key, &keySchedule);

    int numBlocks = length / BLOCK_SIZE;

    for (int i = 0; i < numBlocks; i++) {
        DES_ecb_encrypt((const_DES_cblock *)(plaintext + i * BLOCK_SIZE), (DES_cblock *)(ciphertext + i * BLOCK_SIZE),
                        &keySchedule, DES_ENCRYPT);
    }
}

// Function to perform DES decryption in ECB mode
void ecbDecrypt(unsigned char *ciphertext, int length, unsigned char *key, unsigned char *plaintext) {
    DES_key_schedule keySchedule;
    DES_set_key_checked((const_DES_cblock *)key, &keySchedule);

    int numBlocks = length / BLOCK_SIZE;

    for (int i = 0; i < numBlocks; i++) {
        DES_ecb_encrypt((const_DES_cblock *)(ciphertext + i * BLOCK_SIZE), (DES_cblock *)(plaintext + i * BLOCK_SIZE),
                        &keySchedule, DES_DECRYPT);
    }
}

// Function to perform DES encryption in CBC mode
void cbcEncrypt(unsigned char *plaintext, int length, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    DES_key_schedule keySchedule;
    DES_set_key_checked((const_DES_cblock *)key, &keySchedule);

    DES_cblock ivec;
    memcpy(&ivec, iv, sizeof(DES_cblock));

    int numBlocks = length / BLOCK_SIZE;

    for (int i = 0; i < numBlocks; i++) {
        DES_ncbc_encrypt((const unsigned char *)(plaintext + i * BLOCK_SIZE), (unsigned char *)(ciphertext + i * BLOCK_SIZE),
                         BLOCK_SIZE, &keySchedule, &ivec, DES_ENCRYPT);
    }
}

// Function to perform DES decryption in CBC mode
void cbcDecrypt(unsigned char *ciphertext, int length, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    DES_key_schedule keySchedule;
    DES_set_key_checked((const_DES_cblock *)key, &keySchedule);

    DES_cblock ivec;
    memcpy(&ivec, iv, sizeof(DES_cblock));

    int numBlocks = length / BLOCK_SIZE;

    for (int i = 0; i < numBlocks; i++) {
        DES_ncbc_encrypt((const unsigned char *)(ciphertext + i * BLOCK_SIZE), (unsigned char *)(plaintext + i * BLOCK_SIZE),
                         BLOCK_SIZE, &keySchedule, &ivec, DES_DECRYPT);
    }
}

// Function to perform DES encryption in CFB mode
void cfbEncrypt(unsigned char *plaintext, int length, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    DES_key_schedule keySchedule;
    DES_set_key_checked((const_DES_cblock *)key, &keySchedule);

    DES_cblock ivec;
    memcpy(&ivec, iv, sizeof(DES_cblock));

    int numBlocks = length / BLOCK_SIZE;

    for (int i = 0; i < numBlocks; i++) {
        DES_cfb64_encrypt((const unsigned char *)(plaintext + i * BLOCK_SIZE),
