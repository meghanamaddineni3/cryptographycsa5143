#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AES_BLOCK_SIZE 16

// Padding function
void pad(unsigned char *input, int len, int block_size) {
    int padding_len = block_size - (len % block_size);
    memset(input + len, 0, padding_len);
    input[len] = 0x80; // Padding with 0x80 followed by zeros
}

// ECB Mode Encryption
void aes_ecb_encrypt(const unsigned char *key, const unsigned char *input, unsigned char *output, int len) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);

    for (int i = 0; i < len; i += AES_BLOCK_SIZE) {
        AES_ecb_encrypt(input + i, output + i, &aes_key, AES_ENCRYPT);
    }
}

// ECB Mode Decryption
void aes_ecb_decrypt(const unsigned char *key, const unsigned char *input, unsigned char *output, int len) {
    AES_KEY aes_key;
    AES_set_decrypt_key(key, 128, &aes_key);

    for (int i = 0; i < len; i += AES_BLOCK_SIZE) {
        AES_ecb_encrypt(input + i, output + i, &aes_key, AES_DECRYPT);
    }
}

// CBC Mode Encryption
void aes_cbc_encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *input, unsigned char *output, int len) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);

    unsigned char iv_copy[AES_BLOCK_SIZE];
    memcpy(iv_copy, iv, AES_BLOCK_SIZE);

    AES_cbc_encrypt(input, output, len, &aes_key, iv_copy, AES_ENCRYPT);
}

// CBC Mode Decryption
void aes_cbc_decrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *input, unsigned char *output, int len) {
    AES_KEY aes_key;
    AES_set_decrypt_key(key, 128, &aes_key);

    unsigned char iv_copy[AES_BLOCK_SIZE];
    memcpy(iv_copy, iv, AES_BLOCK_SIZE);

    AES_cbc_encrypt(input, output, len, &aes_key, iv_copy, AES_DECRYPT);
}

// CFB Mode Encryption
void aes_cfb_encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *input, unsigned char *output, int len) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);

    unsigned char iv_copy[AES_BLOCK_SIZE];
    memcpy(iv_copy, iv, AES_BLOCK_SIZE);

    int num = 0;
    AES_cfb128_encrypt(input, output, len, &aes_key, iv_copy, &num, AES_ENCRYPT);
}

// CFB Mode Decryption
void aes_cfb_decrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *input, unsigned char *output, int len) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);

    unsigned char iv_copy[AES_BLOCK_SIZE];
    memcpy(iv_copy, iv, AES_BLOCK_SIZE);

    int num = 0;
    AES_cfb128_encrypt(input, output, len, &aes_key, iv_copy, &num, AES_DECRYPT);
}

int main() {
    unsigned char key[AES_BLOCK_SIZE] = "0123456789abcdef";
    unsigned char iv[AES_BLOCK_SIZE] = "abcdef9876543210";
    unsigned char input[] = "This is a test message for AES encryption.";
    int len = strlen((char *)input);

    int padded_len = len + (AES_BLOCK_SIZE - (len % AES_BLOCK_SIZE));
    unsigned char *padded_input = (unsigned char *)malloc(padded_len);
    unsigned char *output = (unsigned char *)malloc(padded_len);
    unsigned char *decrypted = (unsigned char *)malloc(padded_len);

    memcpy(padded_input, input, len);
    pad(padded_input, len, AES_BLOCK_SIZE);

    printf("Plaintext: %s\n", input);

    // ECB Mode
    aes_ecb_encrypt(key, padded_input, output, padded_len);
    printf("ECB Encrypted: ");
    for (int i = 0; i < padded_len; i++) {
        printf("%02x", output[i]);
    }
    printf("\n");

    aes_ecb_decrypt(key, output, decrypted, padded_len);
    printf("ECB Decrypted: %s\n", decrypted);

    // CBC Mode
    aes_cbc_encrypt(key, iv, padded_input, output, padded_len);
    printf("CBC Encrypted: ");
    for (int i = 0; i < padded_len; i++) {
        printf("%02x", output[i]);
    }
    printf("\n");

    aes_cbc_decrypt(key, iv, output, decrypted, padded_len);
    printf("CBC Decrypted: %s\n", decrypted);

    // CFB Mode
    aes_cfb_encrypt(key, iv, padded_input, output, padded_len);
    printf("CFB Encrypted: ");
    for (int i = 0; i < padded_len; i++) {
        printf("%02x", output[i]);
    }
    printf("\n");

    aes_cfb_decrypt(key, iv, output, decrypted, padded_len);
    printf("CFB Decrypted: %s\n", decrypted);

    free(padded_input);
    free(output);
    free(decrypted);

    return 0;
}

