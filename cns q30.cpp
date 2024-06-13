#include <stdio.h>
#include <string.h>

// Block size for the cipher (in bytes)
#define BLOCK_SIZE 16

// XOR two blocks of data
void xorBlocks(const unsigned char *block1, const unsigned char *block2, unsigned char *output) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        output[i] = block1[i] ^ block2[i];
    }
}

// Simple mock block cipher encryption function (for demonstration purposes)
void encryptBlock(const unsigned char *plaintext, const unsigned char *key, unsigned char *ciphertext) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        ciphertext[i] = plaintext[i] ^ key[i]; // Simple XOR encryption (not secure)
    }
}

// CBC-MAC function
void cbcMac(const unsigned char *key, const unsigned char *message, int messageLen, unsigned char *mac) {
    unsigned char block[BLOCK_SIZE];
    unsigned char previousMac[BLOCK_SIZE] = {0};

    for (int i = 0; i < messageLen / BLOCK_SIZE; i++) {
        xorBlocks(message + i * BLOCK_SIZE, previousMac, block);
        encryptBlock(block, key, previousMac);
    }

    memcpy(mac, previousMac, BLOCK_SIZE);
}

int main() {
    unsigned char key[BLOCK_SIZE] ="thisisakey123456";
    unsigned char message[BLOCK_SIZE] = "thisisablockmsg"; // 16 bytes message
    unsigned char mac[BLOCK_SIZE];

    // Compute CBC-MAC of the one-block message X
    cbcMac(key, message, BLOCK_SIZE, mac);

    printf("CBC-MAC of one-block message X: ");
    for (int i = 0; i < BLOCK_SIZE; i++) {
        printf("%02x", mac[i]);
    }
    printf("\n");

    // Create the two-block message X || (X ? T)
    unsigned char twoBlockMessage[2 * BLOCK_SIZE];
    unsigned char xoredBlock[BLOCK_SIZE];

    memcpy(twoBlockMessage, message, BLOCK_SIZE);
    xorBlocks(message, mac, xoredBlock);
    memcpy(twoBlockMessage + BLOCK_SIZE, xoredBlock, BLOCK_SIZE);

    unsigned char twoBlockMac[BLOCK_SIZE];
    cbcMac(key, twoBlockMessage, 2 * BLOCK_SIZE, twoBlockMac);

    printf("CBC-MAC of two-block message X || (X ? T): ");
    for (int i = 0; i < BLOCK_SIZE; i++) {
        printf("%02x", twoBlockMac[i]);
    }
    printf("\n");

    return 0;
}

