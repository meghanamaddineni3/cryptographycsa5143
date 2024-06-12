#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Function to encrypt a plaintext using the one-time pad Vigenère cipher
void encrypt(char *plaintext, int *key, char *ciphertext) {
    int len = strlen(plaintext);
    int i, j;

    for (i = 0; i < len; i++) {
        if (plaintext[i] == ' ') {
            ciphertext[i] = ' ';
            continue;
        }
        // Encrypting each character using the corresponding key
        ciphertext[i] = ((plaintext[i] - 'a' + key[i]) % 26) + 'a';
    }
    ciphertext[len] = '\0';
}

// Function to decrypt a ciphertext using the one-time pad Vigenère cipher
void decrypt(char *ciphertext, int *key, char *plaintext) {
    int len = strlen(ciphertext);
    int i, j;

    for (i = 0; i < len; i++) {
        if (ciphertext[i] == ' ') {
            plaintext[i] = ' ';
            continue;
        }
        // Decrypting each character using the corresponding key
        plaintext[i] = ((ciphertext[i] - 'a' - key[i]) % 26);
        if (plaintext[i] < 0)
            plaintext[i] += 26;
        plaintext[i] += 'a';
    }
    plaintext[len] = '\0';
}

int main() {
    char plaintext[] = "send more money";
    int key[] = {9, 0, 1, 7, 23, 15, 21, 14, 11, 11, 2, 8, 9};
    char ciphertext[strlen(plaintext)];
    char decrypted_plaintext[strlen(plaintext)];

    // Encrypting the plaintext
    encrypt(plaintext, key, ciphertext);
    printf("Encrypted Ciphertext: %s\n", ciphertext);

    // Decrypting the ciphertext to find the original plaintext
    decrypt(ciphertext, key, decrypted_plaintext);
    printf("Decrypted Plaintext: %s\n", decrypted_plaintext);

    return 0;
}

