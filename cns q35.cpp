#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Encrypts a plaintext using the one-time pad Vigenère cipher
void vigenere_one_time_pad_encrypt(const char *plaintext, const int *key, char *ciphertext) {
    int len = strlen(plaintext);
    int key_len = strlen((const char *)key);

    for (int i = 0; i < len; ++i) {
        // Calculate the shift amount based on the key
        int shift = key[i % key_len];
        // Encrypt the character
        ciphertext[i] = (plaintext[i] - 'A' + shift) % 26 + 'A';
    }
    ciphertext[len] = '\0';
}

// Decrypts a ciphertext using the one-time pad Vigenère cipher
void vigenere_one_time_pad_decrypt(const char *ciphertext, const int *key, char *plaintext) {
    int len = strlen(ciphertext);
    int key_len = strlen((const char *)key);

    for (int i = 0; i < len; ++i) {
        // Calculate the shift amount based on the key
        int shift = key[i % key_len];
        // Decrypt the character
        plaintext[i] = (ciphertext[i] - 'A' - shift + 26) % 26 + 'A';
    }
    plaintext[len] = '\0';
}

int main() {
    char plaintext[] = "HELLO";
    int key[] = {3, 19, 5, 10, 15}; // Example key: 3, 19, 5, 10, 15
    char ciphertext[strlen(plaintext) + 1];
    char decrypted[strlen(plaintext) + 1];

    vigenere_one_time_pad_encrypt(plaintext, key, ciphertext);
    printf("Plaintext: %s\n", plaintext);
    printf("Ciphertext: %s\n", ciphertext);

    vigenere_one_time_pad_decrypt(ciphertext, key, decrypted);
    printf("Decrypted: %s\n", decrypted);

    return 0;
}

