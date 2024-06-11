#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#define ALPHABET_SIZE 26

void generateCipherSequence(const char *keyword, char *cipher) {
    bool used[ALPHABET_SIZE] = { false };
    int index = 0;

    // Add the keyword to the cipher sequence
    for (int i = 0; keyword[i] != '\0'; i++) {
        if (!used[keyword[i] - 'A']) {
            cipher[index++] = keyword[i];
            used[keyword[i] - 'A'] = true;
        }
    }

    // Add the remaining letters in alphabetical order
    for (char ch = 'A'; ch <= 'Z'; ch++) {
        if (!used[ch - 'A']) {
            cipher[index++] = ch;
        }
    }

    cipher[index] = '\0';
}

void encrypt(const char *plaintext, const char *cipher, char *encrypted) {
    while (*plaintext) {
        if (*plaintext >= 'a' && *plaintext <= 'z') {
            *encrypted = cipher[*plaintext - 'a'] + 'a' - 'A';
        } else if (*plaintext >= 'A' && *plaintext <= 'Z') {
            *encrypted = cipher[*plaintext - 'A'];
        } else {
            *encrypted = *plaintext;
        }
        plaintext++;
        encrypted++;
    }
    *encrypted = '\0';
}

void decrypt(const char *encrypted, const char *cipher, char *decrypted) {
    while (*encrypted) {
        if (*encrypted >= 'a' && *encrypted <= 'z') {
            char *pos = strchr(cipher, *encrypted - 'a' + 'A');
            *decrypted = (pos - cipher) + 'a';
        } else if (*encrypted >= 'A' && *encrypted <= 'Z') {
            char *pos = strchr(cipher, *encrypted);
            *decrypted = (pos - cipher) + 'A';
        } else {
            *decrypted = *encrypted;
        }
        encrypted++;
        decrypted++;
    }
    *decrypted = '\0';
}

int main() {
    const char *keyword = "CIPHER";
    char cipher[ALPHABET_SIZE + 1];
    char plaintext[] = "HELLO WORLD";
    char encrypted[100];
    char decrypted[100];

    generateCipherSequence(keyword, cipher);

    printf("Plain alphabet:  ABCDEFGHIJKLMNOPQRSTUVWXYZ\n");
    printf("Cipher alphabet: %s\n", cipher);

    encrypt(plaintext, cipher, encrypted);
    printf("Encrypted: %s\n", encrypted);

    decrypt(encrypted, cipher, decrypted);
    printf("Decrypted: %s\n", decrypted);

    return 0;
}
