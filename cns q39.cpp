#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALPHABET_SIZE 26

// Function to calculate letter frequencies in the text
void calculateFrequencies(const char *text, int length, double frequencies[ALPHABET_SIZE]) {
    int counts[ALPHABET_SIZE] = {0};
    for (int i = 0; i < length; i++) {
        if (text[i] >= 'A' && text[i] <= 'Z') {
            counts[text[i] - 'A']++;
        } else if (text[i] >= 'a' && text[i] <= 'z') {
            counts[text[i] - 'a']++;
        }
    }
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        frequencies[i] = (double)counts[i] / length * 100;
    }
}

// Function to perform the additive cipher decryption
void decryptAdditiveCipher(const char *ciphertext, int length, int shift, char *plaintext) {
    for (int i = 0; i < length; i++) {
        if (ciphertext[i] >= 'A' && ciphertext[i] <= 'Z') {
            plaintext[i] = 'A' + (ciphertext[i] - 'A' - shift + ALPHABET_SIZE) % ALPHABET_SIZE;
        } else if (ciphertext[i] >= 'a' && ciphertext[i] <= 'z') {
            plaintext[i] = 'a' + (ciphertext[i] - 'a' - shift + ALPHABET_SIZE) % ALPHABET_SIZE;
        } else {
            plaintext[i] = ciphertext[i];
        }
    }
    plaintext[length] = '\0';
}

// Function to perform the frequency attack and display top possible plaintexts
void frequencyAttack(const char *ciphertext, int length, int topPlaintexts) {
    double englishFrequencies[ALPHABET_SIZE] = {
        8.12, 1.49, 2.71, 4.32, 12.02, 2.30, 2.03, 5.92,
        7.31, 0.10, 0.69, 3.98, 2.61, 6.95, 7.68, 1.82,
        0.11, 6.02, 6.28, 9.10, 2.88, 1.11, 2.09, 0.17,
        2.11, 0.07
    };

    double ciphertextFrequencies[ALPHABET_SIZE];
    calculateFrequencies(ciphertext, length, ciphertextFrequencies);

    int shifts[ALPHABET_SIZE];
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        shifts[i] = (int)((ciphertextFrequencies[i] - englishFrequencies[i] + ALPHABET_SIZE) % ALPHABET_SIZE);
    }

    // Decrypt using each possible shift and display top possible plaintexts
    printf("Top %d possible plaintexts:\n", topPlaintexts);
    for (int i = 0; i < topPlaintexts; i++) {
        char plaintext[length + 1];
        decryptAdditiveCipher(ciphertext, length, shifts[i], plaintext);
        printf("%d. %s\n", i + 1, plaintext);
    }
}

int main() {
    char ciphertext[1000];
    int topPlaintexts;

    printf("Enter the ciphertext: ");
    fgets(ciphertext, sizeof(ciphertext), stdin);
    ciphertext[strcspn(ciphertext, "\n")] = '\0';

    printf("Enter the number of top possible plaintexts to display: ");
    scanf("%d", &topPlaintexts);

    int length = strlen(ciphertext);
    frequencyAttack(ciphertext, length, topPlaintexts);

    return 0;
}
