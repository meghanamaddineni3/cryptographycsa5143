#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define ALPHABET_SIZE 26

// English letter frequencies
const float english_frequencies[ALPHABET_SIZE] = {
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,  // A-G
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,  // H-N
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,  // O-U
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074, 0.00750            // V-Z
}

// Function to calculate the Chi-squared statistic
float chi_squared(const int *observed, const float *expected) {
    float chi_sq = 0.0;
    for (int i = 0; i < ALPHABET_SIZE; ++i) {
        chi_sq += ((observed[i] - expected[i]) * (observed[i] - expected[i])) / expected[i];
    }
    return chi_sq;
}

// Function to decrypt a message using a given key
void decrypt(const char *cipher, char *plain, const char *key) {
    for (int i = 0; cipher[i] != '\0'; ++i) {
        if (isalpha(cipher[i])) {
            char base = islower(cipher[i]) ? 'a' : 'A';
            plain[i] = key[cipher[i] - base];
        } else {
            plain[i] = cipher[i];
        }
    }
    plain[strlen(cipher)] = '\0';
}

// Function to perform a letter frequency attack
void frequency_attack(const char *cipher, int top_plaintexts) {
    int observed[ALPHABET_SIZE] = {0};
    char decrypted[strlen(cipher) + 1];
    char key[ALPHABET_SIZE + 1] = {0};
    float min_chi_squared = 1000000.0; // Initialize with a large value

    // Count the occurrences of each letter in the ciphertext
    for (int i = 0; cipher[i] != '\0'; ++i) {
        if (isalpha(cipher[i])) {
            char base = islower(cipher[i]) ? 'a' : 'A';
            observed[cipher[i] - base]++;
        }
    }

    // Attempt all possible shifts to find the decryption key
    for (int shift = 0; shift < ALPHABET_SIZE; ++shift) {
        char current_key[ALPHABET_SIZE + 1] = {0};
        for (int i = 0; i < ALPHABET_SIZE; ++i) {
            current_key[i] = 'A' + (i + shift) % ALPHABET_SIZE;
        }
        decrypt(cipher, decrypted, current_key);
        float current_chi_squared = chi_squared(observed, english_frequencies);
        if (current_chi_squared < min_chi_squared) {
            min_chi_squared = current_chi_squared;
            strcpy(key, current_key);
        }
    }

    // Print the top possible plaintexts
    printf("Top %d possible plaintexts:\n", top_plaintexts);
    for (int i = 0; i < top_plaintexts; ++i) {
        decrypt(cipher, decrypted, key);
        printf("%d. %s (Chi-squared: %.2f)\n", i + 1, decrypted, min_chi_squared);
        key[i]++; // Shift key for next possible plaintext
    }
}

int main() {
    char cipher[1000];
    int top_plaintexts;

    printf("Enter the ciphertext: ");
    fgets(cipher, sizeof(cipher), stdin);

    printf("Enter the number of top possible plaintexts to display: ");
    scanf("%d", &top_plaintexts);

    frequency_attack(cipher, top_plaintexts);

    return 0;
}

