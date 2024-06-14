#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_TEXT_LENGTH 1000
#define ALPHABET_SIZE 26

// English letter frequencies (approximate)
const double englishFrequencies[ALPHABET_SIZE] = {
    8.12, 1.49, 2.71, 4.32, 12.02, 2.30, 2.03, 5.92,
    7.31, 0.10, 0.69, 3.98, 2.61, 6.95, 7.68, 1.82,
    0.11, 6.02, 6.28, 9.10, 2.88, 1.11, 2.09, 0.17,
    2.11, 0.07
};

// Function to calculate letter frequencies in the ciphertext
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

// Function to find the index of the maximum element in an array
int findMaxIndex(double array[], int size) {
    int maxIndex = 0;
    for (int i = 1; i < size; i++) {
        if (array[i] > array[maxIndex]) {
            maxIndex = i;
        }
    }
    return maxIndex;
}

// Function to perform the frequency attack
void frequencyAttack(const char *ciphertext, int length, char *plaintext) {
    double ciphertextFrequencies[ALPHABET_SIZE];
    calculateFrequencies(ciphertext, length, ciphertextFrequencies);

    // Sort the frequencies
    double sortedFrequencies[ALPHABET_SIZE];
    memcpy(sortedFrequencies, englishFrequencies, sizeof(englishFrequencies));
    for (int i = 0; i < ALPHABET_SIZE - 1; i++) {
        for (int j = i + 1; j < ALPHABET_SIZE; j++) {
            if (sortedFrequencies[i] < sortedFrequencies[j]) {
                double temp = sortedFrequencies[i];
                sortedFrequencies[i] = sortedFrequencies[j];
                sortedFrequencies[j] = temp;
            }
        }
    }

    // Generate the substitution map
    char substitution[ALPHABET_SIZE];
    int used[ALPHABET_SIZE] = {0};
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        int maxIndex = findMaxIndex(ciphertextFrequencies, ALPHABET_SIZE);
        for (int j = 0; j < ALPHABET_SIZE; j++) {
            if (sortedFrequencies[i] == englishFrequencies[j] && !used[j]) {
                substitution[maxIndex] = 'A' + j;
                used[j] = 1;
                ciphertextFrequencies[maxIndex] = -1;
                break;
            }
        }
    }

    // Decrypt the text
    for (int i = 0; i < length; i++) {
        if (ciphertext[i] >= 'A' && ciphertext[i] <= 'Z') {
            plaintext[i] = substitution[ciphertext[i] - 'A'];
        } else if (ciphertext[i] >= 'a' && ciphertext[i] <= 'z') {
            plaintext[i] = substitution[ciphertext[i] - 'a'] + ('a' - 'A');
        } else {
            plaintext[i] = ciphertext[i];
        }
    }
    plaintext[length] = '\0';
}

// Main function to handle user input and display results
int main() {
    char ciphertext[MAX_TEXT_LENGTH];
    printf("Enter the ciphertext: ");
    fgets(ciphertext, MAX_TEXT_LENGTH, stdin);
    ciphertext[strcspn(ciphertext, "\n")] = '\0';

    int length = strlen(ciphertext);
    char plaintext[MAX_TEXT_LENGTH];
    frequencyAttack(ciphertext, length, plaintext);

    printf("Possible plaintext: %s\n", plaintext);

    return 0;
}
