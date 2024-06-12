#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Function to calculate the frequency of each letter in a string
void calculate_frequency(char *text, int *frequency) {
    int i;
    for (i = 0; text[i] != '\0'; i++) {
        if (isalpha(text[i])) {
            frequency[tolower(text[i]) - 'a']++;
        }
    }
}

// Function to perform additive decryption
void decrypt(char *ciphertext, int shift, char *plaintext) {
    int i;
    for (i = 0; ciphertext[i] != '\0'; i++) {
        if (isalpha(ciphertext[i])) {
            char base = isupper(ciphertext[i]) ? 'A' : 'a';
            plaintext[i] = ((ciphertext[i] - base - shift) % 26 + 26) % 26 + base;
        } else {
            plaintext[i] = ciphertext[i];
        }
    }
    plaintext[i] = '\0';
}

// Function to perform letter frequency attack and print top possible plaintexts
void letter_frequency_attack(char *ciphertext, int top) {
    int frequency[26] = {0};
    calculate_frequency(ciphertext, frequency);

    int i, j;
    for (i = 0; i < top; i++) {
        int max_freq = -1, max_index = -1;
        for (j = 0; j < 26; j++) {
            if (frequency[j] > max_freq) {
                max_freq = frequency[j];
                max_index = j;
            }
        }
        if (max_freq == 0) break; // No more significant letters found
        printf("Key %d: ", max_index);
        char plaintext[strlen(ciphertext)];
        decrypt(ciphertext, max_index, plaintext);
        printf("%s\n", plaintext);

        // Resetting frequency of decrypted letters to prevent repetition
        frequency[max_index] = 0;
    }
}

int main() {
    char ciphertext[] = "Uifsf jt b tfdsfu ujnft pg xpsme, xijdi jt dmfbs.";
    int top = 10; // Number of top possible plaintexts to display

    printf("Ciphertext: %s\n", ciphertext);
    printf("Possible Plaintexts:\n");
    letter_frequency_attack(ciphertext, top);

    return 0;
}

