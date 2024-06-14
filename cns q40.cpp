#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// English letter frequencies (from https://en.wikipedia.org/wiki/Letter_frequency)
float english_frequencies[] = {8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025,
                               2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150,
                               1.974, 0.074};

// Function to calculate letter frequency in a string
void calculate_letter_frequency(const char *text, float *frequency) {
    int total_letters = 0;
    memset(frequency, 0, 26 * sizeof(float));

    for (const char *p = text; *p != '\0'; ++p) {
        if (isalpha(*p)) {
            int index = toupper(*p) - 'A';
            frequency[index]++;
            total_letters++;
        }
    }

    for (int i = 0; i < 26; ++i) {
        frequency[i] = (frequency[i] / total_letters) * 100.0;
    }
}

// Function to perform letter frequency attack on monoalphabetic substitution cipher
void letter_frequency_attack(const char *ciphertext, char **plaintexts, int num_plaintexts) {
    float ciphertext_frequency[26];
    calculate_letter_frequency(ciphertext, ciphertext_frequency);

    // Calculate differences in frequency
    float differences[num_plaintexts];
    for (int i = 0; i < num_plaintexts; ++i) {
        float plaintext_frequency[26];
        calculate_letter_frequency(plaintexts[i], plaintext_frequency);

        float diff = 0.0;
        for (int j = 0; j < 26; ++j) {
            diff += fabs(ciphertext_frequency[j] - plaintext_frequency[j]);
        }
        differences[i] = diff;
    }

    // Sort plaintexts by likelihood (smallest differences first)
    for (int i = 0; i < num_plaintexts - 1; ++i) {
        for (int j = i + 1; j < num_plaintexts; ++j) {
            if (differences[i] > differences[j]) {
                // Swap differences
                float temp_diff = differences[i];
                differences[i] = differences[j];
                differences[j] = temp_diff;

                // Swap plaintexts
                char *temp_plaintext = plaintexts[i];
                plaintexts[i] = plaintexts[j];
                plaintexts[j] = temp_plaintext;
            }
        }
    }
}

int main() {
    const char *ciphertext = "Qktagxq oaxq bg qkq btgksmbtgwq bg lxctg oxv ygtzbvwpsq!";

    char *plaintexts[] = {
        "Attack from east at dawn to break their line!",
        "Dinner at six with friends on the yacht.",
        "Packing my box with five dozen liquor jugs.",
        "Jumpy wizards had quicksack of flying beer.",
        "Fox nymphs grab quick-jived waltz.",
        "How razorback-jumping frogs can level six piqued gymnasts!"
    };
    int num_plaintexts = sizeof(plaintexts) / sizeof(plaintexts[0]);

    // Perform letter frequency attack
    letter_frequency_attack(ciphertext, plaintexts, num_plaintexts);

    // Print the top 10 possible plaintexts
    int top = 10;
    if (top > num_plaintexts) {
        top = num_plaintexts;
    }

    printf("Top %d possible plaintexts:\n", top);
    for (int i = 0; i < top; ++i) {
        printf("%d. %s\n", i + 1, plaintexts[i]);
    }

    return 0;
}

