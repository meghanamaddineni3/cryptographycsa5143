#include <stdio.h>
#include <stdint.h>

// Initial permutation table
const int IP[] = {58, 50, 42, 34, 26, 18, 10, 2,
                  60, 52, 44, 36, 28, 20, 12, 4,
                  62, 54, 46, 38, 30, 22, 14, 6,
                  64, 56, 48, 40, 32, 24, 16, 8,
                  57, 49, 41, 33, 25, 17, 9, 1,
                  59, 51, 43, 35, 27, 19, 11, 3,
                  61, 53, 45, 37, 29, 21, 13, 5,
                  63, 55, 47, 39, 31, 23, 15, 7};

// Permutation table for generating subkeys
const int PC1[] = {57, 49, 41, 33, 25, 17, 9,
                   1, 58, 50, 42, 34, 26, 18,
                   10, 2, 59, 51, 43, 35, 27,
                   19, 11, 3, 60, 52, 44, 36,
                   63, 55, 47, 39, 31, 23, 15,
                   7, 62, 54, 46, 38, 30, 22,
                   14, 6, 61, 53, 45, 37, 29,
                   21, 13, 5, 28, 20, 12, 4};

// Permutation table for key compression
const int PC2[] = {14, 17, 11, 24, 1, 5,
                   3, 28, 15, 6, 21, 10,
                   23, 19, 12, 4, 26, 8,
                   16, 7, 27, 20, 13, 2,
                   41, 52, 31, 37, 47, 55,
                   30, 40, 51, 45, 33, 48,
                   44, 49, 39, 56, 34, 53,
                   46, 42, 50, 36, 29, 32};

// Left shift schedule
const int left_shift_schedule[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

// Perform initial permutation
void initial_permutation(uint64_t *data) {
    uint64_t result = 0;
    for (int i = 0; i < 64; ++i) {
        result |= ((*data >> (64 - IP[i])) & 1) << (63 - i);
    }
    *data = result;
}

// Key schedule function
void key_schedule(uint64_t key, uint64_t subkeys[]) {
    // Perform permutation choice 1 (PC1)
    uint64_t permuted_choice1 = 0;
    for (int i = 0; i < 56; ++i) {
        permuted_choice1 |= ((key >> (64 - PC1[i])) & 1) << (55 - i);
    }

    // Split into two 28-bit halves
    uint32_t C = (uint32_t)(permuted_choice1 >> 28); // First 28 bits
    uint32_t D = (uint32_t)permuted_choice1;         // Last 28 bits

    // Generate 16 subkeys
    for (int i = 0; i < 16; ++i) {
        // Perform left circular shift on C and D
        int shift = left_shift_schedule[i];
        C = ((C << shift) | (C >> (28 - shift))) & 0x0FFFFFFF;
        D = ((D << shift) | (D >> (28 - shift))) & 0x0FFFFFFF;

        // Merge C and D
        uint64_t merged = ((uint64_t)C << 28) | D;

        // Perform permutation choice 2 (PC2)
        uint64_t subkey = 0;
        for (int j = 0; j < 48; ++j) {
            subkey |= ((merged >> (56 - PC2[j])) & 1) << (47 - j);
        }

        subkeys[i] = subkey;
    }
}

int main() {
    // Example key
    uint64_t key = 0x133457799BBCDFF1;

    // Array to store subkeys
    uint64_t subkeys[16];

    // Perform initial permutation of the key
    initial_permutation(&key);

    // Generate subkeys
    key_schedule(key, subkeys);

    // Print subkeys
    printf("Subkeys:\n");
    for (int i = 0; i < 16; ++i) {
        printf("%d: 0x%012lX\n", i + 1, subkeys[i]);
    }

    return 0;
}

