#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Initial Permutation Table
int IP[] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

// Final Permutation Table
int FP[] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
};

// Expansion Table
int E[] = {
    32, 1, 2, 3, 4, 5, 4, 5,
    6, 7, 8, 9, 8, 9, 10, 11,
    12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27,
    28, 29, 28, 29, 30, 31, 32, 1
};

// S-boxes
int S[8][4][16] = {
    {
        {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
        {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
        {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
        {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
    },
    {
        {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
        {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
        {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
        {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
    },
    {
        {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
        {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
        {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
        {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
    },
    {
        {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
        {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
        {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
        {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
    },
    {
        {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
        {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
        {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
        {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
    },
    {
        {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
        {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
        {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
        {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
    },
    {
        {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
        {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
        {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
        {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
    },
    {
        {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
        {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
        {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
        {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
    }
};

// Permutation Table
int P[] = {
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
};

// Left Shifts Table
int SHIFTS[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

// Function to perform the initial permutation
void initialPermutation(uint64_t *block) {
    uint64_t permutedBlock = 0;
    for (int i = 0; i < 64; i++) {
        permutedBlock |= ((*block >> (64 - IP[i])) & 1) << (63 - i);
    }
    *block = permutedBlock;
}

// Function to perform the final permutation
void finalPermutation(uint64_t *block) {
    uint64_t permutedBlock = 0;
    for (int i = 0; i < 64; i++) {
        permutedBlock |= ((*block >> (64 - FP[i])) & 1) << (63 - i);
    }
    *block = permutedBlock;
}

// Function to perform the expansion permutation
uint32_t expansionPermutation(uint32_t halfBlock) {
    uint32_t expandedBlock = 0;
    for (int i = 0; i < 48; i++) {
        expandedBlock |= ((halfBlock >> (32 - E[i])) & 1) << (47 - i);
    }
    return expandedBlock;
}

// Function to perform the substitution with S-boxes
uint32_t substitution(uint48_t expandedHalfBlock) {
    uint32_t substitutedBlock = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t sixBits = (expandedHalfBlock >> (42 - 6 * i)) & 0x3F;
        uint8_t row = ((sixBits & 0x20) >> 4) | (sixBits & 0x01);
        uint8_t col = (sixBits >> 1) & 0x0F;
        substitutedBlock |= S[i][row][col] << (28 - 4 * i);
    }
    return substitutedBlock;
}

// Function to perform the permutation
uint32_t permutation(uint32_t halfBlock) {
    uint32_t permutedBlock = 0;
    for (int i = 0; i < 32; i++) {
        permutedBlock |= ((halfBlock >> (32 - P[i])) & 1) << (31 - i);
    }
    return permutedBlock;
}

// Feistel function
uint32_t feistel(uint32_t halfBlock, uint48_t subKey) {
    uint48_t expandedHalfBlock = expansionPermutation(halfBlock);
    expandedHalfBlock ^= subKey;
    uint32_t substitutedBlock = substitution(expandedHalfBlock);
    return permutation(substitutedBlock);
}

// Key schedule generation
void generateSubKeys(uint64_t key, uint48_t subKeys[16]) {
    // Permuted Choice 1 (PC1) Table
    int PC1[] = {
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    };

    // Permuted Choice 2 (PC2) Table
    int PC2[] = {
        14, 17, 11, 24, 1, 5, 3, 28,
        15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56,
        34, 53, 46, 42, 50, 36, 29, 32
    };

    uint56_t permutedKey = 0;
    for (int i = 0; i < 56; i++) {
        permutedKey |= ((key >> (64 - PC1[i])) & 1) << (55 - i);
    }

    uint28_t C = (permutedKey >> 28) & 0xFFFFFFF;
    uint28_t D = permutedKey & 0xFFFFFFF;

    for (int i = 0; i < 16; i++) {
        C = ((C << SHIFTS[i]) | (C >> (28 - SHIFTS[i]))) & 0xFFFFFFF;
        D = ((D << SHIFTS[i]) | (D >> (28 - SHIFTS[i]))) & 0xFFFFFFF;
        uint56_t CD = ((uint56_t)C << 28) | D;
        subKeys[i] = 0;
        for (int j = 0; j < 48; j++) {
            subKeys[i] |= ((CD >> (56 - PC2[j])) & 1) << (47 - j);
        }
    }
}

// DES encryption/decryption function
void DES(uint64_t *block, uint64_t key, int encrypt) {
    uint48_t subKeys[16];
    generateSubKeys(key, subKeys);

    initialPermutation(block);

    uint32_t L = (*block >> 32) & 0xFFFFFFFF;
    uint32_t R = *block & 0xFFFFFFFF;

    for (int i = 0; i < 16; i++) {
        uint32_t temp = R;
        if (encrypt) {
            R = L ^ feistel(R, subKeys[i]);
        } else {
            R = L ^ feistel(R, subKeys[15 - i]);
        }
        L = temp;
    }

    *block = ((uint64_t)R << 32) | L;

    finalPermutation(block);
}

// Helper function to print a 64-bit block
void printBlock(uint64_t block) {
    for (int i = 63; i >= 0; i--) {
        printf("%d", (block >> i) & 1);
        if (i % 8 == 0) printf(" ");
    }
    printf("\n");
}

int main() {
    uint64_t plaintext = 0x0123456789ABCDEF;
    uint64_t key = 0x133457799BBCDFF1;

    printf("Plaintext: ");
    printBlock(plaintext);

    DES(&plaintext, key, 1);
    printf("Ciphertext: ");
    printBlock(plaintext);

    DES(&plaintext, key, 0);
    printf("Decrypted text: ");
    printBlock(plaintext);

    return 0;
}
