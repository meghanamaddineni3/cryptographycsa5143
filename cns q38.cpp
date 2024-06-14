#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define MAX_TEXT_LENGTH 1000
#define MAX_MATRIX_SIZE 10

// Function to find the modular inverse of a number
int modInverse(int a, int m) {
    a = a % m;
    for (int x = 1; x < m; x++) {
        if ((a * x) % m == 1) return x;
    }
    return -1; // No modular inverse exists
}

// Function to encrypt plaintext using Hill cipher
void hillEncrypt(char *plaintext, char *ciphertext, int keyMatrix[MAX_MATRIX_SIZE][MAX_MATRIX_SIZE], int keySize) {
    int length = strlen(plaintext);
    int blocks = length / keySize;
    if (length % keySize != 0) blocks++;

    int paddedLength = blocks * keySize;
    char paddedText[MAX_TEXT_LENGTH];
    strcpy(paddedText, plaintext);
    for (int i = length; i < paddedLength; i++) {
        paddedText[i] = 'X'; // Padding with 'X' if necessary
    }
    paddedText[paddedLength] = '\0';

    for (int i = 0; i < blocks; i++) {
        int block[MAX_MATRIX_SIZE];
        for (int j = 0; j < keySize; j++) {
            block[j] = paddedText[i * keySize + j] - 'A';
        }

        for (int j = 0; j < keySize; j++) {
            int sum = 0;
            for (int k = 0; k < keySize; k++) {
                sum += keyMatrix[j][k] * block[k];
            }
            ciphertext[i * keySize + j] = (sum % 26) + 'A';
        }
    }
    ciphertext[paddedLength] = '\0';
}

// Function to decrypt ciphertext using Hill cipher
void hillDecrypt(char *ciphertext, char *plaintext, int keyMatrix[MAX_MATRIX_SIZE][MAX_MATRIX_SIZE], int keySize) {
    int length = strlen(ciphertext);
    int blocks = length / keySize;

    for (int i = 0; i < blocks; i++) {
        int block[MAX_MATRIX_SIZE];
        for (int j = 0; j < keySize; j++) {
            block[j] = ciphertext[i * keySize + j] - 'A';
        }

        for (int j = 0; j < keySize; j++) {
            int sum = 0;
            for (int k = 0; k < keySize; k++) {
                sum += keyMatrix[j][k] * block[k];
            }
            plaintext[i * keySize + j] = (sum % 26) + 'A';
        }
    }
    plaintext[length] = '\0';
}

// Function to perform known plaintext attack
void knownPlaintextAttack(char *plaintext, char *ciphertext, int keyMatrix[MAX_MATRIX_SIZE][MAX_MATRIX_SIZE], int keySize) {
    int length = strlen(plaintext);
    int blocks = length / keySize;
    if (length % keySize != 0) blocks++;

    int matrix[MAX_MATRIX_SIZE][MAX_MATRIX_SIZE];
    int inverseMatrix[MAX_MATRIX_SIZE][MAX_MATRIX_SIZE];

    // Construct the known plaintext-ciphertext pairs
    int pairs[blocks][MAX_MATRIX_SIZE];
    for (int i = 0; i < blocks; i++) {
        for (int j = 0; j < keySize; j++) {
            pairs[i][j] = plaintext[i * keySize + j] - 'A';
        }
    }

    // Construct the corresponding ciphertext blocks
    int cipherBlocks[blocks][MAX_MATRIX_SIZE];
    for (int i = 0; i < blocks; i++) {
        for (int j = 0; j < keySize; j++) {
            cipherBlocks[i][j] = ciphertext[i * keySize + j] - 'A';
        }
    }

    // Solve for the key matrix using known plaintext-ciphertext pairs
    for (int i = 0; i < keySize; i++) {
        for (int j = 0; j < keySize; j++) {
            matrix[i][j] = pairs[0][i] * modInverse(pairs[0][j], 26) % 26;
        }
    }

    // Compute the inverse of the key matrix
    int det = (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0] + 26) % 26;
    int detInv = modInverse(det, 26);
    inverseMatrix[0][0] = (matrix[1][1] * detInv) % 26;
    inverseMatrix[0][1] = (-matrix[0][1] * detInv) % 26;
    inverseMatrix[1][0] = (-matrix[1][0] * detInv) % 26;
    inverseMatrix[1][1] = (matrix[0][0] * detInv) % 26;

    // Decrypt using the key matrix
    hillDecrypt(ciphertext, plaintext, inverseMatrix, keySize);
}

int main() {
    char plaintext[MAX_TEXT_LENGTH], ciphertext[MAX_TEXT_LENGTH];

    // Example known plaintext-ciphertext pair
    strcpy(plaintext, "HELLO");
    int keyMatrix[MAX_MATRIX_SIZE][MAX_MATRIX_SIZE] = {{3, 2}, {5, 7}}; // Example key matrix
    hillEncrypt(plaintext, ciphertext, keyMatrix, 2);
    printf("Ciphertext: %s\n", ciphertext);

    // Perform known plaintext attack
    knownPlaintextAttack(plaintext, ciphertext, keyMatrix, 2);
    printf("Decrypted plaintext: %s\n", plaintext);

    return 0;
}
