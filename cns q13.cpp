#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define MATRIX_SIZE 2
#define MOD 26

// Function to find the determinant of a 2x2 matrix
int determinant(int matrix[MATRIX_SIZE][MATRIX_SIZE]) {
    return (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]) % MOD;
}

// Function to find the modular inverse of a number modulo m using the extended Euclidean algorithm
int modInverse(int a, int m) {
    int m0 = m, t, q;
    int x0 = 0, x1 = 1;

    if (m == 1) return 0;

    while (a > 1) {
        q = a / m;
        t = m;
        m = a % m;
        a = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }

    if (x1 < 0) x1 += m0;

    return x1;
}

// Function to find the inverse of a 2x2 matrix modulo 26
void findMatrixInverse(int key[MATRIX_SIZE][MATRIX_SIZE], int inverse[MATRIX_SIZE][MATRIX_SIZE]) {
    int det = determinant(key);
    int invDet = modInverse(det, MOD);

    inverse[0][0] = (key[1][1] * invDet) % MOD;
    inverse[0][1] = (-key[0][1] * invDet + MOD) % MOD;
    inverse[1][0] = (-key[1][0] * invDet + MOD) % MOD;
    inverse[1][1] = (key[0][0] * invDet) % MOD;
}

// Function to multiply two matrices
void matrixMultiply(int a[MATRIX_SIZE][MATRIX_SIZE], int b[MATRIX_SIZE][MATRIX_SIZE], int result[MATRIX_SIZE][MATRIX_SIZE]) {
    for (int i = 0; i < MATRIX_SIZE; i++) {
        for (int j = 0; j < MATRIX_SIZE; j++) {
            result[i][j] = 0;
            for (int k = 0; k < MATRIX_SIZE; k++) {
                result[i][j] += a[i][k] * b[k][j];
            }
            result[i][j] %= MOD;
        }
    }
}

// Function to print a 2x2 matrix
void printMatrix(int matrix[MATRIX_SIZE][MATRIX_SIZE]) {
    for (int i = 0; i < MATRIX_SIZE; i++) {
        for (int j = 0; j < MATRIX_SIZE; j++) {
            printf("%d ", matrix[i][j]);
        }
        printf("\n");
    }
}

int main() {
    // Example known plaintext-ciphertext pairs (chosen plaintext attack)
    int plaintext[MATRIX_SIZE][MATRIX_SIZE] = {
        { 0, 1 }, // "AB"
        { 1, 0 }  // "BA"
    };

    int ciphertext[MATRIX_SIZE][MATRIX_SIZE] = {
        { 9, 16 }, // Encrypted "AB"
        { 5, 7 }   // Encrypted "BA"
    };

    // Compute the inverse of the plaintext matrix
    int plaintextInverse[MATRIX_SIZE][MATRIX_SIZE];
    findMatrixInverse(plaintext, plaintextInverse);

    // Calculate the key matrix
    int key[MATRIX_SIZE][MATRIX_SIZE];
    matrixMultiply(ciphertext, plaintextInverse, key);

    // Print the discovered key matrix
    printf("Discovered key matrix:\n");
    printMatrix(key);

    return 0;
}
