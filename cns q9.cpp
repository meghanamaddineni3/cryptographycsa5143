#include <stdio.h>
#include <string.h>

#define SIZE 5

// Function to find the position of a character in the key square
void findPosition(char key[SIZE][SIZE], char letter, int *row, int *col) {
    int i, j;
    for (i = 0; i < SIZE; i++) {
        for (j = 0; j < SIZE; j++) {
            if (key[i][j] == letter) {
                *row = i;
                *col = j;
                return;
            }
        }
    }
}

// Function to decrypt a digraph using the Playfair cipher
void decryptDigraph(char key[SIZE][SIZE], char digraph[2], char plaintext[2]) {
    int row1, col1, row2, col2;
    findPosition(key, digraph[0], &row1, &col1);
    findPosition(key, digraph[1], &row2, &col2);

    // Case 1: Same row
    if (row1 == row2) {
        plaintext[0] = key[row1][(col1 - 1 + SIZE) % SIZE];
        plaintext[1] = key[row2][(col2 - 1 + SIZE) % SIZE];
    }
    // Case 2: Same column
    else if (col1 == col2) {
        plaintext[0] = key[(row1 - 1 + SIZE) % SIZE][col1];
        plaintext[1] = key[(row2 - 1 + SIZE) % SIZE][col2];
    }
    // Case 3: Rectangle
    else {
        plaintext[0] = key[row1][col2];
        plaintext[1] = key[row2][col1];
    }
}

// Function to decrypt a message using the Playfair cipher
void decryptMessage(char key[SIZE][SIZE], char *ciphertext) {
    int i;
    char plaintext[2];

    for (i = 0; i < strlen(ciphertext); i += 2) {
        decryptDigraph(key, ciphertext + i, plaintext);
        printf("%c%c", plaintext[0], plaintext[1]);
    }
    printf("\n");
}

int main() {
    char key[SIZE][SIZE] = {{'K', 'X', 'J', 'E',

