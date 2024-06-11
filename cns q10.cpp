#include <stdio.h>
#include <string.h>

#define SIZE 5

// Function to find the position of a character in the Playfair matrix
void findPosition(char key[SIZE][SIZE], char letter, int *row, int *col) {
    int i, j;
    for (i = 0; i < SIZE; i++) {
        for (j = 0; j < SIZE; j++) {
            if (key[i][j] == letter || (key[i][j] == 'J' && letter == 'I')) {
                *row = i;
                *col = j;
                return;
            }
        }
    }
}

// Function to encrypt a digraph using the Playfair cipher
void encryptDigraph(char key[SIZE][SIZE], char digraph[2], char ciphertext[2]) {
    int row1, col1, row2, col2;
    findPosition(key, digraph[0], &row1, &col1);
    findPosition(key, digraph[1], &row2, &col2);

    // Case 1: Same row
    if (row1 == row2) {
        ciphertext[0] = key[row1][(col1 + 1) % SIZE];
        ciphertext[1] = key[row2][(col2 + 1) % SIZE];
    }
    // Case 2: Same column
    else if (col1 == col2) {
        ciphertext[0] = key[(row1 + 1) % SIZE][col1];
        ciphertext[1] = key[(row2 + 1) % SIZE][col2];
    }
    // Case 3: Rectangle
    else {
        ciphertext[0] = key[row1][col2];
        ciphertext[1] = key[row2][col1];
    }
}

// Function to encrypt a message using the Playfair cipher
void encryptMessage(char key[SIZE][SIZE], char *plaintext, char *ciphertext) {
    int i, j = 0;
    char digraph[2];

    for (i = 0; i < strlen(plaintext); i += 2) {
        digraph[0] = plaintext[i];
        if (plaintext[i] == plaintext[i + 1]) {
            digraph[1] = 'X'; // Add filler 'X' if two consecutive letters are the same
            i--;
        } else {
            digraph[1] = plaintext[i + 1];
        }
        encryptDigraph(key, digraph, ciphertext + j);
        j += 2;
    }
    ciphertext[j] = '\0';
}

int main() {
    char key[SIZE][SIZE] = {{'M', 'F', 'H', 'I', 'J'},
                            {'U', 'N', 'O', 'P', 'Q'},
                            {'Z', 'V', 'W', 'X', 'Y'},
                            {'E', 'L', 'A', 'R', 'G'},
                            {'D', 'S', 'T', 'B', 'C'}};

    char plaintext[] = "Must see you over Cadogan West. Coming at once.";
    char ciphertext[1000];

    encryptMessage(key, plaintext, ciphertext);

    printf("Encrypted message: %s\n", ciphertext);

    return 0;
}

