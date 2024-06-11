n#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define SIZE 5

void generateKeyTable(char key[], char keyTable[SIZE][SIZE]) {
    int map[26] = {0};
    int x = 0, y = 0;

    for (int i = 0; i < strlen(key); i++) {
        if (key[i] == 'J') key[i] = 'I';
        if (map[key[i] - 'A'] == 0) {
            keyTable[x][y++] = key[i];
            map[key[i] - 'A'] = 1;
            if (y == SIZE) {
                y = 0;
                x++;
            }
        }
    }

    for (char c = 'A'; c <= 'Z'; c++) {
        if (c == 'J') continue;
        if (map[c - 'A'] == 0) {
            keyTable[x][y++] = c;
            map[c - 'A'] = 1;
            if (y == SIZE) {
                y = 0;
                x++;
            }
        }
    }
}

void digraphEncryption(char digraph[], char keyTable[SIZE][SIZE], char result[]) {
    int row1, col1, row2, col2;
    for (int i = 0; i < SIZE; i++) {
        for (int j = 0; j < SIZE; j++) {
            if (keyTable[i][j] == digraph[0]) {
                row1 = i;
                col1 = j;
            } else if (keyTable[i][j] == digraph[1]) {
                row2 = i;
                col2 = j;
            }
        }
    }

    if (row1 == row2) {
        result[0] = keyTable[row1][(col1 + 1) % SIZE];
        result[1] = keyTable[row2][(col2 + 1) % SIZE];
    } else if (col1 == col2) {
        result[0] = keyTable[(row1 + 1) % SIZE][col1];
        result[1] = keyTable[(row2 + 1) % SIZE][col2];
    } else {
        result[0] = keyTable[row1][col2];
        result[1] = keyTable[row2][col1];
    }
}

void preprocessText(char *text) {
    int length = strlen(text);
    for (int i = 0; i < length; i++) {
        if (text[i] == 'J') {
            text[i] = 'I';
        }
    }

    for (int i = 0; i < length - 1; i += 2) {
        if (text[i] == text[i + 1]) {
            for (int j = length; j > i; j--) {
                text[j] = text[j - 1];
            }
            text[i + 1] = 'X';
            length++;
        }
    }
    if (length % 2 != 0) {
        text[length] = 'X';
        text[length + 1] = '\0';
    }
}

void playfairCipher(char text[], char keyTable[SIZE][SIZE], char result[]) {
    preprocessText(text);

    char digraph[2];
    int length = strlen(text);
    int resultIndex = 0;

    for (int i = 0; i < length; i += 2) {
        digraph[0] = text[i];
        digraph[1] = text[i + 1];
        digraphEncryption(digraph, keyTable, &result[resultIndex]);
        resultIndex += 2;
    }
    result[resultIndex] = '\0';
}

int main() {
    char key[100], text[100], result[100];
    char keyTable[SIZE][SIZE];

    printf("Enter the key: ");
    fgets(key, sizeof(key), stdin);
    key[strcspn(key, "\n")] = '\0';
    for (int i = 0; key[i]; i++) key[i] = toupper(key[i]);

    printf("Enter the plaintext: ");
    fgets(text, sizeof(text), stdin);
    text[strcspn(text, "\n")] = '\0';
    for (int i = 0; text[i]; i++) text[i] = toupper(text[i]);

    generateKeyTable(key, keyTable);

    playfairCipher(text, keyTable, result);

    printf("Encrypted text: %s\n", result);

    return 0;
}
