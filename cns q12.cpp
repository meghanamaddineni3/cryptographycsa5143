#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define N 2
void encrypt(char *message, int key[N][N]) {
    int len = strlen(message);
    int i, j, k;
    int plain[N][1], cipher[N][1];

    // Padding the message with 'x' if its length is not divisible by N
    while (len % N != 0) {
        message[len++] = 'x';
    }
    message[len] = '\0';

    // Encrypting the message
    for (i = 0; i < len; i += N) {
        // Mapping characters to numerical values (a=0, b=1, ..., z=25)
        for (j = 0; j < N; j++) {
            plain[j][0] = tolower(message[i + j]) - 'a';
        }
        // Multiplying the key matrix with the plaintext vector
        for (j = 0; j < N; j++) {
            cipher[j][0] = 0;
            for (k = 0; k < N; k++) {
                cipher[j][0] += key[j][k] * plain[k][0];
            }
            // Taking mod 26 to keep the result within the range of 0-25
            cipher[j][0] %= 26;
        }
        // Mapping numerical values back to characters
        for (j = 0; j < N; j++) {
            message[i + j] = cipher[j][0] + 'a';
        }
    }
}
void decrypt(char *message, int key[N][N]) {
    int len = strlen(message);
    int i, j, k;
    int plain[N][1], cipher[N][1], inverse[N][N];
    int det = key[0][0] * key[1][1] - key[0][1] * key[1][0];
    int det_inv = 0;
    for (i = 0; i < 26; i++) {
        if ((det * i) % 26 == 1) {
            det_inv = i;
            break;
        }
    }
    inverse[0][0] = (det_inv * key[1][1]) % 26;
    inverse[1][1] = (det_inv * key[0][0]) % 26;
    inverse[0][1] = (-det_inv * key[0][1] + 26) % 26;
    inverse[1][0] = (-det_inv * key[1][0] + 26) % 26;
    for (i = 0; i < len; i += N) {
        for (j = 0; j < N; j++) {
            cipher[j][0] = tolower(message[i + j]) - 'a';
        }
        for (j = 0; j < N; j++) {
            plain[j][0] = 0;
            for (k = 0; k < N; k++) {
                plain[j][0] += inverse[j][k] * cipher[k][0];
            }
            plain[j][0] = (plain[j][0] + 26) % 26;
        }
        for (j = 0; j < N; j++) {
            message[i + j] = plain[j][0] + 'a';
        }
    }
}
int main() {
    int key[N][N] = {{9, 4}, {5, 7}};
    char message[] = "meet me at the usual place at ten rather than eight oclock";
    printf("Original Message: %s\n", message);
    encrypt(message, key);
    printf("Encrypted Message: %s\n", message);

    // Decrypting the message
    decrypt(message, key);
    printf("Decrypted Message: %s\n", message);

    return 0;
}

