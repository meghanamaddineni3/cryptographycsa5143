#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int modInverse(int a, int m) {
    a = a % m;
    for (int x = 1; x < m; x++) {
        if ((a * x) % m == 1) {
            return x;
        }
    }
    return -1;
}
char affineDecrypt(char cipherText, int a, int b) {
    int a_inv = modInverse(a, 26);
    if (a_inv == -1) {
        printf("Inverse doesn't exist for a = %d\n", a);
        exit(1);
    }
    int x = (a_inv * ((cipherText - 'A') - b + 26)) % 26;
    return (x + 'A');
}

int main() {
    char ciphertext[] = "B...U..."; 
    int a, b;
    int E = 4, T = 19, B = 1, U = 20;
    
    for (a = 1; a < 26; a++) {
        if (modInverse(a, 26) != -1) { 
            for (b = 0; b < 26; b++) {
                if (((4 * a + b) % 26 == 1) && ((19 * a + b) % 26 == 20)) {
                    printf("Found a = %d, b = %d\n", a, b);
                    int n = strlen(ciphertext);
                    for (int i = 0; i < n; i++) {
                        if (ciphertext[i] >= 'A' && ciphertext[i] <= 'Z') {
                            printf("%c", affineDecrypt(ciphertext[i], a, b));
                        } else {
                            printf("%c", ciphertext[i]);
                        }
                    }
                    printf("\n");
                    return 0;
                }
            }
        }
    }

    printf("No valid keys found.\n");
    return 1;
}
