#include <stdio.h>
#include <ctype.h>

// Encrypts a single character using the affine Caesar cipher
char encrypt_char(int a, int b, char p) {
    if (isalpha(p)) {
        p = toupper(p); // Convert to uppercase
        int index = p - 'A';
        return (char)((a * index + b) % 26 + 'A');
    } else {
        return p; // If not an alphabet character, return unchanged
    }
}

// Decrypts a single character using the affine Caesar cipher
char decrypt_char(int a, int b, char C) {
    if (isalpha(C)) {
        C = toupper(C); // Convert to uppercase
        int index = C - 'A';
        // Find modular multiplicative inverse of a modulo 26
        int a_inverse = 0;
        for (int i = 1; i < 26; ++i) {
            if ((a * i) % 26 == 1) {
                a_inverse = i;
                break;
            }
        }
        if (a_inverse == 0) {
            printf("Error: Modular inverse does not exist for given 'a' value.\n");
            return C; // Return the character unchanged if modular inverse doesn't exist
        }
        // Calculate plaintext index
        int p_index = (a_inverse * (index - b + 26)) % 26;
        return (char)(p_index + 'A');
    } else {
        return C; // If not an alphabet character, return unchanged
    }
}

// Encrypts a plaintext string using the affine Caesar cipher
void encrypt_affine_caesar(int a, int b, const char *plaintext, char *ciphertext) {
    for (int i = 0; plaintext[i] != '\0'; ++i) {
        ciphertext[i] = encrypt_char(a, b, plaintext[i]);
    }
    ciphertext[strlen(plaintext)] = '\0';
}

// Decrypts a ciphertext string using the affine Caesar cipher
void decrypt_affine_caesar(int a, int b, const char *ciphertext, char *plaintext) {
    for (int i = 0; ciphertext[i] != '\0'; ++i) {
        plaintext[i] = decrypt_char(a, b, ciphertext[i]);
    }
    plaintext[strlen(ciphertext)] = '\0';
}

int main() {
    int a = 5; // Example values for a and b
    int b = 8;
    char plaintext[] = "HELLO";
    char ciphertext[strlen(plaintext) + 1];
    char decrypted[strlen(plaintext) + 1];

    encrypt_affine_caesar(a, b, plaintext, ciphertext);
    printf("Plaintext: %s\n", plaintext);
    printf("Encrypted: %s\n", ciphertext);

    decrypt_affine_caesar(a, b, ciphertext, decrypted);
    printf("Decrypted: %s\n", decrypted);

    return 0;
}

