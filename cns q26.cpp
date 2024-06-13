#include <stdio.h>
#include <stdlib.h>
#include <math.h>

// Function prototypes
int gcd(int a, int b);
int modInverse(int e, int phi);
int modExp(int base, int exp, int mod);
void generateKeys(int p, int q, int* n, int* e, int* d);
void encrypt(int message, int e, int n, int* ciphertext);
void decrypt(int ciphertext, int d, int n, int* decryptedMessage);

int main() {
    int p = 61; // Example prime number
    int q = 53; // Example prime number
    int n, e, d;

    // Generate RSA keys
    generateKeys(p, q, &n, &e, &d);

    printf("Public Key (e, n): (%d, %d)\n", e, n);
    printf("Private Key (d, n): (%d, %d)\n", d, n);

    int message = 42; // Example message
    int ciphertext, decryptedMessage;

    // Encrypt the message
    encrypt(message, e, n, &ciphertext);
    printf("Encrypted Message: %d\n", ciphertext);

    // Decrypt the message
    decrypt(ciphertext, d, n, &decryptedMessage);
    printf("Decrypted Message: %d\n", decryptedMessage);

    return 0;
}

// Function to compute the greatest common divisor
int gcd(int a, int b) {
    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// Function to compute modular inverse
int modInverse(int e, int phi) {
    int m0 = phi, t, q;
    int x0 = 0, x1 = 1;

    if (phi == 1)
        return 0;

    while (e > 1) {
        q = e / phi;
        t = phi;
        phi = e % phi;
        e = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }

    if (x1 < 0)
        x1 += m0;

    return x1;
}

// Function to perform modular exponentiation
int modExp(int base, int exp, int mod) {
    int result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1)
            result = (result * base) % mod;
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    return result;
}

// Function to generate RSA keys
void generateKeys(int p, int q, int* n, int* e, int* d) {
    *n = p * q;
    int phi = (p - 1) * (q - 1);

    *e = 3;
    while (gcd(*e, phi) != 1) {
        (*e)++;
    }

    *d = modInverse(*e, phi);
}

// Function to encrypt a message
void encrypt(int message, int e, int n, int* ciphertext) {
    *ciphertext = modExp(message, e, n);
}

// Function to decrypt a message
void decrypt(int ciphertext, int d, int n, int* decryptedMessage) {
    *decryptedMessage = modExp(ciphertext, d, n);
}

