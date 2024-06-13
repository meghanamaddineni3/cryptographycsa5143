#include <stdio.h>

// Function to find gcd
int gcd(int a, int b) {
    if (b == 0)
        return a;
    return gcd(b, a % b);
}

// Extended Euclidean Algorithm
int extended_gcd(int a, int b, int *x, int *y) {
    if (a == 0) {
        *x = 0;
        *y = 1;
        return b;
    }
    int x1, y1;
    int gcd = extended_gcd(b % a, a, &x1, &y1);
    *x = y1 - (b / a) * x1;
    *y = x1;
    return gcd;
}

// Function to find modular inverse of a under modulo m
int mod_inverse(int a, int m) {
    int x, y;
    int g = extended_gcd(a, m, &x, &y);
    if (g != 1) {
        printf("Inverse doesn't exist\n");
        return -1;
    }
    return (x % m + m) % m;
}

// Function to perform modular exponentiation
long long mod_exp(long long base, int exp, int mod) {
    long long result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1)
            result = (result * base) % mod;
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    return result;
}

// Function to factorize n into p and q
void factorize_n(int n, int *p, int *q) {
    for (int i = 2; i * i <= n; i++) {
        if (n % i == 0) {
            *p = i;
            *q = n / i;
            return;
        }
    }
}

int main() {
    int e = 31;
    int n = 3599;
    int p, q;

    // Step 1: Factorize n
    factorize_n(n, &p, &q);
    printf("p = %d, q = %d\n", p, q);

    // Step 2: Compute f(n)
    int phi_n = (p - 1) * (q - 1);
    printf("f(n) = %d\n", phi_n);

    // Step 3: Find the modular inverse of e modulo f(n)
    int d = mod_inverse(e, phi_n);
    if (d == -1) {
        printf("Failed to find the modular inverse.\n");
        return 1;
    }
    printf("Private key (d) = %d\n", d);

    // Example plaintext to encrypt and decrypt
    int plaintext = 123;
    printf("Plaintext: %d\n", plaintext);

    // Encryption: ciphertext = plaintext^e mod n
    long long ciphertext = mod_exp(plaintext, e, n);
    printf("Ciphertext: %lld\n", ciphertext);

    // Decryption: decrypted_plaintext = ciphertext^d mod n
    long long decrypted_plaintext = mod_exp(ciphertext, d, n);
    printf("Decrypted plaintext: %lld\n", decrypted_plaintext);

    return 0;
}
