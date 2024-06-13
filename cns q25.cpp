#include <stdio.h>

// Function to compute gcd
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

int main() {
    int e = 31;
    int n = 3599;
    int known_plaintext = 59; // We use one of the factors of n directly

    // Step 1: Finding a factor of n using gcd
    int p = gcd(known_plaintext, n);
    if (p == 1 || p == n) {
        printf("The known plaintext does not have a common factor with n.\n");
        return 1;
    }
    int q = n / p;
    printf("Factors found: p = %d, q = %d\n", p, q);

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

    // Example ciphertext to decrypt
    long long ciphertext = 2221; // Example ciphertext block
    printf("Ciphertext: %lld\n", ciphertext);

    // Decryption: decrypted_plaintext = ciphertext^d mod n
    long long decrypted_plaintext = mod_exp(ciphertext, d, n);
    printf("Decrypted plaintext: %lld\n", decrypted_plaintext);

    return 0;
}
