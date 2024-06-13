#include <stdio.h>
#include <stdlib.h>
#include <math.h>

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

int main() {
    int p = 23; // Example prime modulus
    int g = 5;  // Example base (generator)

    // Alice's secret and public values
    int a = 6; // Alice's secret
    int A = modExp(g, a, p); // Alice's public value

    // Bob's secret and public values
    int b = 15; // Bob's secret
    int B = modExp(g, b, p); // Bob's public value

    // Exchange public values and compute the shared secret
    int sharedSecretAlice = modExp(B, a, p);
    int sharedSecretBob = modExp(A, b, p);

    printf("Alice's public value: %d\n", A);
    printf("Bob's public value: %d\n", B);
    printf("Shared secret (Alice): %d\n", sharedSecretAlice);
    printf("Shared secret (Bob): %d\n", sharedSecretBob);

    return 0;
}

