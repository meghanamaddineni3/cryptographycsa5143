#include <stdio.h>
#include <math.h>

// Function to calculate factorial
unsigned long long factorial(int n) {
    unsigned long long result = 1;
    for (int i = 1; i <= n; i++) {
        result *= i;
    }
    return result;
}

int main() {
    int n = 25; // Number of letters in Playfair cipher
    unsigned long long total_keys = factorial(n);
    unsigned long long unique_keys = total_keys / 8;

    double total_keys_log2 = log2(total_keys);
    double unique_keys_log2 = log2(unique_keys);

    printf("Total possible keys (approximate power of 2): 2^%.2f\n", total_keys_log2);
    printf("Effectively unique keys (approximate power of 2): 2^%.2f\n", unique_keys_log2);

    return 0;
}
