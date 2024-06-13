#include <stdio.h>
#include <stdint.h>

// Utility functions for bit manipulation
uint8_t get_bit(uint8_t byte, int position) {
    return (byte >> position) & 1;
}

void set_bit(uint8_t *byte, int position, uint8_t value) {
    if (value)
        *byte |= (1 << position);
    else
        *byte &= ~(1 << position);
}

uint8_t permute(uint8_t in, const int *perm, int n) {
    uint8_t out = 0;
    for (int i = 0; i < n; i++) {
        set_bit(&out, n - 1 - i, get_bit(in, perm[i] - 1));
    }
    return out;
}

uint8_t f(uint8_t r, uint8_t k) {
    static const int EP[] = {4, 1, 2, 3, 2, 3, 4, 1};
    static const int P4[] = {2, 4, 3, 1};
    static const int S0[4][4] = {
        {1, 0, 3, 2},
        {3, 2, 1, 0},
        {0, 2, 1, 3},
        {3, 1, 3, 2}
    };
    static const int S1[4][4] = {
        {0, 1, 2, 3},
        {2, 0, 1, 3},
        {3, 0, 1, 0},
        {2, 1, 0, 3}
    };
    
    uint8_t ep = permute(r, EP, 8);
    ep ^= k;
    
    uint8_t l = (ep >> 4) & 0xF;
    uint8_t r_ep = ep & 0xF;
    
    int row = (get_bit(l, 3) << 1) | get_bit(l, 0);
    int col = (get_bit(l, 2) << 1) | get_bit(l, 1);
    uint8_t s0 = S0[row][col];
    
    row = (get_bit(r_ep, 3) << 1) | get_bit(r_ep, 0);
    col = (get_bit(r_ep, 2) << 1) | get_bit(r_ep, 1);
    uint8_t s1 = S1[row][col];
    
    uint8_t s_output = (s0 << 2) | s1;
    return permute(s_output, P4, 4);
}

void key_schedule(uint16_t key, uint8_t *k1, uint8_t *k2) {
    static const int P10[] = {3, 5, 2, 7, 4, 10, 1, 9, 8, 6};
    static const int P8[] = {6, 3, 7, 4, 8, 5, 10, 9};
    
    uint16_t permuted_key = permute(key, P10, 10);
    
    uint8_t l = (permuted_key >> 5) & 0x1F;
    uint8_t r = permuted_key & 0x1F;
    
    l = ((l << 1) | (l >> 4)) & 0x1F;
    r = ((r << 1) | (r >> 4)) & 0x1F;
    
    *k1 = permute((l << 5) | r, P8, 8);
    
    l = ((l << 2) | (l >> 3)) & 0x1F;
    r = ((r << 2) | (r >> 3)) & 0x1F;
    
    *k2 = permute((l << 5) | r, P8, 8);
}

uint8_t sdes(uint8_t in, uint8_t k1, uint8_t k2, int encrypt) {
    static const int IP[] = {2, 6, 3, 1, 4, 8, 5, 7};
    static const int IP_INV[] = {4, 1, 3, 5, 7, 2, 8, 6};
    
    uint8_t permuted_input = permute(in, IP, 8);
    
    uint8_t l = (permuted_input >> 4) & 0xF;
    uint8_t r = permuted_input & 0xF;
    
    if (encrypt) {
        uint8_t temp = l ^ f(r, k1);
        l = r;
        r = temp ^ f(l, k2);
    } else {
        uint8_t temp = l ^ f(r, k2);
        l = r;
        r = temp ^ f(l, k1);
    }
    
    uint8_t pre_output = (r << 4) | l;
    return permute(pre_output, IP_INV, 8);
}

void print_binary(uint8_t value, int bits) {
    for (int i = bits - 1; i >= 0; i--) {
        printf("%d", (value >> i) & 1);
    }
    printf("\n");
}

void ctr_mode_encrypt_decrypt(uint8_t *data, int len, uint16_t key, uint8_t counter) {
    uint8_t k1, k2;
    key_schedule(key, &k1, &k2);
    
    for (int i = 0; i < len; i++) {
        uint8_t encrypted_counter = sdes(counter, k1, k2, 1);
        data[i] ^= encrypted_counter;
        counter++;
    }
}

int main() {
    uint8_t plaintext[] = {0x01, 0x02, 0x04};
    uint16_t key = 0x1FD; // Binary key: 0111111101
    uint8_t counter = 0x00;
    
    printf("Plaintext: ");
    for (int i = 0; i < 3; i++) {
        print_binary(plaintext[i], 8);
    }
    
    ctr_mode_encrypt_decrypt(plaintext, 3, key, counter);
    
    printf("Ciphertext: ");
    for (int i = 0; i < 3; i++) {
        print_binary(plaintext[i], 8);
    }
    
    // Reset counter for decryption
    counter = 0x00;
    ctr_mode_encrypt_decrypt(plaintext, 3, key, counter);
    
    printf("Decrypted Plaintext: ");
    for (int i = 0; i < 3; i++) {
        print_binary(plaintext[i], 8);
    }
    
    return 0;
}
