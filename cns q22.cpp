#include <stdio.h>
#include <stdint.h>

typedef uint8_t byte;

// S-DES functions (subkey generation, F function, and encryption/decryption)
byte permute(byte in, const int* table, int n) {
    byte out = 0;
    for (int i = 0; i < n; ++i) {
        out |= ((in >> (8 - table[i])) & 1) << (n - i - 1);
    }
    return out;
}

byte sbox(byte in, const int sbox[4][4]) {
    int row = ((in & 0b1000) >> 2) | (in & 0b0001);
    int col = (in & 0b0110) >> 1;
    return sbox[row][col];
}

byte f(byte r, byte sk) {
    static const int e_p[8] = {4, 1, 2, 3, 2, 3, 4, 1};
    static const int s0[4][4] = {
        {1, 0, 3, 2},
        {3, 2, 1, 0},
        {0, 2, 1, 3},
        {3, 1, 3, 2}};
    static const int s1[4][4] = {
        {0, 1, 2, 3},
        {2, 0, 1, 3},
        {3, 0, 1, 0},
        {2, 1, 0, 3}};
    static const int p4[4] = {2, 4, 3, 1};

    byte ep = permute(r, e_p, 8);
    byte a = (ep ^ sk) >> 4;
    byte b = ep ^ sk;
    byte s0_out = sbox(a, s0);
    byte s1_out = sbox(b, s1);
    byte p4_out = permute((s0_out << 2) | s1_out, p4, 4);
    return p4_out;
}

void key_schedule(byte key, byte* sk1, byte* sk2) {
    static const int p10[10] = {3, 5, 2, 7, 4, 10, 1, 9, 8, 6};
    static const int p8[8] = {6, 3, 7, 4, 8, 5, 10, 9};

    byte k = permute(key, p10, 10);
    byte k1 = (k >> 5) << 1 | (k & 0b10000) >> 4;
    byte k2 = (k & 0b11110) << 1 | (k & 0b1);
    *sk1 = permute(k1, p8, 8);
    *sk2 = permute(k2, p8, 8);
}

byte sdes(byte in, byte key, int mode) {
    static const int ip[8] = {2, 6, 3, 1, 4, 8, 5, 7};
    static const int ip_inv[8] = {4, 1, 3, 5, 7, 2, 8, 6};

    byte sk1, sk2;
    key_schedule(key, &sk1, &sk2);

    byte p = permute(in, ip, 8);
    byte l = p >> 4;
    byte r = p;

    byte f_out = f(r, mode ? sk2 : sk1);
    byte new_l = l ^ f_out;

    l = r;
    r = new_l;

    f_out = f(r, mode ? sk1 : sk2);
    new_l = l ^ f_out;

    byte out = permute((r << 4) | new_l, ip_inv, 8);
    return out;
}

byte encrypt(byte plaintext, byte key) {
    return sdes(plaintext, key, 0);
}

byte decrypt(byte ciphertext, byte key) {
    return sdes(ciphertext, key, 1);
}

// CBC Mode functions
void cbc_encrypt(byte* plaintext, byte* ciphertext, int length, byte key, byte iv) {
    byte block = iv;
    for (int i = 0; i < length; ++i) {
        block ^= plaintext[i];
        block = encrypt(block, key);
        ciphertext[i] = block;
    }
}

void cbc_decrypt(byte* ciphertext, byte* plaintext, int length, byte key, byte iv) {
    byte block = iv;
    for (int i = 0; i < length; ++i) {
        byte decrypted_block = decrypt(ciphertext[i], key);
        plaintext[i] = decrypted_block ^ block;
        block = ciphertext[i];
    }
}

// Helper function to print bytes in binary
void print_binary(byte b) {
    for (int i = 7; i >= 0; --i) {
        printf("%d", (b >> i) & 1);
    }
    printf(" ");
}

int main() {
    byte plaintext[2] = {0b00000001, 0b00100011};
    byte key = 0b0111111101;
    byte iv = 0b10101010;
    byte ciphertext[2];
    byte decrypted[2];

    cbc_encrypt(plaintext, ciphertext, 2, key, iv);
    printf("Ciphertext: ");
    for (int i = 0; i < 2; ++i) {
        print_binary(ciphertext[i]);
    }
    printf("\n");

    cbc_decrypt(ciphertext, decrypted, 2, key, iv);
    printf("Decrypted: ");
    for (int i = 0; i < 2; ++i) {
        print_binary(decrypted[i]);
    }
    printf("\n");

    return 0;
}

