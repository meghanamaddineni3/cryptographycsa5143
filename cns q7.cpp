#include <stdio.h>
#include <string.h>

void decrypt(char *ciphertext) {
    char plaintext[1000];
    int i;

    // Frequency analysis to find characters that might represent common letters
    char most_common[4] = {'e', 't', 'a', 'o'};

    for (i = 0; i < strlen(ciphertext); i++) {
        if (ciphertext[i] == '3') plaintext[i] = 'e'; // Guessing based on frequency analysis
        else if (ciphertext[i] == '4') plaintext[i] = 't'; // Guessing based on common word "the"
        else if (ciphertext[i] == '8') plaintext[i] = 'a'; // Guessing based on common letters
        else if (ciphertext[i] == '5') plaintext[i] = 'o'; // Guessing based on common letters
        else if (ciphertext[i] == '6') plaintext[i] = 'h'; // Guessing based on common word "the"
        else if (ciphertext[i] == '9') plaintext[i] = 's'; // Guessing based on common letters
        else if (ciphertext[i] == '1') plaintext[i] = 'n'; // Guessing based on common letters
        else if (ciphertext[i] == '0') plaintext[i] = 'r'; // Guessing based on common letters
        else if (ciphertext[i] == '.') plaintext[i] = 'i'; // Guessing based on common letters
        else if (ciphertext[i] == '(') plaintext[i] = 'd'; // Guessing based on common letters
        else if (ciphertext[i] == ';') plaintext[i] = 'l'; // Guessing based on common letters
        else if (ciphertext[i] == ':') plaintext[i] = 'c'; // Guessing based on common letters
        else if (ciphertext[i] == '?') plaintext[i] = 'f'; // Guessing based on common letters
        else if (ciphertext[i] == ']') plaintext[i] = 'm'; // Guessing based on common letters
        else if (ciphertext[i] == '*') plaintext[i] = 'w'; // Guessing based on common letters
        else if (ciphertext[i] == '-') plaintext[i] = 'g'; // Guessing based on common letters
        else if (ciphertext[i] == '2') plaintext[i] = 'u'; // Guessing based on common letters
        else if (ciphertext[i] == '7') plaintext[i] = 'y'; // Guessing based on common letters
        else if (ciphertext[i] == '¶') plaintext[i] = 'v'; // Guessing based on common letters
        else plaintext[i] = ciphertext[i];
    }
    plaintext[i] = '\0';

    printf("Decrypted message: %s\n", plaintext);
}

int main() {
    char ciphertext[] = "53‡‡†305))6*;4826)4‡.)4‡);806*;48†8¶60))85;;]8*;:‡*8†83(88)5*†;46(;88*96*?;8)*‡(;485);5*†2:*‡(;4956*2(5*—4)8¶8*;4069285);)6†8)4‡‡;1(‡9;48081;8:8‡1;48†85;4)485†528806*81 (‡9;48;(88;4(‡?34;48)4‡;161;:188;‡?;";
    decrypt(ciphertext);
    return 0;
}

