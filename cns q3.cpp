#include <stdio.h>
#include <ctype.h>
#include <string.h>
void monoalphabeticCipher(char *text, const char *cipherAlphabet) {
    char plaintextAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    for (int i = 0; text[i] != '\0'; ++i) {
        char ch = text[i];
        if (isalpha(ch)) {
            int isLower = islower(ch);
            ch = toupper(ch);
            for (int j = 0; j < 26; ++j) {
                if (ch == plaintextAlphabet[j]) {
                    ch = cipherAlphabet[j];
                    if (isLower) {
                        ch = tolower(ch);
                    }
                    break;
                }
            }
        }
        text[i] = ch;
    }
}
