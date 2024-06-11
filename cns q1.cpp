#include <stdio.h>
#include <ctype.h>
void caesarCipher(char *text, int shift) {
    char ch;
    for (int i = 0; text[i] != '\0'; ++i) {
        ch = text[i];
        if (isupper(ch)) {
            ch = ((ch - 'A' + shift) % 26) + 'A';
        } 
        else if (islower(ch)) {
            ch = ((ch - 'a' + shift) % 26) + 'a';
        }
        text[i] = ch;
    }
}

int main() {
    char text[100];
    int shift;
    printf("Enter a string: ");
    fgets(text, sizeof(text), stdin);
    printf("Enter shift value (1-25): ");
    scanf("%d", &shift);
    if (shift < 1 || shift > 25) {
        printf("Invalid shift value. Please enter a value between 1 and 25.\n");
        return 1;
    }
    caesarCipher(text, shift);
    printf("Encrypted text: %s\n", text);
    return 0;
}
