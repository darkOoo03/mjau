#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* homophone(char* message, int* key);

int main() {
    int key[] = {3302, 5, 4, 10, 5812, 21, 99, 83, 7101, 6, 47, 91, 12, 22, 1416, 31, 56, 42, 8, 77, 6652, 51, 39, 46, 24, 29};

    char message[] = "HELLO";
    printf("Original Message: %s\n", message);

    homophone(message, key);

    printf("Encrypted Message: ");
    for (int i = 0; i < strlen(message); i++) {
        printf("%d ", message[i]);
    }

    return 0;
}

char* homophone(char* message, int* key) {


	for (int i = 0; i < strlen(message); i++) {
		if (message[i] == 'A' || message[i] == 'E' || message[i] == 'I' || message[i] == 'O' || message[i] == 'U') {
			int randomInteger = rand();
			// Scale the random integer to a floating-point number in the range [0, 1)
			double randomFloat = (double)randomInteger / RAND_MAX;
			if (randomFloat >= 0.5) {
				message[i] = key[message[i] - 'A'] % 100; //higher portion
			}
			else {
				message[i] = key[message[i] - 'A'] / 100; //lower portion
			}
		}
		else {
			message[i] = key[message[i] - 'A']; //getting a number between 0 and 25 and mapping key value to it
		}
	}
	return message;
}
