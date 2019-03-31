// CALLBACK example
#include <stdio.h>

void meaningOfLife(void) {
	printf("The meanining of life is: 42\n");
}

void printNumber(int number, void (*callback_function)(void)) {
	printf("The number you have entered is: %d\n", number);
	callback_function();
}

void populate_array(int *array, size_t arraySize, int(*getNextValue)(void))
{
	for (size_t i = 0; i<arraySize; i++)
		array[i] = getNextValue();
}

int getNextRandomValue(void)
{
	return rand();
}

int main(void)
{
	printf("[+] CALLBACK example 0x01.\n\n");
	int nr = 6;
	printNumber(nr, meaningOfLife);

	printf("\n\n[+] CALLBACK example 0x02.\n\n");
	int myarray[10];
	populate_array(myarray, 10, getNextRandomValue);
	for (int i = 0; i<10; ++i) {
		printf("%d ", myarray[i]);
	}

	return 0;
}