// addidion_x86.cpp : Defines the entry point for the console application.
//

#include <stdio.h>
#include <Windows.h>

extern "C" int Addition(int first, int second);

int main()
{
	int first = 20;
	int second = 25;

	int result = 0;
	result = Addition(first, second);
	printf("Addition result = %d", result);
	return 0;
}