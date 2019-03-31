// addition_x64.cpp : Defines the entry point for the console application.
// Right Click the "addition_x64 (NOT SOLUTION) -> Build Dependencies -> Build Customisation -> Enable MASM 

#include <stdio.h>
#include <Windows.h>

extern "C" ULONGLONG Addition(ULONGLONG first, ULONGLONG second, ULONGLONG third, ULONGLONG fourth, ULONGLONG fifth, ULONGLONG sixth);

int main() {

	ULONGLONG first = 0x0000000000000002;
	ULONGLONG second = 0x0000000000000004;
	ULONGLONG third = 0x0000000000000006;
	ULONGLONG fourth = 0x0000000000000008;
	ULONGLONG fifth = 0x000000000000000a;
	ULONGLONG sixth = 0x000000000000000c;

	ULONGLONG result = 0;
	result = Addition(first, second, third, fourth, fifth, sixth);
	printf("Addition result: %I64x\n", result);

	return 0; 
}

