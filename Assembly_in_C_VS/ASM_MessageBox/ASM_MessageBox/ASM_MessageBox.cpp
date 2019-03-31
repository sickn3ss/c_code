// ASM_MessageBox.cpp : Defines the entry point for the console application.
// Right Click the "ASM_MessageBox (NOT SOLUTION) -> Build Dependencies -> Build Customisation -> Enable MASM 

#include <stdio.h>
#include <Windows.h>

extern "C" int CallMSG();

int main()
{
	CallMSG();
	return 0;
}
