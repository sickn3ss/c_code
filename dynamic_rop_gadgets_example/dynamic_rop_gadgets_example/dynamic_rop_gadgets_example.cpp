// dynamic_rop_gadgets_example.cpp : This file contains the 'main' function. Program execution begins and ends there.
/*
Check:

http://stackoverflow.com/questions/2913633/get-pe-and-va-of-executable-file-with-c/2914083#2914083
https://msdn.microsoft.com/en-us/library/ms809762.aspx
https://github.com/tfairane/ReverseEngineering/blob/master/Ring3/Windows/PE/PE.h

*/

#include "pch.h"


#include <stdio.h>
#include <Windows.h>
#include <winnt.h>

#define Magic_DOS 0x00005A4D
#define Magic_NT  0x00004550	

int main() {

	HMODULE lpFileName = LoadLibraryA("C:\\Windows\\System32\\ntoskrnl.exe");
	if (lpFileName == NULL) {
		printf("[!] Error while loading ntoskrnl: %d\n", GetLastError());
		return 1;
	}

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)lpFileName;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("[!] Invalid file.\n");
		return 1;
	}

	//Offset of NT Header is found at 0x3c location in DOS header specified by e_lfanew
	//Get the Base of NT Header(PE Header)  = dosHeader + RVA address of PE header
	PIMAGE_NT_HEADERS ntHeader;
	ntHeader = (PIMAGE_NT_HEADERS)((ULONGLONG)(dosHeader)+(dosHeader->e_lfanew));
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		printf("[!] Invalid PE Signature.\n");
		return 1;
	}

	//Info about Optional Header
	IMAGE_OPTIONAL_HEADER opHeader;
	opHeader = ntHeader->OptionalHeader;
	printf("SizeOfCode: %x\n", opHeader.SizeOfCode);
	printf("AddressOfEntryPoint: %x\n", opHeader.AddressOfEntryPoint);

	unsigned char *ntoskrnl_buffer;
	ntoskrnl_buffer = (unsigned char *)malloc(opHeader.SizeOfCode);
	SIZE_T size_read;

	//ULONGLONG ntoskrnl_code_base = (ULONGLONG)lpFileName + opHeader.BaseOfCode;
	BOOL rpm = ReadProcessMemory(GetCurrentProcess(), lpFileName, ntoskrnl_buffer, opHeader.SizeOfCode, &size_read);
	if (rpm == 0) {
		printf("[!] Error while calling ReadProcessMemory: %d\n", GetLastError());
		return 1;
	}

	unsigned int j;
	unsigned int z;
	unsigned char search_opcode[] = { 0xc3, 0x5b, 0x20, 0xc4, 0x83, 0x48, 0x10, 0x43, 0x89, 0x48 };
	//unsigned char search_opcode[] = {0x00, 0xc2, 0xc2, 0xe9, 0x00, 0x00, 0x00, 0xbc};

	for (j = 0; j < opHeader.SizeOfCode; j++) {
		unsigned char gadget[sizeof(search_opcode)];
		memset(gadget, 0x00, sizeof(gadget));
		for (z = 0; z < sizeof(gadget); z++) {
			gadget[z] = ntoskrnl_buffer[j - z];
		}

		int comparison;
		comparison = memcmp(search_opcode, gadget, sizeof(gadget));
		if (comparison == 0) {
			printf("Found at %I64x\n", j - (sizeof(gadget) - 1));
		}
	}

	printf("%p\n", lpFileName);
	getchar();
	return 0;
}